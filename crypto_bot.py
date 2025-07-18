import discord
from discord.ext import commands, tasks
import asyncio
import random
from datetime import datetime
import traceback
import json
import os
import uuid
from decimal import Decimal, getcontext
import requests
import time
import hashlib
import binascii
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der

# ===== CONFIGURATION =====
BET_CHANNEL_ID = 1394715225948688537
TICKET_CATEGORY_NAME = "Crypto Battle Tickets"
BOT_PREFIX = "!"
BOT_TOKEN = "MTM5NTQ2OTg4NjA5MTY5MDAxNA.GCJaGW.3QdfzaztRPDyDLJTTG0tFzpXShzFBOOUYumJTk"
MIN_BET_AMOUNT = 1.00  # Global minimum bet

# BlockCypher API Configuration
BLOCKCYPHER_API_KEY = "c703adf08f1a4766bbaa3284da97a7aa"
BLOCKCYPHER_API_URL = "https://api.blockcypher.com/v1/"

# Tip receiver addresses
TIP_ADDRESSES = {
    "LTC": "LZYMRRtCyck3WT2DqiuysY8XJxGAt83BJb",
    "BTC": "YOUR_BTC_TIP_ADDRESS_HERE"  # Replace with your BTC address
}

# Fiat conversion rates (update periodically)
FIAT_RATES = {
    "BTC": 60000.00,  # $60,000 per BTC
    "LTC": 80.00      # $80 per LTC
}

# Cryptocurrency configuration
CRYPTOCURRENCIES = {
    "BTC": {
        "name": "Bitcoin",
        "min_bet": 25.00,
        "withdrawal_fee": 0.0005,
        "network": "btc/main",
        "emoji": "💰",
        "unit": "BTC",
        "divisor": 10**8
    },
    "LTC": {
        "name": "Litecoin",
        "min_bet": 0.05,
        "withdrawal_fee": 0.001,
        "network": "ltc/main",
        "emoji": "🔷",
        "unit": "LTC",
        "divisor": 10**8
    }
}

# Wallet storage
WALLET_FILE = "user_wallets.json"
# ===== END CONFIGURATION =====

# ===== CRYPTOGRAPHIC FUNCTIONS =====
def private_key_to_public_key(private_key_hex):
    """Convert a private key to compressed public key"""
    try:
        # Remove '0x' prefix if present
        if private_key_hex.startswith('0x'):
            private_key_hex = private_key_hex[2:]
        
        # Convert hex to bytes
        private_key_bytes = binascii.unhexlify(private_key_hex)
        
        # Create signing key
        signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        
        # Get public key point
        public_key_point = signing_key.get_verifying_key().pubkey.point
        
        # Convert to compressed format
        x = public_key_point.x()
        y = public_key_point.y()
        
        # Determine if y is even or odd for compression
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        
        # Convert x coordinate to 32-byte big-endian
        x_bytes = x.to_bytes(32, 'big')
        
        # Combine prefix and x coordinate
        compressed_pubkey = prefix + x_bytes
        
        return binascii.hexlify(compressed_pubkey).decode('utf-8')
    except Exception as e:
        print(f"Error converting private key to public key: {str(e)}")
        return None

def sign_transaction_data(private_key_hex, tosign_hex):
    """Sign transaction data using ECDSA"""
    try:
        # Store original private key for public key generation
        original_private_key = private_key_hex
        
        # Remove '0x' prefix if present
        if private_key_hex.startswith('0x'):
            private_key_hex = private_key_hex[2:]
        if tosign_hex.startswith('0x'):
            tosign_hex = tosign_hex[2:]
        
        # Convert hex to bytes
        private_key_bytes = binascii.unhexlify(private_key_hex)
        tosign_bytes = binascii.unhexlify(tosign_hex)
        
        # Create signing key
        signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        
        # Sign the data using DER encoding
        signature = signing_key.sign(tosign_bytes, sigencode=sigencode_der)
        
        # Convert signature to hex
        signature_hex = binascii.hexlify(signature).decode('utf-8')
        
        # Get corresponding public key using original private key
        public_key_hex = private_key_to_public_key(original_private_key)
        
        return signature_hex, public_key_hex
    except Exception as e:
        print(f"Error signing transaction data: {str(e)}")
        return None, None
# ===== END CRYPTOGRAPHIC FUNCTIONS =====

# Configure decimal precision
getcontext().prec = 8

# Proper intents setup
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True
intents.members = True

bot = commands.Bot(
    command_prefix=BOT_PREFIX,
    intents=intents,
    help_command=None
)

# State tracking dictionaries
active_bets = {}
pending_confirmations = {}
dice_games = {}
opponent_requests = {}
deposit_addresses = {}
user_wallets = {}
deposit_notifications = {}

def load_wallets():
    global user_wallets
    if os.path.exists(WALLET_FILE):
        try:
            with open(WALLET_FILE, 'r') as f:
                raw_data = json.load(f)
            
            # Migrate DOGE to LTC in the raw data
            needs_migration = False
            for user_id, wallet in raw_data.items():
                # Check if DOGE exists in balances
                if 'DOGE' in wallet.get('balances', {}):
                    needs_migration = True
                    # Convert DOGE balance to LTC
                    if 'LTC' not in wallet['balances']:
                        wallet['balances']['LTC'] = wallet['balances']['DOGE']
                    else:
                        # Add DOGE balance to existing LTC balance
                        current_ltc = Decimal(wallet['balances']['LTC'])
                        doge_balance = Decimal(wallet['balances']['DOGE'])
                        wallet['balances']['LTC'] = str(current_ltc + doge_balance)
                    del wallet['balances']['DOGE']
                
                # Migrate transactions
                for tx in wallet.get('transactions', []):
                    if tx['crypto'] == 'DOGE':
                        tx['crypto'] = 'LTC'
            
            # Save migrated data if changes were made
            if needs_migration:
                with open(WALLET_FILE, 'w') as f:
                    json.dump(raw_data, f, indent=2)
                print("Migrated DOGE to LTC in wallet data")
            
            # Now load into user_wallets with Decimal conversion
            user_wallets = {}
            for user_id, wallet in raw_data.items():
                user_wallets[user_id] = {
                    'balances': {crypto: Decimal(str(balance)) for crypto, balance in wallet['balances'].items()},
                    'transactions': wallet.get('transactions', [])
                }
            print(f"Loaded {len(user_wallets)} wallets")
        except Exception as e:
            print(f"Error loading wallets: {str(e)}")
            user_wallets = {}
    else:
        user_wallets = {}
        print("No wallet file found, starting fresh.")

def save_wallets():
    try:
        # Convert Decimal to string for JSON serialization
        save_data = {}
        for user_id, wallet in user_wallets.items():
            save_data[user_id] = {
                'balances': {crypto: str(balance) for crypto, balance in wallet['balances'].items()},
                'transactions': wallet.get('transactions', [])
            }
        
        with open(WALLET_FILE, 'w') as f:
            json.dump(save_data, f, indent=2)
        print("Wallets saved successfully")
    except Exception as e:
        print(f"Error saving wallets: {str(e)}")

def get_user_wallet(user_id):
    user_id = str(user_id)
    if user_id not in user_wallets:
        user_wallets[user_id] = {
            'balances': {crypto: Decimal('0') for crypto in CRYPTOCURRENCIES},
            'transactions': []
        }
    return user_wallets[user_id]

def add_transaction(user_id, tx_type, crypto, amount, battle_id=None, notes=""):
    wallet = get_user_wallet(user_id)
    tx_id = str(uuid.uuid4())[:8]
    transaction = {
        'id': tx_id,
        'type': tx_type,
        'crypto': crypto,
        'amount': str(amount),
        'timestamp': datetime.now().isoformat(),
        'battle_id': battle_id,
        'notes': notes
    }
    wallet['transactions'].insert(0, transaction)
    # Keep only last 50 transactions
    wallet['transactions'] = wallet['transactions'][:50]
    save_wallets()
    return tx_id

def get_crypto_min_bet(crypto):
    return max(CRYPTOCURRENCIES[crypto]['min_bet'], MIN_BET_AMOUNT)

def generate_deposit_address(user_id, crypto):
    """Generate a unique deposit address using BlockCypher"""
    if crypto not in CRYPTOCURRENCIES:
        return None
    
    network = CRYPTOCURRENCIES[crypto]['network']
    url = f"{BLOCKCYPHER_API_URL}{network}/addrs?token={BLOCKCYPHER_API_KEY}"
    
    try:
        response = requests.post(url)
        response.raise_for_status()
        data = response.json()
        address = data['address']
        private_key = data['private']
        
        # Store private key securely
        if user_id not in deposit_addresses:
            deposit_addresses[user_id] = {}
        deposit_addresses[user_id][crypto] = {
            'address': address,
            'private': private_key
        }
        
        return address
    except Exception as e:
        print(f"Error generating deposit address: {str(e)}")
        return None

def check_deposits():
    """Check for new deposits using BlockCypher API"""
    for user_id, wallets in deposit_addresses.items():
        for crypto, wallet_info in wallets.items():
            address = wallet_info['address']
            network = CRYPTOCURRENCIES[crypto]['network']
            url = f"{BLOCKCYPHER_API_URL}{network}/addrs/{address}/balance?token={BLOCKCYPHER_API_KEY}"
            
            try:
                response = requests.get(url)
                response.raise_for_status()
                data = response.json()
                
                # Convert balance to decimal
                divisor = CRYPTOCURRENCIES[crypto]['divisor']
                confirmed_balance = Decimal(data['balance']) / Decimal(divisor)
                
                # Only process confirmed transactions
                if confirmed_balance > 0:
                    wallet = get_user_wallet(user_id)
                    
                    # Check if this deposit is already recorded
                    last_balance = wallet['balances'].get(crypto, Decimal('0'))
                    if confirmed_balance > last_balance:
                        deposit_amount = confirmed_balance - last_balance
                        
                        # Create unique key for this deposit
                        deposit_key = f"{user_id}-{crypto}-{address}-{deposit_amount}"
                        
                        # Skip if we've already notified about this deposit
                        if deposit_key in deposit_notifications:
                            continue
                            
                        # Add to balance
                        wallet['balances'][crypto] = confirmed_balance
                        
                        # Record transaction
                        tx_id = add_transaction(
                            user_id,
                            'deposit',
                            crypto,
                            deposit_amount,
                            notes=f"Deposit to {address}"
                        )
                        
                        # Mark this deposit for notification
                        deposit_notifications[deposit_key] = {
                            "user_id": user_id,
                            "crypto": crypto,
                            "amount": deposit_amount,
                            "address": address,
                            "tx_id": tx_id,
                            "notified": False
                        }
                        
                        print(f"Deposit detected: {deposit_amount} {crypto} for user {user_id}")
            except Exception as e:
                print(f"Error checking deposits for {crypto}: {str(e)}")

async def send_deposit_notifications():
    """Send notifications about new deposits to users"""
    global deposit_notifications
    
    for deposit_key, deposit_info in list(deposit_notifications.items()):
        if not deposit_info["notified"]:
            try:
                user_id = deposit_info["user_id"]
                user = await bot.fetch_user(int(user_id))
                
                if user:
                    # Calculate fiat value
                    fiat_value = deposit_info['amount'] * Decimal(FIAT_RATES[deposit_info['crypto']])
                    
                    embed = discord.Embed(
                        title="💰 Deposit Received! 💰",
                        description="Your cryptocurrency deposit has been detected and added to your balance",
                        color=discord.Color.green()
                    )
                    embed.add_field(
                        name="Details",
                        value=(
                            f"**Amount**: {deposit_info['amount']} {deposit_info['crypto']} "
                            f"(${fiat_value:.2f})\n"
                            f"**Address**: `{deposit_info['address']}`\n"
                            f"**Transaction ID**: `{deposit_info['tx_id']}`\n"
                            f"**New Balance**: {get_user_wallet(user_id)['balances'][deposit_info['crypto']]} {deposit_info['crypto']} "
                            f"(${get_user_wallet(user_id)['balances'][deposit_info['crypto']] * Decimal(FIAT_RATES[deposit_info['crypto']]):.2f})"
                        ),
                        inline=False
                    )
                    embed.set_footer(text="Thank you for using our service!")
                    
                    await user.send(embed=embed)
                    print(f"Sent deposit notification to user {user_id}")
                    
                    # Mark as notified
                    deposit_info["notified"] = True
                    deposit_notifications[deposit_key] = deposit_info
            except discord.NotFound:
                print(f"User not found: {user_id}")
            except discord.Forbidden:
                print(f"Cannot send message to user: {user_id}")
            except Exception as e:
                print(f"Error sending deposit notification: {str(e)}")

def send_withdrawal(user_id, crypto, address, amount):
    """Send cryptocurrency using BlockCypher with proper cryptographic signatures"""
    if crypto not in deposit_addresses.get(str(user_id), {}):
        return None, "No deposit address found for user"
    
    network = CRYPTOCURRENCIES[crypto]['network']
    wallet_info = deposit_addresses[str(user_id)][crypto]
    from_address = wallet_info['address']
    private_key = wallet_info['private']
    
    # Convert amount to satoshi
    multiplier = CRYPTOCURRENCIES[crypto]['divisor']
    amount_satoshi = int(amount * multiplier)
    fee = int(CRYPTOCURRENCIES[crypto]['withdrawal_fee'] * multiplier)
    
    url = f"{BLOCKCYPHER_API_URL}{network}/txs/new?token={BLOCKCYPHER_API_KEY}"
    
    try:
        payload = {
            "inputs": [{"addresses": [from_address]}],
            "outputs": [{"addresses": [address], "value": amount_satoshi}],
            "fees": fee
        }
        
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        # Check if we have data to sign
        if 'tosign' not in data or not data['tosign']:
            return None, "No transaction data to sign"
        
        # Sign transaction with proper cryptographic signatures
        data['signatures'] = []
        data['pubkeys'] = []
        
        for to_sign in data['tosign']:
            signature_hex, public_key_hex = sign_transaction_data(private_key, to_sign)
            
            if signature_hex is None or public_key_hex is None:
                return None, "Failed to sign transaction data"
            
            data['signatures'].append(signature_hex)
            data['pubkeys'].append(public_key_hex)
        
        # Verify we have the same number of signatures and public keys as tosign items
        if len(data['signatures']) != len(data['tosign']) or len(data['pubkeys']) != len(data['tosign']):
            return None, "Signature count mismatch"
        
        # Send transaction
        send_url = f"{BLOCKCYPHER_API_URL}{network}/txs/send?token={BLOCKCYPHER_API_KEY}"
        send_response = requests.post(send_url, json=data)
        send_response.raise_for_status()
        
        tx_data = send_response.json()
        
        # Check if transaction was successful
        if 'hash' not in tx_data:
            error_msg = tx_data.get('error', 'Unknown error occurred')
            return None, f"Transaction failed: {error_msg}"
        
        return tx_data['hash'], None
        
    except requests.exceptions.HTTPError as e:
        try:
            error_data = e.response.json()
            error_msg = error_data.get('error', str(e))
        except:
            error_msg = str(e)
        print(f"HTTP error sending withdrawal: {error_msg}")
        return None, f"HTTP error: {error_msg}"
    except Exception as e:
        print(f"Error sending withdrawal: {str(e)}")
        return None, str(e)

# Load wallets on startup
load_wallets()

# Background task to check deposits
@tasks.loop(minutes=10)
async def check_deposits_background():
    check_deposits()
    await send_deposit_notifications()

class TipView(discord.ui.View):
    def __init__(self, winner, winnings, crypto):
        super().__init__(timeout=120.0)
        self.winner = winner
        self.winnings = winnings
        self.crypto = crypto
        self.tip_percentage = 0

    @discord.ui.button(label="0% Tip", style=discord.ButtonStyle.secondary)
    async def tip_0(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.winner.id:
            await interaction.response.send_message("❌ Only the winner can select a tip!", ephemeral=True)
            return
        self.tip_percentage = 0
        await self.process_tip(interaction)

    @discord.ui.button(label="5% Tip", style=discord.ButtonStyle.primary)
    async def tip_5(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.winner.id:
            await interaction.response.send_message("❌ Only the winner can select a tip!", ephemeral=True)
            return
        self.tip_percentage = 5
        await self.process_tip(interaction)

    @discord.ui.button(label="10% Tip", style=discord.ButtonStyle.primary)
    async def tip_10(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.winner.id:
            await interaction.response.send_message("❌ Only the winner can select a tip!", ephemeral=True)
            return
        self.tip_percentage = 10
        await self.process_tip(interaction)

    async def process_tip(self, interaction: discord.Interaction):
        user_id = str(interaction.user.id)
        wallet = get_user_wallet(user_id)
        tip_amount = self.winnings * Decimal(self.tip_percentage) / Decimal(100)
        net_winnings = self.winnings - tip_amount
        
        # Add winnings to balance
        wallet['balances'][self.crypto] += net_winnings
        
        # Record transactions
        add_transaction(
            user_id,
            'battle_win',
            self.crypto,
            net_winnings,
            notes=f"Battle winnings with {self.tip_percentage}% tip"
        )
        
        if tip_amount > 0:
            # Record tip transaction
            add_transaction(
                user_id,
                'tip',
                self.crypto,
                -tip_amount,
                notes=f"Tip sent to bot owner"
            )
            
            # Send tip to predefined address
            if self.crypto in TIP_ADDRESSES:
                tip_address = TIP_ADDRESSES[self.crypto]
                txid, error = send_withdrawal(user_id, self.crypto, tip_address, tip_amount)
                
                if error:
                    print(f"Error sending tip: {error}")
                    await interaction.followup.send(
                        f"⚠️ Tip failed to send: {error}",
                        ephemeral=True
                    )
                else:
                    # Record the tip transfer
                    add_transaction(
                        user_id,
                        'tip_sent',
                        self.crypto,
                        -tip_amount,
                        notes=f"Tip sent to {tip_address} | TX: {txid}"
                    )
                    
                    # Send confirmation to user
                    await interaction.followup.send(
                        f"✅ Tip of {tip_amount} {self.crypto} sent successfully! TX: {txid}",
                        ephemeral=True
                    )
            else:
                await interaction.followup.send(
                    f"⚠️ Tip not sent: No address configured for {self.crypto}",
                    ephemeral=True
                )
        
        save_wallets()
        
        # Disable buttons after selection
        for child in self.children:
            child.disabled = True
        
        await interaction.response.edit_message(
            content=(
                f"🎉 **{interaction.user.mention} received {net_winnings} {self.crypto} "
                f"(${(net_winnings * Decimal(FIAT_RATES[self.crypto])):.2f}) "
                f"after tipping {tip_amount} {self.crypto} "
                f"(${(tip_amount * Decimal(FIAT_RATES[self.crypto])):.2f})!**\n"
                f"Thank you for your generosity!"
            ),
            view=self
        )

class OpponentModal(discord.ui.Modal, title='Enter Opponent ID'):
    opponent_id = discord.ui.TextInput(
        label="Opponent's Discord ID",
        placeholder="Enter the user's full Discord ID (e.g. 123456789012345678)",
        min_length=17,
        max_length=20
    )

    async def on_submit(self, interaction: discord.Interaction):
        try:
            user_id = int(self.opponent_id.value)
            opponent = await bot.fetch_user(user_id)
            opponent = interaction.guild.get_member(opponent.id)
            
            if not opponent:
                await interaction.response.send_message(
                    "❌ User not found in this server. Please enter a valid user ID.",
                    ephemeral=True
                )
                return
            
            if opponent.bot:
                await interaction.response.send_message(
                    "❌ Cannot select a bot as opponent.",
                    ephemeral=True
                )
                return
                
            if opponent.id == interaction.user.id:
                await interaction.response.send_message(
                    "❌ You cannot battle yourself.",
                    ephemeral=True
                )
                return
                
            crypto = opponent_requests.get(interaction.user.id)
            if not crypto:
                await interaction.response.send_message(
                    "❌ Session expired. Please restart the battle.",
                    ephemeral=True
                )
                return
                
            ticket = await create_ticket(interaction.guild, interaction.user, opponent, crypto)
            
            embed = discord.Embed(
                title=f"⚔️ {interaction.user.name} vs {opponent.name} ⚔️",
                description=f"**Selected Crypto**: {crypto}",
                color=discord.Color.blue()
            )
            embed.add_field(
                name="Game Mode",
                value="Select a game mode below:",
                inline=False
            )
            await ticket.send(embed=embed, view=GameModeView(ticket.id))
            
            await interaction.response.send_message(
                f"✅ Ticket created: {ticket.mention}",
                ephemeral=True
            )
            
            del opponent_requests[interaction.user.id]
            
        except ValueError:
            await interaction.response.send_message(
                "❌ Invalid ID format. Please enter a numeric Discord ID.",
                ephemeral=True
            )
        except discord.NotFound:
            await interaction.response.send_message(
                "❌ User not found. Please enter a valid Discord ID.",
                ephemeral=True
            )
        except Exception as e:
            print(f"Modal error: {str(e)}")
            await interaction.response.send_message(
                "⚠️ An error occurred. Please try again.",
                ephemeral=True
            )

class CryptoSelectView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)
    
    @discord.ui.button(label="Bitcoin", style=discord.ButtonStyle.grey, emoji="💰", custom_id="btc")
    async def btc_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.handle_selection(interaction, "BTC")
    
    @discord.ui.button(label="Litecoin", style=discord.ButtonStyle.grey, emoji="🔷", custom_id="ltc")
    async def ltc_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.handle_selection(interaction, "LTC")
    
    async def handle_selection(self, interaction, crypto):
        opponent_requests[interaction.user.id] = crypto
        await interaction.response.send_modal(OpponentModal())

class GameModeView(discord.ui.View):
    def __init__(self, channel_id):
        super().__init__(timeout=None)
        self.channel_id = channel_id
    
    @discord.ui.button(label="Dice Roll", style=discord.ButtonStyle.blurple, emoji="🎲", custom_id="dice")
    async def dice_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.handle_game_mode(interaction, "Dice")
    
    @discord.ui.button(label="Coinflip", style=discord.ButtonStyle.blurple, emoji="🪙", custom_id="coinflip")
    async def coinflip_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.handle_game_mode(interaction, "Coinflip")
    
    async def handle_game_mode(self, interaction, mode):
        bet_data = active_bets.get(self.channel_id)
        if bet_data:
            bet_data["game_mode"] = mode
            bet_data["status"] = "awaiting_confirmation"
            await interaction.response.send_message(
                f"**{mode} selected!** Both players must type `confirm` to proceed."
            )
            pending_confirmations[self.channel_id] = {
                "players": [bet_data["player1"].id, bet_data["player2"].id],
                "confirmed": []
            }

async def create_ticket(guild, player1, player2, crypto):
    category = discord.utils.get(guild.categories, name=TICKET_CATEGORY_NAME)
    if not category:
        overwrites = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            guild.me: discord.PermissionOverwrite(
                read_messages=True, 
                send_messages=True,
                manage_channels=True,
                manage_roles=True
            )
        }
        category = await guild.create_category(TICKET_CATEGORY_NAME, overwrites=overwrites)
    
    timestamp = datetime.now().strftime("%m%d%H%M")
    ticket_name = f"battle-{player1.name}-vs-{player2.name}-{timestamp}"[:95]
    
    ticket = await category.create_text_channel(
        ticket_name,
        overwrites={
            guild.default_role: discord.PermissionOverwrite(read_messages=False),
            player1: discord.PermissionOverwrite(
                read_messages=True, 
                send_messages=True,
                read_message_history=True
            ),
            player2: discord.PermissionOverwrite(
                read_messages=True, 
                send_messages=True,
                read_message_history=True
            ),
            guild.me: discord.PermissionOverwrite(
                read_messages=True,
                send_messages=True,
                manage_messages=True,
                manage_channels=True,
                embed_links=True
            )
        }
    )
    
    active_bets[ticket.id] = {
        "player1": player1,
        "player2": player2,
        "crypto": crypto,
        "status": "awaiting_game_mode",
        "channel": ticket,
        "amount_setter": player1,
        "battle_id": f"BATTLE-{timestamp}-{random.randint(1000,9999)}"
    }
    
    return ticket

@bot.event
async def on_ready():
    print(f'✅ Bot Online: {bot.user.name} (ID: {bot.user.id})')
    print(f'🌐 Connected to {len(bot.guilds)} server(s)')
    await bot.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching,
        name="Crypto Battles"
    ))
    check_deposits_background.start()
    
    # Register persistent views
    bot.add_view(CryptoSelectView())
    
    # Create ticket category if missing
    for guild in bot.guilds:
        category = discord.utils.get(guild.categories, name=TICKET_CATEGORY_NAME)
        if not category:
            try:
                overwrites = {
                    guild.default_role: discord.PermissionOverwrite(read_messages=False),
                    guild.me: discord.PermissionOverwrite(
                        read_messages=True,
                        send_messages=True,
                        manage_channels=True
                    )
                }
                await guild.create_category(TICKET_CATEGORY_NAME, overwrites=overwrites)
                print(f"Created ticket category in {guild.name}")
            except Exception as e:
                print(f"Error creating category in {guild.name}: {str(e)}")
        else:
            print(f"Ticket category exists in {guild.name}")

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return
    
    await bot.process_commands(message)
    
    # Handle confirmations
    if message.channel.id in pending_confirmations:
        tracker = pending_confirmations[message.channel.id]
        if message.author.id in tracker["players"] and message.content.lower() == "confirm":
            if message.author.id not in tracker["confirmed"]:
                tracker["confirmed"].append(message.author.id)
                await message.add_reaction("✅")
                
                if len(tracker["confirmed"]) == len(tracker["players"]):
                    bet_data = active_bets.get(message.channel.id)
                    if bet_data:
                        if bet_data["status"] == "awaiting_confirmation":
                            bet_data["status"] = "awaiting_amount"
                            await message.channel.send(
                                f"✅ **Both players confirmed!** {bet_data['amount_setter'].mention}, "
                                f"please enter the bet amount (in USD):"
                            )
                        elif bet_data["status"] == "awaiting_amount_confirmation":
                            bet_data["status"] = "balance_check"
                            amount = bet_data["amount"]
                            crypto = bet_data["crypto"]
                            
                            # Check balances
                            player1_wallet = get_user_wallet(str(bet_data["player1"].id))
                            player2_wallet = get_user_wallet(str(bet_data["player2"].id))
                            
                            # Convert USD amount to crypto equivalent (simplified)
                            crypto_amount = Decimal(amount) / Decimal(100)  # Placeholder conversion
                            
                            min_bet = get_crypto_min_bet(crypto)
                            if amount < min_bet:
                                await message.channel.send(
                                    f"❌ Minimum bet for {crypto} is ${min_bet}. Battle canceled."
                                )
                                del active_bets[message.channel.id]
                                return
                            
                            if player1_wallet['balances'][crypto] < crypto_amount:
                                await message.channel.send(
                                    f"❌ {bet_data['player1'].mention} doesn't have enough {crypto}. "
                                    f"Needed: {crypto_amount}, Available: {player1_wallet['balances'][crypto]}"
                                )
                                return
                                
                            if player2_wallet['balances'][crypto] < crypto_amount:
                                await message.channel.send(
                                    f"❌ {bet_data['player2'].mention} doesn't have enough {crypto}. "
                                    f"Needed: {crypto_amount}, Available: {player2_wallet['balances'][crypto]}"
                                )
                                return
                            
                            # Deduct funds and hold in escrow
                            player1_wallet['balances'][crypto] -= crypto_amount
                            player2_wallet['balances'][crypto] -= crypto_amount
                            save_wallets()
                            
                            # Record transactions
                            add_transaction(
                                str(bet_data["player1"].id),
                                'bet_hold',
                                crypto,
                                -crypto_amount,
                                bet_data["battle_id"],
                                f"Battle escrow: {amount} USD equivalent"
                            )
                            add_transaction(
                                str(bet_data["player2"].id),
                                'bet_hold',
                                crypto,
                                -crypto_amount,
                                bet_data["battle_id"],
                                f"Battle escrow: {amount} USD equivalent"
                            )
                            
                            bet_data["crypto_amount"] = crypto_amount
                            bet_data["status"] = "in_progress"
                            
                            await message.channel.send(
                                f"✅ Funds verified! Starting **{bet_data['game_mode']}** battle..."
                            )
                            
                            if bet_data["game_mode"] == "Coinflip":
                                await resolve_coinflip(bet_data)
                            else:
                                await start_dice_game(bet_data)
                            
                    del pending_confirmations[message.channel.id]
    
    # Handle bet amount input
    if message.channel.id in active_bets and active_bets[message.channel.id]["status"] == "awaiting_amount":
        bet_data = active_bets[message.channel.id]
        if message.author.id != bet_data["amount_setter"].id:
            return
            
        try:
            amount = float(message.content)
            crypto = bet_data["crypto"]
            min_bet = get_crypto_min_bet(crypto)
            
            if amount < min_bet:
                await message.channel.send(
                    f"❌ Minimum bet for {crypto} is ${min_bet}. Please enter a higher amount.",
                    delete_after=15
                )
                return
            
            # Store amount and request confirmation
            bet_data["amount"] = amount
            bet_data["status"] = "awaiting_amount_confirmation"
            
            players = [
                bet_data["player1"].id,
                bet_data["player2"].id
            ]
            pending_confirmations[message.channel.id] = {
                "players": players,
                "confirmed": []
            }
            
            await message.channel.send(
                f"**${amount}** bet set! Both players must type `confirm` to proceed."
            )
        except ValueError:
            await message.channel.send("❌ Invalid amount. Please enter a number (e.g. 25).", delete_after=15)
    
    # Handle dice game commands
    if message.channel.id in dice_games:
        game = dice_games[message.channel.id]
        if message.content.lower() == "!roll" and message.author.id == game["current_player"]:
            await process_dice_roll(message.channel, game)

async def start_dice_game(bet_data):
    channel = bet_data["channel"]
    player1 = bet_data["player1"]
    player2 = bet_data["player2"]
    
    dice_games[channel.id] = {
        "player1": player1,
        "player2": player2,
        "player1_score": 0,
        "player2_score": 0,
        "round": 1,
        "current_player": player1.id,
        "status": "in_progress",
        "bet_data": bet_data
    }
    
    embed = discord.Embed(
        title="🎲 DICE BATTLE - FIRST TO 3 WINS 🎲",
        description=f"{player1.mention} vs {player2.mention}",
        color=discord.Color.gold()
    )
    embed.add_field(
        name="How to Play",
        value=f"• Players take turns rolling dice\n• Highest roll wins the round\n• First to win 3 rounds wins the battle\n\nIt's {player1.mention}'s turn! Type `!roll`",
        inline=False
    )
    await channel.send(embed=embed)

async def process_dice_roll(channel, game):
    player = bot.get_user(game["current_player"])
    roll = random.randint(1, 100)
    
    embed = discord.Embed(
        title=f"🎲 {player.name} rolled: {roll}",
        color=discord.Color.blue()
    )
    await channel.send(embed=embed)
    
    if "current_rolls" not in game:
        game["current_rolls"] = {game["player1"].id: None, game["player2"].id: None}
    
    game["current_rolls"][player.id] = roll
    
    if all(roll is not None for roll in game["current_rolls"].values()):
        player1_roll = game["current_rolls"][game["player1"].id]
        player2_roll = game["current_rolls"][game["player2"].id]
        
        if player1_roll > player2_roll:
            game["player1_score"] += 1
            winner = game["player1"]
            result = f"{winner.mention} wins the round! ({player1_roll} vs {player2_roll})"
        elif player2_roll > player1_roll:
            game["player2_score"] += 1
            winner = game["player2"]
            result = f"{winner.mention} wins the round! ({player2_roll} vs {player1_roll})"
        else:
            result = f"It's a tie! ({player1_roll} vs {player2_roll})"
        
        embed = discord.Embed(
            title=f"🏁 ROUND {game['round']} COMPLETE 🏁",
            description=result,
            color=discord.Color.green()
        )
        embed.add_field(
            name="Score",
            value=f"{game['player1'].mention}: {game['player1_score']}\n{game['player2'].mention}: {game['player2_score']}",
            inline=False
        )
        await channel.send(embed=embed)
        
        if game["player1_score"] >= 3 or game["player2_score"] >= 3:
            if game["player1_score"] > game["player2_score"]:
                winner = game["player1"]
            else:
                winner = game["player2"]
            
            await finish_dice_game(channel, game, winner)
            return
        
        game["round"] += 1
        game["current_rolls"] = {game["player1"].id: None, game["player2"].id: None}
        game["current_player"] = game["player1"].id
        
        embed = discord.Embed(
            title=f"⏭ ROUND {game['round']} STARTING ⏭",
            description=f"{game['player1'].mention}'s turn! Type `!roll`",
            color=discord.Color.blurple()
        )
        await channel.send(embed=embed)
    else:
        if game["current_player"] == game["player1"].id:
            game["current_player"] = game["player2"].id
            next_player = game["player2"]
        else:
            game["current_player"] = game["player1"].id
            next_player = game["player1"]
        
        await channel.send(f"{next_player.mention}'s turn! Type `!roll`")

async def finish_dice_game(channel, game, winner):
    bet_data = game["bet_data"]
    amount = bet_data["amount"]
    crypto = bet_data["crypto"]
    crypto_amount = bet_data["crypto_amount"]
    
    # Total winnings (2x the bet amount)
    total_winnings = crypto_amount * Decimal(2)
    
    # Calculate fiat values for display
    winnings_fiat = total_winnings * Decimal(FIAT_RATES[crypto])
    
    # Ask for tip
    embed = discord.Embed(
        title="🎉 BATTLE WON! 🎉",
        description=f"**{winner.mention} wins ${amount*2} worth of {crypto}!**",
        color=discord.Color.gold()
    )
    embed.add_field(
        name="Tip the Bot",
        value="Please select a tip percentage for your winnings:",
        inline=False
    )
    await channel.send(
        content=f"{winner.mention} please select your tip:",
        embed=embed,
        view=TipView(winner, total_winnings, crypto)
    )
    
    del dice_games[channel.id]
    del active_bets[channel.id]

async def resolve_coinflip(bet_data):
    channel = bet_data["channel"]
    player1 = bet_data["player1"]
    player2 = bet_data["player2"]
    amount = bet_data["amount"]
    crypto = bet_data["crypto"]
    crypto_amount = bet_data["crypto_amount"]
    
    winner = random.choice([player1, player2])
    
    # Total winnings (2x the bet amount)
    total_winnings = crypto_amount * Decimal(2)
    
    # Calculate fiat values for display
    winnings_fiat = total_winnings * Decimal(FIAT_RATES[crypto])
    
    # Ask for tip
    embed = discord.Embed(
        title="🎉 BATTLE WON! 🎉",
        description=f"**{winner.mention} wins ${amount*2} worth of {crypto}!**",
        color=discord.Color.gold()
    )
    embed.add_field(
        name="Tip the Bot",
        value="Please select a tip percentage for your winnings:",
        inline=False
    )
    await channel.send(
        content=f"{winner.mention} please select your tip:",
        embed=embed,
        view=TipView(winner, total_winnings, crypto)
    )
    
    del active_bets[channel.id]

@bot.command()
@commands.has_permissions(administrator=True)
async def setup(ctx):
    if ctx.channel.id != BET_CHANNEL_ID:
        await ctx.send("❌ This command must be run in the betting channel!", delete_after=10)
        return
    
    embed = discord.Embed(
        title="🚀 CRYPTO BATTLE ARENA 🚀",
        description="Start a PvP crypto battle! Select a cryptocurrency:",
        color=discord.Color.green()
    )
    
    min_bets_text = "\n".join(
        [f"• **{crypto}**: ${max(CRYPTOCURRENCIES[crypto]['min_bet'], MIN_BET_AMOUNT)}" 
         for crypto in CRYPTOCURRENCIES]
    )
    embed.add_field(
        name="💰 Minimum Bets",
        value=min_bets_text,
        inline=False
    )
    
    embed.add_field(
        name="⚡ How to Play",
        value="1. Select a cryptocurrency\n2. Enter opponent's ID\n3. Follow instructions in private ticket",
        inline=False
    )
    
    embed.set_footer(text="Battles are final. Play responsibly.")
    
    await ctx.send(embed=embed, view=CryptoSelectView())
    await ctx.send("✅ Betting panel is now active! Click buttons to start battles.", delete_after=20)

@bot.command()
async def deposit(ctx, crypto: str):
    """Get a deposit address for cryptocurrency"""
    crypto = crypto.upper()
    if crypto not in CRYPTOCURRENCIES:
        await ctx.send(f"❌ Invalid cryptocurrency. Available: {', '.join(CRYPTOCURRENCIES.keys())}")
        return
    
    user_id = str(ctx.author.id)
    wallet = get_user_wallet(user_id)
    
    # Generate or retrieve deposit address
    address = generate_deposit_address(user_id, crypto)
    if not address:
        await ctx.send("❌ Failed to generate deposit address. Please try again later.")
        return
    
    # Get min deposit requirements
    min_deposit = "0.001 BTC" if crypto == "BTC" else "0.1 LTC"
    
    embed = discord.Embed(
        title=f"📥 {crypto} Deposit",
        description=f"Send **{crypto}** to the following address:",
        color=discord.Color.green()
    )
    embed.add_field(
        name="Address",
        value=f"```{address}```",
        inline=False
    )
    embed.add_field(
        name="Important Information",
        value=(
            f"• Send only **{crypto}** to this address\n"
            f"• Minimum deposit: {min_deposit}\n"
            f"• Deposits typically appear within 10-30 minutes\n"
            f"• You'll receive a DM when your deposit is detected"
        ),
        inline=False
    )
    # Add fiat balance
    balance_fiat = wallet['balances'][crypto] * Decimal(FIAT_RATES[crypto])
    embed.set_footer(text=f"Your current {crypto} balance: {wallet['balances'][crypto]} (${balance_fiat:.2f})")
    
    await ctx.send(embed=embed)

@bot.command()
async def balance(ctx, crypto: str = None):
    """Check your crypto balances"""
    wallet = get_user_wallet(str(ctx.author.id))
    
    if crypto:
        crypto = crypto.upper()
        if crypto in wallet['balances']:
            # Calculate fiat value
            balance_fiat = wallet['balances'][crypto] * Decimal(FIAT_RATES[crypto])
            
            embed = discord.Embed(
                title=f"💰 {crypto} Balance",
                description=f"**{wallet['balances'][crypto]} {crypto} (${balance_fiat:.2f})**",
                color=discord.Color.blue()
            )
            await ctx.send(embed=embed)
        else:
            await ctx.send(f"❌ Invalid cryptocurrency. Available: {', '.join(wallet['balances'].keys())}")
    else:
        embed = discord.Embed(
            title="💰 Your Crypto Balances",
            color=discord.Color.blue()
        )
        for crypto, balance in wallet['balances'].items():
            if balance > 0:
                # Calculate fiat value
                balance_fiat = balance * Decimal(FIAT_RATES[crypto])
                embed.add_field(
                    name=crypto,
                    value=f"{balance} (${balance_fiat:.2f})",
                    inline=True
                )
        if not embed.fields:
            embed.description = "You have no balances. Use `!deposit <crypto>` to add funds."
        await ctx.send(embed=embed)

@bot.command()
async def withdraw(ctx, crypto: str, amount: float, address: str):
    """Withdraw cryptocurrency to an external address"""
    crypto = crypto.upper()
    if crypto not in CRYPTOCURRENCIES:
        await ctx.send(f"❌ Invalid cryptocurrency. Available: {', '.join(CRYPTOCURRENCIES.keys())}")
        return
    
    amount_dec = Decimal(str(amount))
    wallet = get_user_wallet(str(ctx.author.id))
    fee = CRYPTOCURRENCIES[crypto]['withdrawal_fee']
    total_required = amount_dec + Decimal(str(fee))
    
    if wallet['balances'][crypto] < total_required:
        await ctx.send(
            f"❌ Insufficient balance. You need {total_required} {crypto} "
            f"(including {fee} {crypto} fee). Your balance: {wallet['balances'][crypto]} {crypto}"
        )
        return
    
    # Send real withdrawal
    txid, error = send_withdrawal(str(ctx.author.id), crypto, address, amount_dec)
    if error:
        await ctx.send(f"❌ Withdrawal failed: {error}")
        return
    
    # Deduct from balance
    wallet['balances'][crypto] -= total_required
    
    # Record transaction
    add_transaction(
        str(ctx.author.id),
        'withdrawal',
        crypto,
        -total_required,
        notes=f"Withdrawal to {address} | TX: {txid}"
    )
    
    save_wallets()
    
    embed = discord.Embed(
        title="✅ Withdrawal Processed",
        description=f"Your withdrawal has been completed!",
        color=discord.Color.green()
    )
    embed.add_field(
        name="Details",
        value=(
            f"• Amount: {amount} {crypto}\n"
            f"• Fee: {fee} {crypto}\n"
            f"• Total Deducted: {total_required} {crypto}\n"
            f"• Address: `{address}`\n"
            f"• Transaction ID: `{txid}`"
        ),
        inline=False
    )
    await ctx.send(embed=embed)

@bot.command()
async def transactions(ctx, count: int = 5):
    """View your recent transactions"""
    wallet = get_user_wallet(str(ctx.author.id))
    transactions = wallet.get('transactions', [])[:count]
    
    if not transactions:
        await ctx.send("❌ No transactions found.")
        return
    
    embed = discord.Embed(
        title=f"📊 Last {len(transactions)} Transactions",
        color=discord.Color.blue()
    )
    
    for tx in transactions:
        # Calculate fiat value if possible
        fiat_value = ""
        if tx['crypto'] in FIAT_RATES:
            fiat_value = f" (${Decimal(tx['amount']) * Decimal(FIAT_RATES[tx['crypto']]):.2f})"
            
        value = (
            f"**Type**: {tx['type'].replace('_', ' ').title()}\n"
            f"**Amount**: {tx['amount']} {tx['crypto']}{fiat_value}\n"
            f"**Date**: {tx['timestamp'][:10]}\n"
        )
        if tx.get('battle_id'):
            value += f"**Battle ID**: {tx['battle_id']}\n"
        if tx.get('notes'):
            value += f"**Notes**: {tx['notes']}\n"
        
        embed.add_field(
            name=f"TX {tx['id']}",
            value=value,
            inline=False
        )
    
    await ctx.send(embed=embed)

@bot.command()
async def roll(ctx):
    if ctx.channel.id in dice_games and ctx.author.id == dice_games[ctx.channel.id]["current_player"]:
        await process_dice_roll(ctx.channel, dice_games[ctx.channel.id])

@bot.command()
async def help(ctx):
    embed = discord.Embed(
        title="Crypto Battle Bot Help",
        description="Start PvP crypto battles with friends!",
        color=discord.Color.blue()
    )
    embed.add_field(
        name="Getting Started",
        value="1. Admin runs `!setup` in the betting channel\n"
              "2. Click a crypto button to start a battle\n"
              "3. Enter your opponent's ID\n"
              "4. Complete the battle in the private ticket",
        inline=False
    )
    embed.add_field(
        name="Wallet Commands",
        value="• `!deposit <crypto>` - Get deposit address\n"
              "• `!balance [crypto]` - Check your balance\n"
              "• `!withdraw <crypto> <amount> <address>` - Withdraw funds\n"
              "• `!transactions [count]` - View transaction history",
        inline=False
    )
    embed.add_field(
        name="Game Commands",
        value="• `!roll` - Roll dice during a dice game",
        inline=False
    )
    await ctx.send(embed=embed)

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    print(f"Command error: {type(error).__name__} - {str(error)}")
    
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ You don't have permission to use this command!", delete_after=10)
    elif isinstance(error, commands.BadArgument):
        await ctx.send("❌ Invalid argument. Please check your input.", delete_after=10)
    else:
        await ctx.send("⚠️ An unexpected error occurred. Please try again.", delete_after=10)

# ===== BOT STARTUP =====
if __name__ == "__main__":
    print("Starting Crypto Battle Bot...")
    print("=" * 50)
    
    try:
        bot.run(BOT_TOKEN)
    except discord.LoginFailure:
        print("\n❌ INVALID TOKEN: Failed to login")
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {str(e)}")
        traceback.print_exc()
