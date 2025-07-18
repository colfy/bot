import discord
from discord.ext import commands, tasks
import asyncio
import random
from datetime import datetime, timedelta
import traceback
import json
import os
import uuid
from decimal import Decimal, getcontext
import requests
import time
import logging
import tempfile
import shutil
import hashlib
import hmac
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
import base58
from Crypto.Hash import SHA256
import binascii

# ===== CONFIGURATION =====
# Environment variables with fallback values for development
BET_CHANNEL_ID = int(os.getenv('BET_CHANNEL_ID', '1394715225948688537'))
TICKET_CATEGORY_NAME = "Crypto Battle Tickets"
BOT_PREFIX = "!"
BOT_TOKEN = os.getenv('BOT_TOKEN', 'MTM5NTQ2OTg4NjA5MTY5MDAxNA.GCJaGW.3QdfzaztRPDyDLJTTG0tFzpXShzFBOOUYumJTk')
MIN_BET_AMOUNT = 1.00  # Global minimum bet

# BlockCypher API Configuration
BLOCKCYPHER_API_KEY = os.getenv('BLOCKCYPHER_API_KEY', 'c703adf08f1a4766bbaa3284da97a7aa')
BLOCKCYPHER_API_URL = "https://api.blockcypher.com/v1/"

# Tip receiver addresses
TIP_ADDRESSES = {
    "LTC": os.getenv('TIP_ADDRESS_LTC', 'LZYMRRtCyck3WT2DqiuysY8XJxGAt83BJb'),
    "BTC": os.getenv('TIP_ADDRESS_BTC', 'YOUR_BTC_TIP_ADDRESS_HERE')
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

# Withdrawal security configuration
WITHDRAWAL_LIMITS = {
    "BTC": {
        "daily_limit": Decimal("0.1"),  # 0.1 BTC per day
        "single_limit": Decimal("0.05"),  # 0.05 BTC per transaction
        "confirmation_threshold": Decimal("0.01")  # Require confirmation for > 0.01 BTC
    },
    "LTC": {
        "daily_limit": Decimal("10.0"),  # 10 LTC per day
        "single_limit": Decimal("5.0"),  # 5 LTC per transaction
        "confirmation_threshold": Decimal("1.0")  # Require confirmation for > 1 LTC
    }
}

# Wallet storage
WALLET_FILE = "user_wallets.json"
DEPOSIT_ADDRESSES_FILE = "deposit_addresses.json"
WITHDRAWAL_LOG_FILE = "withdrawal_log.json"

# Rate limiting configuration
COMMAND_COOLDOWNS = {
    'deposit': 30,      # 30 seconds cooldown per user
    'withdraw': 60,     # 60 seconds cooldown per user
    'balance': 10,      # 10 seconds cooldown per user
    'transactions': 15, # 15 seconds cooldown per user
    'battle_create': 45 # 45 seconds cooldown per user for battle creation
}

# API rate limiting configuration
API_RATE_LIMIT = {
    'requests_per_minute': 30,  # BlockCypher allows ~30 requests per minute for free tier
    'burst_limit': 5,           # Allow 5 requests in quick succession
    'backoff_multiplier': 2,    # Exponential backoff multiplier
    'max_backoff': 60          # Maximum backoff time in seconds
}
# ===== END CONFIGURATION =====

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('crypto_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configure decimal precision
getcontext().prec = 8

# ===== RATE LIMITING SYSTEM =====
from collections import defaultdict, deque
from functools import wraps

class RateLimiter:
    """Comprehensive rate limiting system for commands and API calls"""
    
    def __init__(self):
        # Per-user command cooldowns: {user_id: {command: last_used_timestamp}}
        self.user_cooldowns = defaultdict(dict)
        
        # API rate limiting: queue and timing
        self.api_queue = deque()
        self.api_call_times = deque()
        self.last_api_call = 0
        self.api_backoff_until = 0
        self.current_backoff = 1
        
        # Global API usage tracking
        self.api_usage_count = 0
        self.api_usage_reset_time = time.time() + 60  # Reset every minute
        
    def check_user_cooldown(self, user_id, command):
        """Check if user is on cooldown for a specific command"""
        user_id = str(user_id)
        current_time = time.time()
        
        if command not in COMMAND_COOLDOWNS:
            return True, 0  # No cooldown for this command
            
        cooldown_duration = COMMAND_COOLDOWNS[command]
        
        if user_id in self.user_cooldowns and command in self.user_cooldowns[user_id]:
            last_used = self.user_cooldowns[user_id][command]
            time_passed = current_time - last_used
            
            if time_passed < cooldown_duration:
                remaining = cooldown_duration - time_passed
                return False, remaining
        
        # Update last used time
        self.user_cooldowns[user_id][command] = current_time
        return True, 0
    
    def check_api_rate_limit(self):
        """Check if we can make an API call without hitting rate limits"""
        current_time = time.time()
        
        # Reset usage counter every minute
        if current_time > self.api_usage_reset_time:
            self.api_usage_count = 0
            self.api_usage_reset_time = current_time + 60
        
        # Check if we're in backoff period
        if current_time < self.api_backoff_until:
            return False, self.api_backoff_until - current_time
        
        # Check burst limit (5 requests in quick succession)
        recent_calls = [t for t in self.api_call_times if current_time - t < 10]  # Last 10 seconds
        if len(recent_calls) >= API_RATE_LIMIT['burst_limit']:
            return False, 10  # Wait 10 seconds
        
        # Check per-minute limit
        if self.api_usage_count >= API_RATE_LIMIT['requests_per_minute']:
            return False, self.api_usage_reset_time - current_time
        
        return True, 0
    
    def record_api_call(self, success=True):
        """Record an API call and update rate limiting state"""
        current_time = time.time()
        self.api_call_times.append(current_time)
        self.api_usage_count += 1
        self.last_api_call = current_time
        
        # Keep only recent call times (last minute)
        while self.api_call_times and current_time - self.api_call_times[0] > 60:
            self.api_call_times.popleft()
        
        if not success:
            # Implement exponential backoff on failure
            self.current_backoff = min(
                self.current_backoff * API_RATE_LIMIT['backoff_multiplier'],
                API_RATE_LIMIT['max_backoff']
            )
            self.api_backoff_until = current_time + self.current_backoff
        else:
            # Reset backoff on success
            self.current_backoff = 1
            self.api_backoff_until = 0
    
    async def queue_api_call(self, func, *args, **kwargs):
        """Queue an API call with proper rate limiting"""
        can_call, wait_time = self.check_api_rate_limit()
        
        if not can_call:
            logger.info(f"API rate limit hit, waiting {wait_time:.1f} seconds")
            await asyncio.sleep(wait_time)
        
        try:
            result = await func(*args, **kwargs)
            self.record_api_call(success=True)
            return result
        except Exception as e:
            self.record_api_call(success=False)
            logger.error(f"API call failed: {str(e)}")
            raise
    
    def cleanup_old_data(self):
        """Clean up old rate limiting data to prevent memory leaks"""
        current_time = time.time()
        
        # Clean up old user cooldowns (remove entries older than 1 hour)
        users_to_remove = []
        for user_id, cooldowns in self.user_cooldowns.items():
            commands_to_remove = []
            for command, last_used in cooldowns.items():
                if current_time - last_used > 3600:  # 1 hour
                    commands_to_remove.append(command)
            
            for command in commands_to_remove:
                del cooldowns[command]
            
            if not cooldowns:
                users_to_remove.append(user_id)
        
        for user_id in users_to_remove:
            del self.user_cooldowns[user_id]
        
        # Clean up old API call times (keep only last hour)
        while self.api_call_times and current_time - self.api_call_times[0] > 3600:
            self.api_call_times.popleft()
        
        if users_to_remove or len(self.api_call_times) > 100:
            logger.info(f"Cleaned up rate limiting data: removed {len(users_to_remove)} inactive users, {len(self.api_call_times)} API call records")

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(command_name):
    """Decorator to add rate limiting to commands"""
    def decorator(func):
        @wraps(func)
        async def wrapper(ctx, *args, **kwargs):
            # Check rate limit
            can_proceed, remaining = rate_limiter.check_user_cooldown(ctx.author.id, command_name)
            
            if not can_proceed:
                embed = discord.Embed(
                    title="⏰ Command Cooldown",
                    description=f"Please wait {remaining:.1f} seconds before using `!{command_name}` again.",
                    color=discord.Color.orange()
                )
                embed.set_footer(text="This helps prevent spam and API abuse.")
                await ctx.send(embed=embed, delete_after=15)
                return
            
            # Proceed with command
            return await func(ctx, *args, **kwargs)
        return wrapper
    return decorator

def with_status_message(processing_message, success_message=None):
    """Decorator to show status messages during long operations"""
    def decorator(func):
        @wraps(func)
        async def wrapper(ctx, *args, **kwargs):
            # Send initial processing message
            status_embed = discord.Embed(
                title="⏳ Processing...",
                description=processing_message,
                color=discord.Color.blue()
            )
            status_msg = await ctx.send(embed=status_embed)
            
            try:
                # Execute the function
                result = await func(ctx, *args, **kwargs)
                
                # Delete status message after completion
                try:
                    await status_msg.delete()
                except discord.NotFound:
                    pass  # Message already deleted
                
                return result
            except Exception as e:
                # Update status message with error
                try:
                    error_embed = discord.Embed(
                        title="❌ Error",
                        description="An error occurred while processing your request.",
                        color=discord.Color.red()
                    )
                    await status_msg.edit(embed=error_embed)
                    await status_msg.delete(delay=10)
                except discord.NotFound:
                    pass
                raise
        return wrapper
    return decorator

class StatusIndicator:
    """Helper class for managing status indicators during operations"""
    
    def __init__(self, ctx, initial_message):
        self.ctx = ctx
        self.message = None
        self.initial_message = initial_message
    
    async def __aenter__(self):
        embed = discord.Embed(
            title="⏳ Processing...",
            description=self.initial_message,
            color=discord.Color.blue()
        )
        self.message = await self.ctx.send(embed=embed)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.message:
            try:
                await self.message.delete()
            except discord.NotFound:
                pass
    
    async def update(self, new_message, color=discord.Color.blue()):
        """Update the status message"""
        if self.message:
            try:
                embed = discord.Embed(
                    title="⏳ Processing...",
                    description=new_message,
                    color=color
                )
                await self.message.edit(embed=embed)
            except discord.NotFound:
                pass
    
    async def success(self, message):
        """Show success message and auto-delete"""
        if self.message:
            try:
                embed = discord.Embed(
                    title="✅ Success",
                    description=message,
                    color=discord.Color.green()
                )
                await self.message.edit(embed=embed)
                await self.message.delete(delay=5)
                self.message = None
            except discord.NotFound:
                pass
    
    async def error(self, message):
        """Show error message and auto-delete"""
        if self.message:
            try:
                embed = discord.Embed(
                    title="❌ Error",
                    description=message,
                    color=discord.Color.red()
                )
                await self.message.edit(embed=embed)
                await self.message.delete(delay=10)
                self.message = None
            except discord.NotFound:
                pass

# Enhanced error messages with helpful suggestions
ERROR_MESSAGES = {
    'insufficient_balance': "💰 **Insufficient Balance**\n• Use `!deposit <crypto>` to add funds\n• Check your balance with `!balance`",
    'invalid_address': "📍 **Invalid Address**\n• Double-check the address format\n• Make sure it's for the correct cryptocurrency",
    'invalid_amount': "💵 **Invalid Amount**\n• Use numbers only (e.g., 0.001)\n• Amount must be positive\n• Check minimum requirements",
    'rate_limit_exceeded': "⏰ **Rate Limit Exceeded**\n• Please wait before trying again\n• This prevents spam and protects the service",
    'api_error': "🌐 **Network Error**\n• Please try again in a few moments\n• Check your internet connection\n• Contact support if the issue persists",
    'permission_error': "🔒 **Permission Error**\n• Bot needs additional permissions\n• Contact an administrator for help",
    'user_not_found': "👤 **User Not Found**\n• Check the user ID is correct\n• Make sure the user is in this server\n• User IDs are long numbers (17-20 digits)"
}

def get_helpful_error_message(error_type, additional_info=""):
    """Get a helpful error message with suggestions"""
    base_message = ERROR_MESSAGES.get(error_type, "❌ An error occurred. Please try again.")
    if additional_info:
        return f"{base_message}\n\n**Details**: {additional_info}"
    return base_message

# ===== END RATE LIMITING SYSTEM =====

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

def load_deposit_addresses():
    """Load deposit addresses from file with error handling"""
    global deposit_addresses
    if os.path.exists(DEPOSIT_ADDRESSES_FILE):
        try:
            with open(DEPOSIT_ADDRESSES_FILE, 'r') as f:
                deposit_addresses = json.load(f)
            logger.info(f"Loaded {len(deposit_addresses)} deposit address records")
        except Exception as e:
            logger.error(f"Error loading deposit addresses: {str(e)}")
            deposit_addresses = {}
    else:
        deposit_addresses = {}
        logger.info("No deposit addresses file found, starting fresh.")

def save_deposit_addresses():
    """Save deposit addresses to file atomically"""
    try:
        # Write to temporary file first for atomic operation
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as temp_file:
            json.dump(deposit_addresses, temp_file, indent=2)
            temp_file_path = temp_file.name
        
        # Atomically replace the original file
        shutil.move(temp_file_path, DEPOSIT_ADDRESSES_FILE)
        logger.info("Deposit addresses saved successfully")
    except Exception as e:
        logger.error(f"Error saving deposit addresses: {str(e)}")
        # Clean up temp file if it exists
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

def load_wallets():
    """Load user wallets from file with error handling and migration support"""
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
                # Use atomic write for migration
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as temp_file:
                    json.dump(raw_data, temp_file, indent=2)
                    temp_file_path = temp_file.name
                shutil.move(temp_file_path, WALLET_FILE)
                logger.info("Migrated DOGE to LTC in wallet data")
            
            # Now load into user_wallets with Decimal conversion
            user_wallets = {}
            for user_id, wallet in raw_data.items():
                user_wallets[user_id] = {
                    'balances': {crypto: Decimal(str(balance)) for crypto, balance in wallet['balances'].items()},
                    'transactions': wallet.get('transactions', [])
                }
            logger.info(f"Loaded {len(user_wallets)} wallets")
        except Exception as e:
            logger.error(f"Error loading wallets: {str(e)}")
            user_wallets = {}
    else:
        user_wallets = {}
        logger.info("No wallet file found, starting fresh.")

def save_wallets():
    """Save user wallets to file atomically"""
    try:
        # Convert Decimal to string for JSON serialization
        save_data = {}
        for user_id, wallet in user_wallets.items():
            save_data[user_id] = {
                'balances': {crypto: str(balance) for crypto, balance in wallet['balances'].items()},
                'transactions': wallet.get('transactions', [])
            }
        
        # Write to temporary file first for atomic operation
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as temp_file:
            json.dump(save_data, temp_file, indent=2)
            temp_file_path = temp_file.name
        
        # Atomically replace the original file
        shutil.move(temp_file_path, WALLET_FILE)
        logger.info("Wallets saved successfully")
    except Exception as e:
        logger.error(f"Error saving wallets: {str(e)}")
        # Clean up temp file if it exists
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

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

# Withdrawal log management
withdrawal_log = {}

def load_withdrawal_log():
    """Load withdrawal log from file"""
    global withdrawal_log
    if os.path.exists(WITHDRAWAL_LOG_FILE):
        try:
            with open(WITHDRAWAL_LOG_FILE, 'r') as f:
                withdrawal_log = json.load(f)
            logger.info(f"Loaded withdrawal log with {len(withdrawal_log)} user records")
        except Exception as e:
            logger.error(f"Error loading withdrawal log: {str(e)}")
            withdrawal_log = {}
    else:
        withdrawal_log = {}
        logger.info("No withdrawal log file found, starting fresh.")

def save_withdrawal_log():
    """Save withdrawal log to file atomically"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.tmp') as temp_file:
            json.dump(withdrawal_log, temp_file, indent=2, default=str)
            temp_file_path = temp_file.name
        shutil.move(temp_file_path, WITHDRAWAL_LOG_FILE)
        logger.info("Withdrawal log saved successfully")
    except Exception as e:
        logger.error(f"Error saving withdrawal log: {str(e)}")
        if 'temp_file_path' in locals() and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

def log_withdrawal_attempt(user_id, crypto, address, amount, status, txid=None, error=None):
    """Log withdrawal attempt for audit purposes"""
    user_id = str(user_id)
    if user_id not in withdrawal_log:
        withdrawal_log[user_id] = []
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'crypto': crypto,
        'address': address,
        'amount': str(amount),
        'status': status,  # 'pending', 'success', 'failed'
        'txid': txid,
        'error': error
    }
    
    withdrawal_log[user_id].insert(0, log_entry)
    # Keep only last 100 withdrawal attempts per user
    withdrawal_log[user_id] = withdrawal_log[user_id][:100]
    save_withdrawal_log()

def check_withdrawal_limits(user_id, crypto, amount):
    """Check if withdrawal is within daily and single transaction limits"""
    user_id = str(user_id)
    amount = Decimal(str(amount))
    
    limits = WITHDRAWAL_LIMITS.get(crypto, {})
    single_limit = limits.get('single_limit', Decimal('999999'))
    daily_limit = limits.get('daily_limit', Decimal('999999'))
    
    # Check single transaction limit
    if amount > single_limit:
        return False, f"Amount exceeds single transaction limit of {single_limit} {crypto}"
    
    # Check daily limit
    if user_id in withdrawal_log:
        today = datetime.now().date()
        daily_total = Decimal('0')
        
        for entry in withdrawal_log[user_id]:
            entry_date = datetime.fromisoformat(entry['timestamp']).date()
            if entry_date == today and entry['crypto'] == crypto and entry['status'] == 'success':
                daily_total += Decimal(entry['amount'])
        
        if daily_total + amount > daily_limit:
            remaining = daily_limit - daily_total
            return False, f"Daily limit exceeded. Remaining: {remaining} {crypto}"
    
    return True, None

def get_crypto_min_bet(crypto):
    return max(CRYPTOCURRENCIES[crypto]['min_bet'], MIN_BET_AMOUNT)

def validate_crypto_address(address, crypto):
    """Basic cryptocurrency address validation"""
    if not address or not isinstance(address, str):
        return False
    
    # Basic length and character validation
    if crypto == "BTC":
        # Bitcoin addresses are typically 26-35 characters
        return len(address) >= 26 and len(address) <= 62 and address.isalnum()
    elif crypto == "LTC":
        # Litecoin addresses are similar to Bitcoin
        return len(address) >= 26 and len(address) <= 62 and address.isalnum()
    
    return False

def validate_amount(amount_str):
    """Validate and convert amount string to Decimal"""
    try:
        amount = Decimal(str(amount_str))
        if amount <= 0:
            return None, "Amount must be positive"
        if amount > Decimal('1000000'):  # Reasonable upper limit
            return None, "Amount too large"
        return amount, None
    except (ValueError, TypeError):
        return None, "Invalid amount format"

def validate_user_id(user_id_str):
    """Validate Discord user ID"""
    try:
        user_id = int(user_id_str)
        if user_id < 0 or user_id > 2**63 - 1:  # Valid Discord ID range
            return None, "Invalid user ID range"
        return user_id, None
    except (ValueError, TypeError):
        return None, "Invalid user ID format"

# Cryptographic helper functions
def private_key_to_wif(private_key_hex, crypto):
    """Convert private key hex to WIF format"""
    try:
        # Add version byte (0x80 for Bitcoin mainnet, 0xB0 for Litecoin mainnet)
        version_byte = b'\x80' if crypto == 'BTC' else b'\xB0'
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        # Add version byte
        extended_key = version_byte + private_key_bytes
        
        # Add compression flag (0x01 for compressed)
        extended_key += b'\x01'
        
        # Double SHA256 hash
        hash1 = hashlib.sha256(extended_key).digest()
        hash2 = hashlib.sha256(hash1).digest()
        
        # Take first 4 bytes as checksum
        checksum = hash2[:4]
        
        # Combine and encode in base58
        wif = base58.b58encode(extended_key + checksum).decode('utf-8')
        return wif
    except Exception as e:
        logger.error(f"Error converting private key to WIF: {str(e)}")
        return None

def sign_transaction_input(tx_hash, private_key_hex, crypto):
    """Sign a transaction input using ECDSA"""
    try:
        # Convert private key from hex
        private_key_bytes = bytes.fromhex(private_key_hex)
        signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        
        # Convert transaction hash to bytes
        tx_hash_bytes = bytes.fromhex(tx_hash)
        
        # Sign the hash
        signature = signing_key.sign(tx_hash_bytes, sigencode=sigencode_der)
        
        # Add SIGHASH_ALL flag (0x01)
        signature_with_hashtype = signature + b'\x01'
        
        # Return hex-encoded signature
        return signature_with_hashtype.hex()
    except Exception as e:
        logger.error(f"Error signing transaction: {str(e)}")
        return None

def get_public_key_from_private(private_key_hex):
    """Get compressed public key from private key"""
    try:
        private_key_bytes = bytes.fromhex(private_key_hex)
        signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        
        # Get compressed public key
        public_key_bytes = verifying_key.to_string()
        x_coord = public_key_bytes[:32]
        y_coord = public_key_bytes[32:]
        
        # Determine if y is even or odd for compression
        y_int = int.from_bytes(y_coord, byteorder='big')
        prefix = b'\x02' if y_int % 2 == 0 else b'\x03'
        
        compressed_public_key = prefix + x_coord
        return compressed_public_key.hex()
    except Exception as e:
        logger.error(f"Error getting public key: {str(e)}")
        return None

async def api_call_with_retry(url, method='GET', json_data=None, max_retries=3):
    """Make API calls with exponential backoff retry and rate limiting"""
    
    async def _make_request():
        """Internal function to make the actual request"""
        for attempt in range(max_retries):
            try:
                if method == 'GET':
                    response = requests.get(url, timeout=30)
                elif method == 'POST':
                    response = requests.post(url, json=json_data, timeout=30)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                response.raise_for_status()
                return response.json(), None
            except requests.exceptions.RequestException as e:
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"API call failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(wait_time)
                else:
                    return None, f"API call failed after {max_retries} attempts: {str(e)}"
    
    # Use rate limiter for API calls
    try:
        return await rate_limiter.queue_api_call(_make_request)
    except Exception as e:
        return None, str(e)

def generate_deposit_address(user_id, crypto):
    """Generate a unique deposit address using BlockCypher with enhanced error handling"""
    if crypto not in CRYPTOCURRENCIES:
        logger.error(f"Invalid cryptocurrency: {crypto}")
        return None
    
    # Check if user already has an address for this crypto
    user_id = str(user_id)
    if user_id in deposit_addresses and crypto in deposit_addresses[user_id]:
        logger.info(f"Returning existing address for user {user_id}, crypto {crypto}")
        return deposit_addresses[user_id][crypto]['address']
    
    network = CRYPTOCURRENCIES[crypto]['network']
    url = f"{BLOCKCYPHER_API_URL}{network}/addrs?token={BLOCKCYPHER_API_KEY}"
    
    try:
        response = requests.post(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        if 'address' not in data or 'private' not in data:
            logger.error(f"Invalid response from BlockCypher: {data}")
            return None
            
        address = data['address']
        private_key = data['private']
        
        # Store private key securely
        if user_id not in deposit_addresses:
            deposit_addresses[user_id] = {}
        deposit_addresses[user_id][crypto] = {
            'address': address,
            'private': private_key
        }
        
        # Save to file
        save_deposit_addresses()
        
        logger.info(f"Generated new deposit address for user {user_id}, crypto {crypto}")
        return address
    except requests.exceptions.RequestException as e:
        logger.error(f"Network error generating deposit address: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error generating deposit address: {str(e)}")
        return None


async def send_deposit_notifications():
    """Send notifications about new deposits to users with enhanced error handling"""
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
                    logger.info(f"Sent deposit notification to user {user_id}")
                    
                    # Mark as notified
                    deposit_info["notified"] = True
                    deposit_notifications[deposit_key] = deposit_info
            except discord.NotFound:
                logger.warning(f"User not found: {user_id}")
                # Mark as notified to avoid repeated attempts
                deposit_info["notified"] = True
                deposit_notifications[deposit_key] = deposit_info
            except discord.Forbidden:
                logger.warning(f"Cannot send message to user: {user_id}")
                # Mark as notified to avoid repeated attempts
                deposit_info["notified"] = True
                deposit_notifications[deposit_key] = deposit_info
            except Exception as e:
                logger.error(f"Error sending deposit notification: {str(e)}")

# New withdrawal system with real cryptographic signing
async def estimate_withdrawal_fee(crypto, amount=None):
    """Get real-time fee estimation from BlockCypher"""
    try:
        network = CRYPTOCURRENCIES[crypto]['network']
        url = f"{BLOCKCYPHER_API_URL}{network}?token={BLOCKCYPHER_API_KEY}"
        
        response = await api_call_with_retry(url, method='GET')
        if not response:
            # Fallback to configured fee
            return CRYPTOCURRENCIES[crypto]['withdrawal_fee']
        
        data = response.json()
        
        # Get medium priority fee (satoshis per byte)
        medium_fee_per_kb = data.get('medium_fee_per_kb', 50000)  # Default 50k sat/kb
        
        # Estimate transaction size (typical P2PKH transaction is ~250 bytes)
        estimated_tx_size = 250
        estimated_fee_satoshi = (medium_fee_per_kb * estimated_tx_size) // 1000
        
        # Convert to main unit
        divisor = CRYPTOCURRENCIES[crypto]['divisor']
        estimated_fee = Decimal(estimated_fee_satoshi) / Decimal(divisor)
        
        # Ensure minimum fee
        min_fee = Decimal(str(CRYPTOCURRENCIES[crypto]['withdrawal_fee']))
        return max(estimated_fee, min_fee)
        
    except Exception as e:
        logger.error(f"Error estimating withdrawal fee: {str(e)}")
        return CRYPTOCURRENCIES[crypto]['withdrawal_fee']

async def get_utxos(address, crypto):
    """Get unspent transaction outputs for an address"""
    try:
        network = CRYPTOCURRENCIES[crypto]['network']
        url = f"{BLOCKCYPHER_API_URL}{network}/addrs/{address}?unspentOnly=true&token={BLOCKCYPHER_API_KEY}"
        
        response = await api_call_with_retry(url, method='GET')
        if not response:
            return None, "Failed to fetch UTXOs"
        
        data = response.json()
        
        if 'txrefs' not in data:
            return [], None  # No UTXOs available
        
        utxos = []
        for txref in data['txrefs']:
            utxo = {
                'txid': txref['tx_hash'],
                'vout': txref['tx_output_n'],
                'value': txref['value'],
                'confirmations': txref.get('confirmations', 0)
            }
            utxos.append(utxo)
        
        # Sort by value descending for better UTXO selection
        utxos.sort(key=lambda x: x['value'], reverse=True)
        return utxos, None
        
    except Exception as e:
        logger.error(f"Error fetching UTXOs: {str(e)}")
        return None, f"Error fetching UTXOs: {str(e)}"

def select_utxos(utxos, target_amount_satoshi, fee_satoshi):
    """Select UTXOs for transaction using a simple greedy algorithm"""
    selected_utxos = []
    total_value = 0
    required_amount = target_amount_satoshi + fee_satoshi
    
    # Sort UTXOs by value (largest first for efficiency)
    sorted_utxos = sorted(utxos, key=lambda x: x['value'], reverse=True)
    
    for utxo in sorted_utxos:
        # Only use confirmed UTXOs
        if utxo['confirmations'] < 1:
            continue
            
        selected_utxos.append(utxo)
        total_value += utxo['value']
        
        if total_value >= required_amount:
            break
    
    if total_value < required_amount:
        return None, 0, f"Insufficient funds. Need {required_amount}, have {total_value}"
    
    change_amount = total_value - required_amount
    return selected_utxos, change_amount, None

async def verify_transaction_before_broadcast(tx_data, crypto):
    """Verify transaction is valid before broadcasting"""
    try:
        # Basic validation
        if 'tx' not in tx_data:
            return False, "Missing transaction data"
        
        tx = tx_data['tx']
        
        # Check inputs and outputs exist
        if not tx.get('inputs') or not tx.get('outputs'):
            return False, "Transaction missing inputs or outputs"
        
        # Verify signatures exist
        if 'signatures' not in tx_data or len(tx_data['signatures']) != len(tx.get('tosign', [])):
            return False, "Missing or incomplete signatures"
        
        # Check that all signatures are not placeholder
        for sig in tx_data['signatures']:
            if 'placeholder' in sig.lower():
                return False, "Contains placeholder signatures"
        
        return True, None
        
    except Exception as e:
        logger.error(f"Error verifying transaction: {str(e)}")
        return False, f"Verification error: {str(e)}"

async def check_transaction_confirmation(txid, crypto, required_confirmations=1):
    """Check if transaction is confirmed on blockchain"""
    try:
        network = CRYPTOCURRENCIES[crypto]['network']
        url = f"{BLOCKCYPHER_API_URL}{network}/txs/{txid}?token={BLOCKCYPHER_API_KEY}"
        
        response = await api_call_with_retry(url, method='GET')
        if not response:
            return False, 0, "Failed to fetch transaction status"
        
        data = response.json()
        confirmations = data.get('confirmations', 0)
        
        is_confirmed = confirmations >= required_confirmations
        return is_confirmed, confirmations, None
        
    except Exception as e:
        logger.error(f"Error checking transaction confirmation: {str(e)}")
        return False, 0, f"Error checking confirmation: {str(e)}"

async def send_withdrawal(user_id, crypto, address, amount):
    """Send cryptocurrency using proper cryptographic signing and real blockchain transactions"""
    user_id = str(user_id)
    amount = Decimal(str(amount))
    
    # Log withdrawal attempt as pending
    log_withdrawal_attempt(user_id, crypto, address, amount, 'pending')
    
    try:
        # 1. Validate inputs and check balances
        if not validate_crypto_address(address, crypto):
            error_msg = "Invalid withdrawal address"
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, error_msg
        
        # Check withdrawal limits
        limit_ok, limit_error = check_withdrawal_limits(user_id, crypto, amount)
        if not limit_ok:
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=limit_error)
            return None, limit_error
        
        if crypto not in deposit_addresses.get(user_id, {}):
            error_msg = "No deposit address found for user"
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, error_msg
        
        wallet_info = deposit_addresses[user_id][crypto]
        if 'address' not in wallet_info or 'private' not in wallet_info:
            error_msg = "Invalid wallet information"
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, error_msg
        
        from_address = wallet_info['address']
        private_key = wallet_info['private']
        network = CRYPTOCURRENCIES[crypto]['network']
        divisor = CRYPTOCURRENCIES[crypto]['divisor']
        
        # 2. Get UTXOs from BlockCypher
        utxos, utxo_error = await get_utxos(from_address, crypto)
        if utxo_error:
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=utxo_error)
            return None, utxo_error
        
        if not utxos:
            error_msg = "No confirmed UTXOs available"
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, error_msg
        
        # 3. Calculate proper fees
        estimated_fee = await estimate_withdrawal_fee(crypto, amount)
        fee_satoshi = int(estimated_fee * divisor)
        amount_satoshi = int(amount * divisor)
        
        # 4. Select UTXOs
        selected_utxos, change_amount, selection_error = select_utxos(utxos, amount_satoshi, fee_satoshi)
        if selection_error:
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=selection_error)
            return None, selection_error
        
        # 5. Build transaction with proper inputs/outputs
        inputs = []
        for utxo in selected_utxos:
            inputs.append({
                "prev_hash": utxo['txid'],
                "output_index": utxo['vout']
            })
        
        outputs = [{"addresses": [address], "value": amount_satoshi}]
        
        # Add change output if needed
        if change_amount > 546:  # Dust threshold
            outputs.append({"addresses": [from_address], "value": change_amount})
        
        # Create transaction via BlockCypher
        url = f"{BLOCKCYPHER_API_URL}{network}/txs/new?token={BLOCKCYPHER_API_KEY}"
        payload = {
            "inputs": inputs,
            "outputs": outputs
        }
        
        response = await api_call_with_retry(url, method='POST', json_data=payload)
        if not response:
            error_msg = "Failed to create transaction"
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, error_msg
        
        tx_data = response.json()
        
        if 'tosign' not in tx_data or 'tx' not in tx_data:
            error_msg = f"Invalid transaction response: {tx_data}"
            logger.error(error_msg)
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, "Invalid transaction response from API"
        
        # 6. Sign transaction with real cryptographic signatures
        tx_data['signatures'] = []
        tx_data['pubkeys'] = []
        
        # Get public key for this private key
        public_key = get_public_key_from_private(private_key)
        if not public_key:
            error_msg = "Failed to derive public key"
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, error_msg
        
        for to_sign in tx_data['tosign']:
            # Sign each input with real ECDSA signature
            signature = sign_transaction_input(to_sign, private_key, crypto)
            if not signature:
                error_msg = "Failed to sign transaction"
                log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
                return None, error_msg
            
            tx_data['signatures'].append(signature)
            tx_data['pubkeys'].append(public_key)
        
        # 7. Verify transaction before broadcasting
        is_valid, verify_error = await verify_transaction_before_broadcast(tx_data, crypto)
        if not is_valid:
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=verify_error)
            return None, f"Transaction verification failed: {verify_error}"
        
        # 8. Broadcast transaction
        send_url = f"{BLOCKCYPHER_API_URL}{network}/txs/send?token={BLOCKCYPHER_API_KEY}"
        send_response = await api_call_with_retry(send_url, method='POST', json_data=tx_data)
        
        if not send_response:
            error_msg = "Failed to broadcast transaction"
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, error_msg
        
        result = send_response.json()
        
        if 'hash' not in result:
            error_msg = f"Transaction broadcast failed: {result}"
            logger.error(error_msg)
            log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
            return None, "Transaction failed to broadcast"
        
        txid = result['hash']
        
        # 9. Log successful withdrawal
        log_withdrawal_attempt(user_id, crypto, address, amount, 'success', txid=txid)
        
        logger.info(f"Withdrawal successful: {amount} {crypto} to {address}, TX: {txid}")
        return txid, None
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(f"Withdrawal error for user {user_id}: {error_msg}")
        log_withdrawal_attempt(user_id, crypto, address, amount, 'failed', error=error_msg)
        return None, error_msg

# Load wallets, deposit addresses, and withdrawal log on startup
load_wallets()
load_deposit_addresses()
load_withdrawal_log()

# Background task to check deposits with enhanced error handling and rate limiting
@tasks.loop(minutes=10)
async def check_deposits_background():
    """Enhanced background task for checking deposits with rate limiting and error recovery"""
    try:
        logger.info("Starting deposit check cycle...")
        
        # Only check addresses that have been used recently or have pending deposits
        active_addresses = {}
        current_time = time.time()
        
        # Filter to only check active addresses (optimization)
        for user_id, wallets in deposit_addresses.items():
            for crypto, wallet_info in wallets.items():
                if 'address' in wallet_info:
                    # Always check addresses, but we could add logic here to skip very old unused addresses
                    if user_id not in active_addresses:
                        active_addresses[user_id] = {}
                    active_addresses[user_id][crypto] = wallet_info
        
        logger.info(f"Checking {sum(len(wallets) for wallets in active_addresses.values())} deposit addresses...")
        
        # Check deposits with rate limiting
        await check_deposits_with_rate_limiting(active_addresses)
        
        # Send notifications
        await send_deposit_notifications()
        
        logger.info("Deposit check cycle completed successfully")
        
    except Exception as e:
        logger.error(f"Error in deposit check background task: {str(e)}")
        # Don't crash the task, just log and continue

# Background task to clean up rate limiting data
@tasks.loop(hours=1)
async def cleanup_rate_limiting_data():
    """Clean up old rate limiting data every hour"""
    try:
        rate_limiter.cleanup_old_data()
    except Exception as e:
        logger.error(f"Error cleaning up rate limiting data: {str(e)}")

async def check_deposits_with_rate_limiting(active_addresses):
    """Check deposits with proper API rate limiting"""
    for user_id, wallets in active_addresses.items():
        for crypto, wallet_info in wallets.items():
            try:
                if 'address' not in wallet_info:
                    logger.warning(f"Missing address for user {user_id}, crypto {crypto}")
                    continue
                    
                address = wallet_info['address']
                network = CRYPTOCURRENCIES[crypto]['network']
                url = f"{BLOCKCYPHER_API_URL}{network}/addrs/{address}/balance?token={BLOCKCYPHER_API_KEY}"
                
                # Use rate-limited API call
                response, error = await api_call_with_retry(url, method='GET')
                if error:
                    logger.error(f"API error checking deposits for {crypto} at {address}: {error}")
                    continue
                
                if 'balance' not in response:
                    logger.warning(f"Invalid balance response for {address}: {response}")
                    continue
                
                # Convert balance to decimal
                divisor = CRYPTOCURRENCIES[crypto]['divisor']
                confirmed_balance = Decimal(response['balance']) / Decimal(divisor)
                
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
                        
                        logger.info(f"Deposit detected: {deposit_amount} {crypto} for user {user_id}")
                
                # Small delay between API calls to be respectful
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Unexpected error checking deposits for {crypto} at {address}: {str(e)}")
                continue

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
                txid, error = await send_withdrawal(user_id, self.crypto, tip_address, tip_amount)
                
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
            # Validate user ID format
            user_id, error = validate_user_id(self.opponent_id.value)
            if error:
                await interaction.response.send_message(
                    f"❌ {error}",
                    ephemeral=True
                )
                return
            
            # Fetch user with error handling
            try:
                opponent = await bot.fetch_user(user_id)
            except discord.NotFound:
                await interaction.response.send_message(
                    "❌ User not found. Please enter a valid Discord ID.",
                    ephemeral=True
                )
                return
            except discord.HTTPException as e:
                logger.error(f"Discord API error fetching user {user_id}: {str(e)}")
                await interaction.response.send_message(
                    "❌ Error fetching user. Please try again.",
                    ephemeral=True
                )
                return
            
            # Check if user is in guild
            opponent = interaction.guild.get_member(opponent.id)
            if not opponent:
                await interaction.response.send_message(
                    "❌ User not found in this server. Please enter a valid user ID.",
                    ephemeral=True
                )
                return
            
            # Validate opponent
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
                
            # Check session
            crypto = opponent_requests.get(interaction.user.id)
            if not crypto:
                await interaction.response.send_message(
                    "❌ Session expired. Please restart the battle.",
                    ephemeral=True
                )
                return
            
            # Create ticket with error handling
            try:
                ticket = await create_ticket(interaction.guild, interaction.user, opponent, crypto)
            except discord.Forbidden:
                await interaction.response.send_message(
                    "❌ Bot lacks permissions to create channels.",
                    ephemeral=True
                )
                return
            except Exception as e:
                logger.error(f"Error creating ticket: {str(e)}")
                await interaction.response.send_message(
                    "❌ Failed to create battle ticket. Please try again.",
                    ephemeral=True
                )
                return
            
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
            
            try:
                await ticket.send(embed=embed, view=GameModeView(ticket.id))
                await interaction.response.send_message(
                    f"✅ Ticket created: {ticket.mention}",
                    ephemeral=True
                )
                del opponent_requests[interaction.user.id]
            except discord.Forbidden:
                await interaction.response.send_message(
                    "❌ Bot lacks permissions to send messages in the ticket.",
                    ephemeral=True
                )
            except Exception as e:
                logger.error(f"Error sending ticket message: {str(e)}")
                await interaction.response.send_message(
                    "❌ Ticket created but failed to initialize. Please check the ticket channel.",
                    ephemeral=True
                )
            
        except Exception as e:
            logger.error(f"Unexpected modal error: {str(e)}")
            await interaction.response.send_message(
                "⚠️ An unexpected error occurred. Please try again.",
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
        # Check rate limit for battle creation
        can_proceed, remaining = rate_limiter.check_user_cooldown(interaction.user.id, 'battle_create')
        
        if not can_proceed:
            embed = discord.Embed(
                title="⏰ Battle Creation Cooldown",
                description=f"Please wait {remaining:.1f} seconds before creating another battle.",
                color=discord.Color.orange()
            )
            embed.set_footer(text="This prevents spam and ensures fair gameplay.")
            await interaction.response.send_message(embed=embed, ephemeral=True, delete_after=15)
            return
        
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
    """Create a battle ticket with enhanced error handling"""
    try:
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
            logger.info(f"Created ticket category in {guild.name}")
        
        timestamp = datetime.now().strftime("%m%d%H%M")
        # Sanitize names for channel creation
        safe_name1 = ''.join(c for c in player1.name if c.isalnum() or c in '-_')[:20]
        safe_name2 = ''.join(c for c in player2.name if c.isalnum() or c in '-_')[:20]
        ticket_name = f"battle-{safe_name1}-vs-{safe_name2}-{timestamp}"[:95]
        
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
        
        logger.info(f"Created battle ticket: {ticket.name} for {player1.name} vs {player2.name}")
        return ticket
    except discord.Forbidden as e:
        logger.error(f"Permission error creating ticket: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error creating ticket: {str(e)}")
        raise

@bot.event
async def on_ready():
    logger.info(f'✅ Bot Online: {bot.user.name} (ID: {bot.user.id})')
    logger.info(f'🌐 Connected to {len(bot.guilds)} server(s)')
    
    try:
        await bot.change_presence(activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="Crypto Battles"
        ))
        logger.info("Bot presence updated")
    except Exception as e:
        logger.error(f"Error setting bot presence: {str(e)}")
    
    try:
        check_deposits_background.start()
        cleanup_rate_limiting_data.start()
        logger.info("Background tasks started (deposit checking & rate limit cleanup)")
    except Exception as e:
        logger.error(f"Error starting background tasks: {str(e)}")
    
    # Register persistent views
    try:
        bot.add_view(CryptoSelectView())
        logger.info("Persistent views registered")
    except Exception as e:
        logger.error(f"Error registering views: {str(e)}")
    
    # Create ticket category if missing
    for guild in bot.guilds:
        try:
            category = discord.utils.get(guild.categories, name=TICKET_CATEGORY_NAME)
            if not category:
                overwrites = {
                    guild.default_role: discord.PermissionOverwrite(read_messages=False),
                    guild.me: discord.PermissionOverwrite(
                        read_messages=True,
                        send_messages=True,
                        manage_channels=True
                    )
                }
                await guild.create_category(TICKET_CATEGORY_NAME, overwrites=overwrites)
                logger.info(f"Created ticket category in {guild.name}")
            else:
                logger.info(f"Ticket category exists in {guild.name}")
        except discord.Forbidden:
            logger.error(f"Missing permissions to create category in {guild.name}")
        except Exception as e:
            logger.error(f"Error creating category in {guild.name}: {str(e)}")

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
            
        # Validate amount using our validation function
        amount_dec, error = validate_amount(message.content)
        if error:
            await message.channel.send(f"❌ {error}", delete_after=15)
            return
        
        crypto = bet_data["crypto"]
        min_bet = get_crypto_min_bet(crypto)
        
        if amount_dec < Decimal(str(min_bet)):
            await message.channel.send(
                f"❌ Minimum bet for {crypto} is ${min_bet}. Please enter a higher amount.",
                delete_after=15
            )
            return
        
        # Store amount and request confirmation
        bet_data["amount"] = float(amount_dec)  # Keep as float for compatibility
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
            f"**${amount_dec}** bet set! Both players must type `confirm` to proceed."
        )
    
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
@rate_limit('deposit')
async def deposit(ctx, crypto: str):
    """Get a deposit address for cryptocurrency"""
    crypto = crypto.upper()
    if crypto not in CRYPTOCURRENCIES:
        embed = discord.Embed(
            title="❌ Invalid Cryptocurrency",
            description=get_helpful_error_message('invalid_amount', f"Available: {', '.join(CRYPTOCURRENCIES.keys())}"),
            color=discord.Color.red()
        )
        await ctx.send(embed=embed, delete_after=15)
        return
    
    user_id = str(ctx.author.id)
    wallet = get_user_wallet(user_id)
    
    # Use status indicator for address generation
    async with StatusIndicator(ctx, "⏳ Generating deposit address...") as status:
        # Generate or retrieve deposit address
        address = generate_deposit_address(user_id, crypto)
        if not address:
            await status.error("Failed to generate deposit address. Please try again later.")
            return
        
        await status.update("📋 Preparing deposit information...")
    
    # Get min deposit requirements
    min_deposit = "0.001 BTC" if crypto == "BTC" else "0.1 LTC"
    
    embed = discord.Embed(
        title=f"📥 {crypto} Deposit Address",
        description=f"Send **{crypto}** to the following address:",
        color=discord.Color.green()
    )
    embed.add_field(
        name="🏦 Deposit Address",
        value=f"```{address}```",
        inline=False
    )
    embed.add_field(
        name="📋 Important Information",
        value=(
            f"• Send only **{crypto}** to this address\n"
            f"• Minimum deposit: {min_deposit}\n"
            f"• Deposits typically appear within 10-30 minutes\n"
            f"• You'll receive a DM when your deposit is detected\n"
            f"• Save this address for future deposits"
        ),
        inline=False
    )
    # Add fiat balance
    balance_fiat = wallet['balances'][crypto] * Decimal(FIAT_RATES[crypto])
    embed.add_field(
        name="💰 Current Balance",
        value=f"{wallet['balances'][crypto]} {crypto} (${balance_fiat:.2f})",
        inline=True
    )
    embed.set_footer(text="⚠️ Only send the specified cryptocurrency to this address!")
    
    await ctx.send(embed=embed)

@bot.command()
@rate_limit('balance')
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
                description=f"**{wallet['balances'][crypto]} {crypto}**\n**${balance_fiat:.2f} USD**",
                color=discord.Color.blue()
            )
            embed.add_field(
                name="📊 Quick Actions",
                value=f"• `!deposit {crypto.lower()}` - Add funds\n• `!withdraw {crypto.lower()} <amount> <address>` - Withdraw\n• `!transactions` - View history",
                inline=False
            )
            embed.set_footer(text=f"Rate: 1 {crypto} = ${FIAT_RATES[crypto]:.2f}")
            await ctx.send(embed=embed)
        else:
            embed = discord.Embed(
                title="❌ Invalid Cryptocurrency",
                description=get_helpful_error_message('invalid_amount', f"Available: {', '.join(wallet['balances'].keys())}"),
                color=discord.Color.red()
            )
            await ctx.send(embed=embed, delete_after=15)
    else:
        embed = discord.Embed(
            title="💰 Your Crypto Portfolio",
            color=discord.Color.blue()
        )
        
        total_fiat = Decimal('0')
        has_balances = False
        
        for crypto, balance in wallet['balances'].items():
            balance_fiat = balance * Decimal(FIAT_RATES[crypto])
            total_fiat += balance_fiat
            
            if balance > 0:
                has_balances = True
                embed.add_field(
                    name=f"{CRYPTOCURRENCIES[crypto]['emoji']} {crypto}",
                    value=f"**{balance} {crypto}**\n${balance_fiat:.2f}",
                    inline=True
                )
        
        if has_balances:
            embed.add_field(
                name="💵 Total Portfolio Value",
                value=f"**${total_fiat:.2f} USD**",
                inline=False
            )
            embed.set_footer(text="Use !deposit <crypto> to add funds • !help for more commands")
        else:
            embed.description = "🏦 **No balances found**\n\nGet started by depositing cryptocurrency:\n• `!deposit btc` - Deposit Bitcoin\n• `!deposit ltc` - Deposit Litecoin"
            embed.set_footer(text="Deposits are usually confirmed within 10-30 minutes")
        
        await ctx.send(embed=embed)

@bot.command()
@rate_limit('withdraw')
async def withdraw(ctx, crypto: str, amount: str, address: str):
    """Withdraw cryptocurrency to an external address with enhanced validation"""
    try:
        crypto = crypto.upper()
        if crypto not in CRYPTOCURRENCIES:
            embed = discord.Embed(
                title="❌ Invalid Cryptocurrency",
                description=get_helpful_error_message('invalid_amount', f"Available: {', '.join(CRYPTOCURRENCIES.keys())}"),
                color=discord.Color.red()
            )
            await ctx.send(embed=embed, delete_after=15)
            return
        
        # Validate amount
        amount_dec, error = validate_amount(amount)
        if error:
            embed = discord.Embed(
                title="❌ Invalid Amount",
                description=get_helpful_error_message('invalid_amount', error),
                color=discord.Color.red()
            )
            await ctx.send(embed=embed, delete_after=15)
            return
        
        # Validate address
        if not validate_crypto_address(address, crypto):
            embed = discord.Embed(
                title="❌ Invalid Address",
                description=get_helpful_error_message('invalid_address', f"Please provide a valid {crypto} address"),
                color=discord.Color.red()
            )
            await ctx.send(embed=embed, delete_after=15)
            return
        
        wallet = get_user_wallet(str(ctx.author.id))
        fee = Decimal(str(CRYPTOCURRENCIES[crypto]['withdrawal_fee']))
        total_required = amount_dec + fee
        
        # Check minimum withdrawal amount
        min_withdrawal = Decimal('0.001')  # Minimum withdrawal
        if amount_dec < min_withdrawal:
            embed = discord.Embed(
                title="❌ Amount Too Small",
                description=get_helpful_error_message('invalid_amount', f"Minimum withdrawal: {min_withdrawal} {crypto}"),
                color=discord.Color.red()
            )
            await ctx.send(embed=embed, delete_after=15)
            return
        
        if wallet['balances'][crypto] < total_required:
            embed = discord.Embed(
                title="❌ Insufficient Balance",
                description=get_helpful_error_message('insufficient_balance', 
                    f"Need: {total_required} {crypto} (including {fee} {crypto} fee)\nYour balance: {wallet['balances'][crypto]} {crypto}"),
                color=discord.Color.red()
            )
            await ctx.send(embed=embed, delete_after=20)
            return
        
        # Add confirmation requirement for large withdrawals
        fiat_value = amount_dec * Decimal(FIAT_RATES[crypto])
        if fiat_value > 100:  # Require confirmation for withdrawals > $100
            embed = discord.Embed(
                title="⚠️ Withdrawal Confirmation Required",
                description=f"You are about to withdraw **{amount_dec} {crypto}** (${fiat_value:.2f})",
                color=discord.Color.orange()
            )
            embed.add_field(
                name="📋 Transaction Details",
                value=(
                    f"• **Amount**: {amount_dec} {crypto}\n"
                    f"• **Fee**: {fee} {crypto}\n"
                    f"• **Total Deducted**: {total_required} {crypto}\n"
                    f"• **Destination**: `{address[:20]}...{address[-10:]}`"
                ),
                inline=False
            )
            embed.add_field(
                name="⏰ Confirmation Required",
                value="Type **CONFIRM** within 60 seconds to proceed\nType **CANCEL** to abort this withdrawal",
                inline=False
            )
            embed.set_footer(text="⚠️ This action cannot be undone!")
            
            await ctx.send(embed=embed)
            
            def check(m):
                return (m.author == ctx.author and 
                       m.channel == ctx.channel and 
                       m.content.upper() in ['CONFIRM', 'CANCEL'])
            
            try:
                response = await bot.wait_for('message', check=check, timeout=60.0)
                if response.content.upper() == 'CANCEL':
                    embed = discord.Embed(
                        title="❌ Withdrawal Cancelled",
                        description="Your withdrawal has been cancelled. Your funds remain in your wallet.",
                        color=discord.Color.red()
                    )
                    await ctx.send(embed=embed, delete_after=10)
                    return
            except asyncio.TimeoutError:
                embed = discord.Embed(
                    title="⏰ Withdrawal Timed Out",
                    description="Confirmation not received within 60 seconds. Please try again.",
                    color=discord.Color.orange()
                )
                await ctx.send(embed=embed, delete_after=10)
                return
        
        # Use status indicator for withdrawal process
        async with StatusIndicator(ctx, "🔍 Validating withdrawal request...") as status:
            await status.update("💰 Checking balances and limits...")
            await asyncio.sleep(0.5)  # Brief pause for UX
            
            await status.update("📤 Broadcasting transaction to blockchain...")
            
            # Send real withdrawal
            txid, error = await send_withdrawal(str(ctx.author.id), crypto, address, amount_dec)
            if error:
                await status.error(f"Withdrawal failed: {error}")
                return
            
            await status.update("✅ Transaction confirmed, updating balance...")
            
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
        
        # Success message
        embed = discord.Embed(
            title="✅ Withdrawal Successful",
            description=f"Your **{amount_dec} {crypto}** withdrawal has been processed!",
            color=discord.Color.green()
        )
        embed.add_field(
            name="📋 Transaction Details",
            value=(
                f"• **Amount Sent**: {amount_dec} {crypto}\n"
                f"• **Network Fee**: {fee} {crypto}\n"
                f"• **Total Deducted**: {total_required} {crypto}\n"
                f"• **Remaining Balance**: {wallet['balances'][crypto]} {crypto}"
            ),
            inline=False
        )
        embed.add_field(
            name="🔗 Blockchain Information",
            value=(
                f"• **Destination**: `{address}`\n"
                f"• **Transaction ID**: `{txid}`\n"
                f"• **Status**: Broadcasted to network"
            ),
            inline=False
        )
        embed.set_footer(text="🔍 You can track this transaction using the Transaction ID on a blockchain explorer")
        
        await ctx.send(embed=embed)
        
    except Exception as e:
        logger.error(f"Error in withdraw command: {str(e)}")
        embed = discord.Embed(
            title="❌ Withdrawal Error",
            description=get_helpful_error_message('api_error', "Please try again in a few moments"),
            color=discord.Color.red()
        )
        await ctx.send(embed=embed, delete_after=15)

@bot.command()
@rate_limit('transactions')
async def transactions(ctx, count: int = 5):
    """View your recent transactions"""
    # Validate count parameter
    if count < 1 or count > 20:
        embed = discord.Embed(
            title="❌ Invalid Count",
            description=get_helpful_error_message('invalid_amount', "Count must be between 1 and 20"),
            color=discord.Color.red()
        )
        await ctx.send(embed=embed, delete_after=15)
        return
    
    wallet = get_user_wallet(str(ctx.author.id))
    transactions = wallet.get('transactions', [])[:count]
    
    if not transactions:
        embed = discord.Embed(
            title="📊 Transaction History",
            description="🏦 **No transactions found**\n\nYour transaction history will appear here after:\n• Making deposits\n• Processing withdrawals\n• Participating in battles",
            color=discord.Color.blue()
        )
        embed.set_footer(text="Use !deposit <crypto> to get started")
        await ctx.send(embed=embed)
        return
    
    embed = discord.Embed(
        title=f"📊 Recent Transactions ({len(transactions)} of {len(wallet.get('transactions', []))})",
        description=f"Showing your last {len(transactions)} transactions",
        color=discord.Color.blue()
    )
    
    # Group transactions by type for better organization
    transaction_emojis = {
        'deposit': '📥',
        'withdrawal': '📤',
        'bet_hold': '🎲',
        'battle_win': '🏆',
        'battle_loss': '💸',
        'tip': '💝',
        'tip_sent': '🎁'
    }
    
    for i, tx in enumerate(transactions, 1):
        # Calculate fiat value if possible
        fiat_value = ""
        if tx['crypto'] in FIAT_RATES:
            amount_decimal = abs(Decimal(tx['amount']))
            fiat_amount = amount_decimal * Decimal(FIAT_RATES[tx['crypto']])
            fiat_value = f" (${fiat_amount:.2f})"
        
        # Get emoji for transaction type
        tx_emoji = transaction_emojis.get(tx['type'], '💰')
        
        # Format transaction type
        tx_type = tx['type'].replace('_', ' ').title()
        
        # Format amount with proper sign
        amount = Decimal(tx['amount'])
        amount_str = f"+{amount}" if amount > 0 else str(amount)
        
        # Format date
        try:
            date_obj = datetime.fromisoformat(tx['timestamp'])
            formatted_date = date_obj.strftime("%m/%d/%Y %H:%M")
        except:
            formatted_date = tx['timestamp'][:16].replace('T', ' ')
        
        value = (
            f"{tx_emoji} **{tx_type}**\n"
            f"💰 **Amount**: {amount_str} {tx['crypto']}{fiat_value}\n"
            f"📅 **Date**: {formatted_date}"
        )
        
        if tx.get('battle_id'):
            value += f"\n🎲 **Battle**: {tx['battle_id']}"
        
        if tx.get('notes'):
            # Truncate long notes
            notes = tx['notes']
            if len(notes) > 50:
                notes = notes[:47] + "..."
            value += f"\n📝 **Notes**: {notes}"
        
        embed.add_field(
            name=f"#{i} • TX {tx['id']}",
            value=value,
            inline=True if i % 2 == 1 else False
        )
    
    # Add summary footer
    total_transactions = len(wallet.get('transactions', []))
    embed.set_footer(text=f"💡 Total transactions: {total_transactions} • Use !transactions <count> to see more")
    
    await ctx.send(embed=embed)

@bot.command()
async def roll(ctx):
    if ctx.channel.id in dice_games and ctx.author.id == dice_games[ctx.channel.id]["current_player"]:
        await process_dice_roll(ctx.channel, dice_games[ctx.channel.id])

@bot.command()
async def status(ctx):
    """Show bot status and rate limiting information"""
    if not ctx.author.guild_permissions.administrator:
        embed = discord.Embed(
            title="🔒 Administrator Only",
            description="This command is only available to administrators.",
            color=discord.Color.red()
        )
        await ctx.send(embed=embed, delete_after=10)
        return
    
    # Get rate limiting stats
    current_time = time.time()
    api_usage_remaining = API_RATE_LIMIT['requests_per_minute'] - rate_limiter.api_usage_count
    api_reset_in = rate_limiter.api_usage_reset_time - current_time
    
    # Count active users with cooldowns
    active_cooldowns = sum(1 for user_cooldowns in rate_limiter.user_cooldowns.values() if user_cooldowns)
    
    # Get backoff status
    backoff_status = "None"
    if current_time < rate_limiter.api_backoff_until:
        backoff_remaining = rate_limiter.api_backoff_until - current_time
        backoff_status = f"{backoff_remaining:.1f}s remaining"
    
    embed = discord.Embed(
        title="🤖 Bot Status & Rate Limiting",
        description="Current bot performance and rate limiting statistics",
        color=discord.Color.blue()
    )
    
    embed.add_field(
        name="📊 API Rate Limiting",
        value=(
            f"• **Usage**: {rate_limiter.api_usage_count}/{API_RATE_LIMIT['requests_per_minute']} per minute\n"
            f"• **Remaining**: {api_usage_remaining} requests\n"
            f"• **Reset in**: {api_reset_in:.1f} seconds\n"
            f"• **Backoff**: {backoff_status}"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⏰ User Cooldowns",
        value=(
            f"• **Active users**: {active_cooldowns}\n"
            f"• **Total cooldown entries**: {sum(len(cooldowns) for cooldowns in rate_limiter.user_cooldowns.values())}"
        ),
        inline=False
    )
    
    embed.add_field(
        name="🏦 System Status",
        value=(
            f"• **Deposit addresses**: {sum(len(wallets) for wallets in deposit_addresses.values())}\n"
            f"• **User wallets**: {len(user_wallets)}\n"
            f"• **Pending notifications**: {sum(1 for info in deposit_notifications.values() if not info['notified'])}"
        ),
        inline=False
    )
    
    embed.add_field(
        name="⚙️ Configuration",
        value=(
            f"• **Deposit check interval**: 10 minutes\n"
            f"• **API burst limit**: {API_RATE_LIMIT['burst_limit']} requests\n"
            f"• **Max backoff**: {API_RATE_LIMIT['max_backoff']} seconds"
        ),
        inline=False
    )
    
    embed.set_footer(text=f"Bot uptime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    await ctx.send(embed=embed)

@bot.command()
async def help(ctx):
    embed = discord.Embed(
        title="🎮 Crypto Battle Bot Help",
        description="Start PvP crypto battles with friends! All commands have built-in rate limiting for security.",
        color=discord.Color.blue()
    )
    embed.add_field(
        name="🚀 Getting Started",
        value="1. Admin runs `!setup` in the betting channel\n"
              "2. Click a crypto button to start a battle\n"
              "3. Enter your opponent's ID\n"
              "4. Complete the battle in the private ticket",
        inline=False
    )
    embed.add_field(
        name="💰 Wallet Commands",
        value="• `!deposit <crypto>` - Get deposit address (30s cooldown)\n"
              "• `!balance [crypto]` - Check your balance (10s cooldown)\n"
              "• `!withdraw <crypto> <amount> <address>` - Withdraw funds (60s cooldown)\n"
              "• `!transactions [count]` - View transaction history (15s cooldown)",
        inline=False
    )
    embed.add_field(
        name="🎲 Game Commands",
        value="• `!roll` - Roll dice during a dice game\n"
              "• Battle creation has a 45s cooldown per user",
        inline=False
    )
    embed.add_field(
        name="🔧 Admin Commands",
        value="• `!setup` - Setup betting panel\n"
              "• `!status` - View bot status and rate limiting info",
        inline=False
    )
    embed.add_field(
        name="⚡ Rate Limiting Info",
        value="• Commands have cooldowns to prevent spam\n"
              "• API calls are automatically rate limited\n"
              "• Status messages show progress during operations\n"
              "• Enhanced error messages provide helpful suggestions",
        inline=False
    )
    embed.set_footer(text="💡 All operations include status indicators and helpful error messages!")
    await ctx.send(embed=embed)

@bot.event
async def on_command_error(ctx, error):
    """Enhanced error handling for commands with helpful messages"""
    if isinstance(error, commands.CommandNotFound):
        return
    
    logger.error(f"Command error in {ctx.command}: {type(error).__name__} - {str(error)}")
    
    try:
        embed = None
        
        if isinstance(error, commands.MissingPermissions):
            embed = discord.Embed(
                title="🔒 Permission Denied",
                description=get_helpful_error_message('permission_error'),
                color=discord.Color.red()
            )
        elif isinstance(error, commands.BadArgument):
            embed = discord.Embed(
                title="❌ Invalid Argument",
                description=get_helpful_error_message('invalid_amount', "Please check your input format and try again."),
                color=discord.Color.red()
            )
        elif isinstance(error, commands.MissingRequiredArgument):
            embed = discord.Embed(
                title="❌ Missing Argument",
                description=f"**Missing required argument**: `{error.param.name}`\n\n• Use `!help` to see command usage\n• Check the command syntax\n• Make sure all required parameters are provided",
                color=discord.Color.red()
            )
        elif isinstance(error, commands.CommandOnCooldown):
            embed = discord.Embed(
                title="⏰ Command Cooldown",
                description=get_helpful_error_message('rate_limit_exceeded', f"Try again in {error.retry_after:.1f} seconds"),
                color=discord.Color.orange()
            )
        elif isinstance(error, discord.Forbidden):
            embed = discord.Embed(
                title="🔒 Permission Error",
                description=get_helpful_error_message('permission_error'),
                color=discord.Color.red()
            )
        elif isinstance(error, discord.HTTPException):
            embed = discord.Embed(
                title="🌐 Discord API Error",
                description=get_helpful_error_message('api_error'),
                color=discord.Color.red()
            )
        elif isinstance(error, ValueError):
            embed = discord.Embed(
                title="❌ Invalid Value",
                description=get_helpful_error_message('invalid_amount', str(error)),
                color=discord.Color.red()
            )
        else:
            embed = discord.Embed(
                title="⚠️ Unexpected Error",
                description=get_helpful_error_message('api_error', "An unexpected error occurred"),
                color=discord.Color.red()
            )
        
        if embed:
            embed.set_footer(text="💡 Use !help for command information")
            await ctx.send(embed=embed, delete_after=15)
            
    except Exception as e:
        logger.error(f"Error sending error message: {str(e)}")
        # Fallback to simple message if embed fails
        try:
            await ctx.send("❌ An error occurred. Please try again.", delete_after=10)
        except:
            pass  # If we can't even send a simple message, give up

# ===== BOT STARTUP =====
if __name__ == "__main__":
    logger.info("Starting Crypto Battle Bot...")
    logger.info("=" * 50)
    
    # Validate critical environment variables
    if not BOT_TOKEN or BOT_TOKEN == 'MTM5NTQ2OTg4NjA5MTY5MDAxNA.GCJaGW.3QdfzaztRPDyDLJTTG0tFzpXShzFBOOUYumJTk':
        logger.warning("Using default/placeholder bot token. Set BOT_TOKEN environment variable.")
    
    if not BLOCKCYPHER_API_KEY or BLOCKCYPHER_API_KEY == 'c703adf08f1a4766bbaa3284da97a7aa':
        logger.warning("Using default/placeholder BlockCypher API key. Set BLOCKCYPHER_API_KEY environment variable.")
    
    try:
        bot.run(BOT_TOKEN)
    except discord.LoginFailure:
        logger.error("❌ INVALID TOKEN: Failed to login to Discord")
    except KeyboardInterrupt:
        logger.info("Bot shutdown requested by user")
    except Exception as e:
        logger.error(f"❌ UNEXPECTED ERROR: {str(e)}")
        traceback.print_exc()
