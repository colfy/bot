# 🚀 Discord Crypto Bot - Deployment Guide

## 📋 **Prerequisites**

1. **Python 3.8+** installed on your system
2. **Discord Bot Token** from Discord Developer Portal
3. **BlockCypher API Key** from BlockCypher.com
4. **Server with appropriate permissions** for the bot

## 🔧 **Installation Steps**

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure Environment Variables
```bash
# Copy the example environment file
cp .env.example .env

# Edit the .env file with your actual values
nano .env
```

**Required Environment Variables:**
```env
BOT_TOKEN=your_discord_bot_token_here
BET_CHANNEL_ID=1234567890123456789
BLOCKCYPHER_API_KEY=your_blockcypher_api_key_here
TIP_ADDRESS_LTC=your_litecoin_tip_address_here
TIP_ADDRESS_BTC=your_bitcoin_tip_address_here
```

### 3. Set Up Discord Bot Permissions
Your bot needs these permissions:
- ✅ Read Messages
- ✅ Send Messages
- ✅ Manage Channels
- ✅ Manage Roles
- ✅ Embed Links
- ✅ Read Message History

### 4. Run the Bot
```bash
python crypto_bot.py
```

## ⚙️ **Configuration Options**

### **Cryptocurrency Settings** (in crypto_bot.py)
- Minimum bet amounts per cryptocurrency
- Withdrawal fees
- Fiat conversion rates (update periodically)

### **Rate Limiting** (configurable in code)
- Command cooldowns per user
- API rate limits
- Withdrawal limits

### **Security Settings**
- Daily withdrawal limits
- Single transaction limits
- Confirmation thresholds

## 🎮 **Bot Commands**

### **Admin Commands**
- `!setup` - Set up the betting panel (admin only)
- `!status` - Check bot status and rate limiting stats (admin only)

### **User Commands**
- `!deposit <crypto>` - Get deposit address
- `!balance [crypto]` - Check balance
- `!withdraw <crypto> <amount> <address>` - Withdraw funds
- `!transactions [count]` - View transaction history
- `!help` - Show help information

### **Battle System**
1. Admin runs `!setup` in the designated betting channel
2. Users click cryptocurrency buttons to start battles
3. Enter opponent's Discord ID
4. Follow instructions in the private ticket channel

## 🔒 **Security Best Practices**

1. **Never commit .env file** to version control
2. **Use strong API keys** and rotate them regularly
3. **Monitor withdrawal logs** for suspicious activity
4. **Set appropriate withdrawal limits** for your use case
5. **Keep the bot updated** with latest security patches

## 📊 **Monitoring**

### **Log Files**
- Bot creates detailed logs for all operations
- Monitor for errors and unusual activity
- Withdrawal attempts are logged with full audit trail

### **Rate Limiting Stats**
- Use `!status` command to check current rate limiting status
- Monitor API usage to stay within BlockCypher limits
- Background tasks automatically manage rate limiting

## 🚨 **Troubleshooting**

### **Common Issues**

1. **Bot won't start**
   - Check environment variables are set correctly
   - Verify Discord bot token is valid
   - Ensure all dependencies are installed

2. **Commands not working**
   - Check bot permissions in Discord
   - Verify the bot is in the correct channel
   - Check rate limiting status

3. **Withdrawals failing**
   - Verify BlockCypher API key is valid
   - Check withdrawal limits haven't been exceeded
   - Ensure sufficient balance for fees

4. **Deposits not detected**
   - Wait 10-30 minutes for blockchain confirmation
   - Check if deposit address was generated correctly
   - Verify minimum deposit amounts are met

### **Getting Help**
- Check the logs for detailed error messages
- Use `!status` command to check system health
- Verify all environment variables are configured
- Ensure bot has proper Discord permissions

## 🎯 **Production Deployment**

### **Recommended Setup**
1. **Use a VPS or cloud server** for 24/7 uptime
2. **Set up process monitoring** (PM2, systemd, etc.)
3. **Configure log rotation** to manage disk space
4. **Set up automated backups** of wallet and deposit data
5. **Monitor API usage** to avoid rate limits

### **Example PM2 Configuration**
```bash
# Install PM2
npm install -g pm2

# Start the bot with PM2
pm2 start crypto_bot.py --name "crypto-bot" --interpreter python3

# Save PM2 configuration
pm2 save

# Set up PM2 to start on boot
pm2 startup
```

## ✅ **Verification Checklist**

Before going live, verify:
- [ ] All environment variables configured
- [ ] Bot has proper Discord permissions
- [ ] Test deposits work correctly
- [ ] Test withdrawals work with small amounts
- [ ] Rate limiting is functioning
- [ ] Error handling works as expected
- [ ] Backup systems are in place

**Your Discord Crypto Bot is now ready for production use!** 🎉