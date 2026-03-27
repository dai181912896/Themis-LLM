
import os
from pymochow.auth.bce_credentials import BceCredentials

# Example configuration file for database and API credentials
# IMPORTANT: Copy this file to config.py and replace with your actual credentials before use

account = 'YOUR_ACCOUNT'  # Account information
api_key = 'YOUR_API_KEY'  # Secret key information
endpoint = 'http://YOUR_ENDPOINT:PORT' # Example endpoint
credentials = BceCredentials(account, api_key)

os.environ["QIANFAN_ACCESS_KEY"] = "YOUR_QIANFAN_ACCESS_KEY"
os.environ["QIANFAN_SECRET_KEY"] = "YOUR_QIANFAN_SECRET_KEY"
