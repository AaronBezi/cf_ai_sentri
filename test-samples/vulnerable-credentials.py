# Vulnerable Credentials Examples in Python
# This file contains hardcoded credentials for testing detection

import requests

# 1. Hardcoded API key - VULNERABLE
API_KEY = "sk_live_51HG7d8sK3jF9xM2nP4qR5tU6vW7yZ8aB9cD0eF1gH2iJ3kL4"

# 2. Hardcoded password - VULNERABLE
DB_PASSWORD = "SuperSecretPassword123!"

# 3. AWS credentials - VULNERABLE
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# 4. JWT secret - VULNERABLE
JWT_SECRET = "my-super-secret-jwt-signing-key-do-not-share"

# 5. Database connection string with credentials - VULNERABLE
DATABASE_URL = "postgresql://admin:password123@localhost:5432/production_db"

# 6. OAuth client secret - VULNERABLE
OAUTH_CLIENT_SECRET = "client_secret_abc123def456ghi789jkl012mno345"

# Function using hardcoded credentials
def connect_to_api():
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    return requests.get("https://api.example.com/data", headers=headers)

def get_database_connection():
    # Using hardcoded password directly
    return f"mysql://root:{DB_PASSWORD}@localhost/mydb"

# Config dict with embedded secrets - VULNERABLE
config = {
    "stripe_key": "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    "sendgrid_api_key": "SG.xxxxxxxxxxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2Z3qX...\n-----END RSA PRIVATE KEY-----"
}
