# Safe Credentials Examples in Python
# This file shows proper handling of credentials using environment variables

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# 1. API key from environment - SAFE
API_KEY = os.getenv('API_KEY')

# 2. Password from environment - SAFE
DB_PASSWORD = os.environ.get('DB_PASSWORD')

# 3. AWS credentials from environment - SAFE
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')

# 4. JWT secret from environment - SAFE
JWT_SECRET = os.getenv('JWT_SECRET')

# 5. Database URL from environment - SAFE
DATABASE_URL = os.environ.get('DATABASE_URL')

# 6. Using config file (not hardcoded) - SAFE
def get_config():
    import json
    with open('config.json') as f:
        return json.load(f)

# 7. Using secrets manager - SAFE
def get_secret_from_vault(secret_name):
    # This would call AWS Secrets Manager, HashiCorp Vault, etc.
    pass

# 8. Placeholder values (not real credentials) - SAFE
EXAMPLE_KEY = None
TEMPLATE_SECRET = ""  # To be filled at runtime

# 9. Config with environment variable references - SAFE
config = {
    "api_key": os.getenv('STRIPE_API_KEY'),
    "database": {
        "password": os.environ.get('DB_PASSWORD'),
    },
    "jwt_secret": os.getenv('JWT_SECRET'),
}

# 10. Function that retrieves credentials securely - SAFE
def connect_to_database():
    password = os.getenv('DB_PASSWORD')
    if not password:
        raise ValueError("DB_PASSWORD environment variable not set")
    return f"postgresql://user:{password}@localhost/db"
