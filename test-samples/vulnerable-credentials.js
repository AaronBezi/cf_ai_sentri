// Vulnerable Credentials Examples in JavaScript
// This file contains hardcoded credentials for testing detection

// 1. Hardcoded API key - VULNERABLE
const API_KEY = "sk_live_51HG7d8sK3jF9xM2nP4qR5tU6vW7yZ8aB9cD0eF1gH2iJ3kL4";

// 2. Hardcoded password - VULNERABLE
const DB_PASSWORD = "SuperSecretPassword123!";

// 3. AWS credentials - VULNERABLE
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// 4. JWT secret - VULNERABLE
const JWT_SECRET = "my-super-secret-jwt-signing-key-do-not-share";

// 5. GitHub personal access token - VULNERABLE
const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// 6. Config object with embedded secrets - VULNERABLE
const config = {
  database: {
    host: "localhost",
    port: 5432,
    username: "admin",
    password: "admin123secure", // Hardcoded password
  },
  stripe: {
    secretKey: "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
    publishableKey: "pk_test_TYooMQauvdEDq54NiTphI7jx",
  },
  oauth: {
    clientSecret: "oauth_secret_xxxxxxxxxxxxxxxxxxx",
  },
};

// 7. Connection string with credentials - VULNERABLE
const connectionString = "mongodb://dbuser:dbpass123@localhost:27017/myapp";

// Function using hardcoded credentials
async function fetchData() {
  const response = await fetch("https://api.example.com/data", {
    headers: {
      Authorization: `Bearer ${API_KEY}`,
    },
  });
  return response.json();
}

// Private key embedded in code - VULNERABLE
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2Z3qX2BTLS4e...
-----END RSA PRIVATE KEY-----`;

// Encryption key - VULNERABLE
const ENCRYPTION_KEY = "aes-256-encryption-key-1234567890abcdef";
