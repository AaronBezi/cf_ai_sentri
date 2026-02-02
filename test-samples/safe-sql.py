import sqlite3

def get_user_by_id_safe(user_id):
    """Safe: Using parameterized query"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def authenticate_user_safe(username, password):
    """Safe: Using named parameters"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = :username AND password = :password"
    cursor.execute(query, {"username": username, "password": password})
    return cursor.fetchone()

def search_products_safe(search_term):
    """Safe: Using parameterized query with LIKE"""
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE ?"
    cursor.execute(query, (f"%{search_term}%",))
    return cursor.fetchall()
