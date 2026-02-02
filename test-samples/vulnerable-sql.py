import sqlite3

def get_user_by_id(user_id):
    """Vulnerable: Direct string concatenation in SQL query"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def authenticate_user(username, password):
    """Vulnerable: F-string formatting in SQL query"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(search_term):
    """Vulnerable: Percent operator in SQL query"""
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(query)
    return cursor.fetchall()

def get_order_details(order_id):
    """Vulnerable: String format method"""
    conn = sqlite3.connect('orders.db')
    cursor = conn.cursor()
    query = "SELECT * FROM orders WHERE order_id = {}".format(order_id)
    cursor.execute(query)
    return cursor.fetchone()
