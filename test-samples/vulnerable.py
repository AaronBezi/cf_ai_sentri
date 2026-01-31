import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Vulnerable: SQL injection risk
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    return cursor.fetchone()

def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    # Also vulnerable
    cursor.execute(query)

def search_products(search_term):
    # Another SQL injection vulnerability
    sql = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(sql)
    return cursor.fetchall()

def delete_user(user_id):
    # Vulnerable to SQL injection
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()
