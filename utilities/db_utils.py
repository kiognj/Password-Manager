import sqlite3

DB_FILE = "files/password_manager.db"

def init_db():
    """Initialize the database with the 'user' and 'credentials' tables"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                hashed_master_password TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                service_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                salt BLOB NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

def add_credential(service_name, username, encrypted_password, salt, user_id):
    """Add a new credential to the database"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO credentials (service_name, username, encrypted_password, salt, user_id)
            VALUES (?, ?, ?, ?, ?)
        """, (service_name, username, encrypted_password, salt, user_id))
        conn.commit()

def fetch_credential(service_name, user_id):
    """Retrieve a credential by service name and user id"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, encrypted_password, salt FROM credentials
            WHERE service_name = ? AND user_id = ?
        """, (service_name, user_id))
        return cursor.fetchone()
    
def delete_credential(service_name, user_id):
    """Delete a credential by service name and user id"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM credentials
            WHERE service_name = ? AND user_id = ?
        """, (service_name, user_id))
        conn.commit()
        if cursor.rowcount > 0:
            return True
        return False

def add_user(username, master_password):
    """Add a new user with a hashed master password"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, hashed_master_password)
            VALUES (?, ?)
        """, (username, master_password))
        conn.commit()

def check_user_exists(username):
    """Check if user exists in the database"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
        return cursor.fetchone() is not None

def get_user_password_hash(username):
    """Get the hashed master password of a user"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_master_password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result[0] if result else None

def get_user_id(username):
    """Get the user ID"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result[0] if result else None

def fetch_all_services(user_id):
    """List of all the added services for a particular user"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT service_name FROM credentials WHERE user_id = ?", (user_id,))
        services = cursor.fetchall()
        return [service[0] for service in services]

def check_service_exists(service_name, user_id):
    """Check if a user already have the service in the database"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT 1 FROM credentials WHERE service_name = ? AND user_id = ?", (service_name, user_id))
        return cursor.fetchone() is not None

def update_service_username(service_name, user_id, new_username):
    """Update the service username for a given service name and user ID"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE credentials
            SET username = ?
            WHERE service_name = ? AND user_id = ?
        """, (new_username, service_name, user_id))
        conn.commit()
        return cursor.rowcount > 0

def update_service_password(service_name, user_id, new_password, salt):
    """Update the service password for a given service name and user ID"""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE credentials
            SET encrypted_password = ?, salt = ?
            WHERE service_name = ? AND user_id = ?
        """, (new_password, salt, service_name, user_id))
        conn.commit()
        return cursor.rowcount > 0