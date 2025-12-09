import sqlite3
from contextlib import contextmanager

DATABASE_NAME = "expense_tracker.db"


def init_db():
    """ Initialised database with tables"""
    conn = sqlite3.connect(DATABASE_NAME)
    sql_execution_cursor = conn.cursor()

    sql_execution_cursor.execute('''
                 
            CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            home_currency TEXT DEFAULT 'USD',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )                                        
                                 ''')
    
    sql_execution_cursor.execute('''


           CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            description TEXT,
            category TEXT NOT NULL,
            date DATE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
                                     
                                ''')
    

    sql_execution_cursor.execute('''

            CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            expires_at DATETIME NOT NULL,
            revoked INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )

                                ''')
    

    conn.commit()
    conn.close()
    print("✅ Database initialized successfully")


@contextmanager
def get_db():
    """
    Context manager for database connections.
    Automatically closes connection when done.
    
    Usage:
        with get_db() as conn:
            sql_execution_cursor = conn.cursor()
            sql_execution_cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
    """
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row  # Access columns by name: row['username']
    try:
        yield conn
    finally:
        conn.close()