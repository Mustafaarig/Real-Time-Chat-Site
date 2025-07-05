import sqlite3

def create_tables():
    conn = sqlite3.connect("messages.db")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room TEXT NOT NULL,
        sender TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()

# Bu dosya doğrudan çalıştırıldığında tablo oluşturulsun
if __name__ == "__main__":
    create_tables()
