import sqlite3

#hashes lists
def save_hashset_to_db(hashset, db_filename):
    conn = sqlite3.connect(db_filename)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS words (word TEXT PRIMARY KEY)')
    c.execute('DELETE FROM words')  # Clear existing data
    c.executemany('INSERT INTO words (word) VALUES (?)', [(word,) for word in hashset])
    conn.commit()
    conn.close()

def load_hashset_from_db(db_filename):
    conn = sqlite3.connect(db_filename)
    c = conn.cursor()
    c.execute('SELECT word FROM words')
    hashset = {row[0] for row in c.fetchall()}
    conn.close()
    return hashset

def is_viruses(db_name, file_path):
    conn = sqlite3.connect(f'{db_name}.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM words WHERE word = ?", (file_path,))
    count = c.fetchone()[0]
    conn.close()
    return count > 0


#Cache 
def create_database():
    conn = sqlite3.connect('models/scanned_files.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS files (file_hash TEXT PRIMARY KEY, file_path TEXT, status INTEGER)''')
    conn.commit()
    conn.close()

# Function to add a scanned file to the database
def add_scanned_file(file_path, file_hash, status):
    conn = sqlite3.connect('models/scanned_files.db')
    c = conn.cursor()
    c.execute("INSERT INTO files (file_hash, file_path, status) VALUES (?, ?, ?)", (file_hash, file_path, status))
    conn.commit()
    conn.close()

def is_file_scanned(file_hash):
    conn = sqlite3.connect('models/scanned_files.db')
    c = conn.cursor()
    c.execute("SELECT status FROM files WHERE file_hash = ?", (file_hash,))
    status = c.fetchone()
    scanned = status is not None  
    conn.close()
    return status, scanned

def delete_file(file_hash):
    conn = sqlite3.connect('models/scanned_files.db')
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE file_hash = ?", (file_hash,))
    conn.commit()
    conn.close()