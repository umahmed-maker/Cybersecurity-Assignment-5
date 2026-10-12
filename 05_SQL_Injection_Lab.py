"""SQL injection demonstration using only a disposable, in-memory SQLite database."""
import sqlite3
con=sqlite3.connect(':memory:')
con.execute('CREATE TABLE users (username TEXT, password TEXT)')
con.executemany('INSERT INTO users VALUES (?,?)',[('alice','secret123'),('bob','example456')])

def vulnerable_login(username,password):
    # BAD: never interpolate untrusted input into a SQL query.
    sql=f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
    return con.execute(sql).fetchall()

def secure_login(username,password):
    # Parameterized query: inputs remain values, not SQL instructions.
    if not isinstance(username,str) or not isinstance(password,str) or not (1<=len(username)<=64 and 1<=len(password)<=128):
        return []
    return con.execute('SELECT username FROM users WHERE username = ? AND password = ?', (username,password)).fetchall()

payload="' OR '1'='1"  # Local lab demonstration only
print('Normal login vulnerable:',vulnerable_login('alice','secret123'))
print('Normal login secure:',secure_login('alice','secret123'))
print('Wrong password vulnerable:',vulnerable_login('alice','wrong'))
print('Injection vulnerable:',vulnerable_login(payload,payload))
print('Injection secure:',secure_login(payload,payload))
print('Note: production systems must use salted password hashing, not plaintext passwords.')
con.close()
