
import sqlite3
from flask import request

def vulnerable_sql_injection(user_id):
    """CWE-89: SQL Injection - FIXED with parameterized queries"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # FIX: Use parameterized queries to prevent SQL injection
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    query2 = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query2, (user_id,))  # If user_id is actually a name, otherwise adjust parameter

    username = request.args.get('username')
    query3 = "SELECT * FROM accounts WHERE username = ?"
    cursor.execute(query3, (username,))

    return cursor.fetchall()

# FIX EXPLANATION: All SQL queries now use parameterized statements (the '?' placeholder with a tuple of parameters), which ensures user input is treated as data, not executable SQL code. This completely mitigates SQL injection vulnerabilities in this context.

def vulnerable_sql_injection_order_by(sort_column):
    """CWE-89: SQL Injection in ORDER BY"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Unvalidated column name in ORDER BY
    query = f"SELECT * FROM products ORDER BY {sort_column}"
    cursor.execute(query)
    
    return cursor.fetchall()

# ============================================================================
# 2. COMMAND INJECTION VULNERABILITIES
# ============================================================================

def vulnerable_command_injection(filename):
    """CWE-78: OS Command Injection"""
    # VULNERABLE: Direct command execution
    os.system(f"cat {filename}")
    
    # VULNERABLE: Shell=True with user input
    subprocess.call(f"echo {filename}", shell=True)
    
    # VULNERABLE: Using os.popen
    result = os.popen(f"ls -la {filename}").read()
    
    # VULNERABLE: subprocess.run with shell=True
    subprocess.run(["sh", "-c", f"grep pattern {filename}"])
    
    return result

def vulnerable_eval_injection(user_input):
    """CWE-95: Eval Injection"""
    # VULNERABLE: Direct eval of user input
    result = eval(user_input)
    
    # VULNERABLE: exec with user input
    exec(f"value = {user_input}")
    
    return result