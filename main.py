
def vulnerable_sql_injection(user_id):
    """CWE-89: SQL Injection"""
    import sqlite3
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()

        # Ensure numeric id is used safely
        try:
            user_id_int = int(user_id)  # PRECOGS_FIX: cast to int to prevent injection via non-numeric input
        except (TypeError, ValueError):
            user_id_int = None

        if user_id_int is not None:
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id_int,))  # PRECOGS_FIX: use parameterized query
        else:
            # If id is invalid, avoid executing unsafe query
            return []

        # Use parameterized query for name lookup (original used user_id variable as name)
        cursor.execute("SELECT * FROM users WHERE name = ?", (str(user_id),))  # PRECOGS_FIX: parameterized query

        # Safely obtain username from request and parameterize the query
        try:
            from flask import request
            username = request.args.get('username')
        except Exception:
            username = None

        if username:
            cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))  # PRECOGS_FIX: parameterized query for username

        result = cursor.fetchall()
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return result

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
    import subprocess
    import re
    import os

    # Validate filename strictly: allow only basename characters (alphanumeric, underscore, dash, dot)
    if not isinstance(filename, str) or not re.match(r'^[\w\-.]+$', filename):
        raise ValueError("Invalid filename")  # PRECOGS_FIX: validate input to eliminate shell metacharacters/path traversal

    result = ''
    try:
        # Use subprocess with argument list (no shell) to avoid shell interpretation
        # PRECOGS_FIX: avoid shell=True and pass args as a list
        proc_cat = subprocess.run(['cat', filename], check=False, capture_output=True, text=True)
        # echo safely (no shell)
        subprocess.run(['echo', filename], check=False)
        proc_ls = subprocess.run(['ls', '-la', filename], check=False, capture_output=True, text=True)
        result = proc_ls.stdout
        subprocess.run(['grep', 'pattern', filename], check=False, capture_output=True, text=True)
    except Exception:
        # Fail safely and do not leak system errors
        result = ''
    return result

def vulnerable_eval_injection(user_input):
    """CWE-95: Eval Injection"""
    import ast

    # PRECOGS_FIX: use ast.literal_eval to safely evaluate only Python literals (no code execution)
    try:
        result = ast.literal_eval(user_input)
    except (ValueError, SyntaxError):
        # If input is not a safe literal, do not evaluate arbitrary code. Return None or handle appropriately.
        result = None
    return result