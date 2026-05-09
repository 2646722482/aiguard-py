# 测试文件：包含多个漏洞
import os
import subprocess
import pickle
import sqlite3

# 漏洞1: 命令注入
def delete_file(filename):
    os.system("rm -rf " + filename)

# 漏洞2: shell=True 危险
def run_cmd(cmd):
    subprocess.call(cmd, shell=True)

# 漏洞3: pickle反序列化
def load_data(data):
    return pickle.loads(data)

# 漏洞4: SQL注入
def get_user(name):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()

# 漏洞5: 硬编码密码
def login(password):
    if password == "admin123":
        return True
    return False

# 漏洞6: eval执行用户输入
def calculate(expr):
    return eval(expr)