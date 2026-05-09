# 这个代码有安全漏洞，用来测试审计工具
import sqlite3

def get_user(name):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 危险：SQL注入漏洞
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return cursor.fetchall()

def admin_login(password):
    # 危险：硬编码密码
    if password == "admin123":
        return True
    return False

# 危险：使用eval
user_input = input("输入表达式: ")
result = eval(user_input)
print(result)