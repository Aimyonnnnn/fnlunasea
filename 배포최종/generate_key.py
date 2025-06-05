from cryptography.fernet import Fernet

key = Fernet.generate_key()
with open('encryption_key.key', 'wb') as f:
    f.write(key)
print("encryption_key.key 생성 완료!")