import re
import hashlib

def check_password_strength(password):
    # Проверка длины пароля
    if len(password) < 8:
        return False, "Пароль должен содержать не менее 8 символов."
    
    # Проверка наличия прописных и строчных букв
    if not re.search("[a-z]", password):
        return False, "Пароль должен содержать хотя бы одну строчную букву."
    if not re.search("[A-Z]", password):
        return False, "Пароль должен содержать хотя бы одну прописную букву."
    
    # Проверка наличия цифр
    if not re.search("[0-9]", password):
        return False, "Пароль должен содержать хотя бы одну цифру."
    
    return True, "Пароль соответствует требованиям."

def hash_password(password):
    # Перевод пароля в хэш-значение (SHA-256)
    sha_signature = hashlib.sha256(password.encode()).hexdigest()
    return sha_signature

def main():
    password = input("Введите пароль: ")
    
    # Проверка сложности пароля
    is_strong, message = check_password_strength(password)
    if not is_strong:
        print(message)
        return
    
    # Хэширование пароля
    hashed_password = hash_password(password)
    print(f"Хэш пароля (SHA-256): {hashed_password}")

if __name__ == "__main__":
    main()
