# generate_hash.py

from werkzeug.security import generate_password_hash

def main():
    password = input("Enter the password to hash: ")
    hashed_password = generate_password_hash(password, method='scrypt')
    print(f"Hashed Password: {hashed_password}")

if __name__ == "__main__":
    main()

