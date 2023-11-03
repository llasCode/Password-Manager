import os
import hashlib
import base64
import json
from getpass import getpass
from os.path import exists
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def view_options():
    print("\n")
    print("---Password Manager---\n")
    print("(1) Create Master Password")
    print("(2) Add Password")
    print("(3) View Passwords")
    print("(4) Edit Password")
    print("(5) Change Master Password")
    print("(6) Exit")

def check_master_password():
    file_exists = exists("mp.key")

    if not file_exists:
        os.system('cls')
        print("Master Password not found! Please, create one first")
        return False

    if os.path.getsize("mp.key") == 0:
        os.system('cls')
        print("Master Password not found! Please, create one first")
        return False

    with open("mp.key", 'rb') as f:
        x = f.read()

    p = getpass("Enter Master Password: ")
    m = hashlib.sha256()
    m.update(p.encode())

    if m.digest() == x:
        os.system('cls')
        print("Successful login")
        return True
    else:
        os.system('cls')
        print("Wrong password")
        return False

def create_master_password():

    if os.path.getsize("mp.key") != 0:
        os.system('cls')
        print("Master Password already found! Please, go to change master password option")
        return

    p = getpass("Enter Master Password: ")
    m = hashlib.sha256()
    m.update(p.encode())

    with open("mp.key", 'wb') as f:
        f.write(m.digest())

    os.system('cls')
    print("Master Password created!")

def add_password(mp):
    u = input("Enter username/email: ")
    p = getpass("Enter password: ").encode('utf-8')

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(mp))
    cipher = Fernet(key)
    e_password = cipher.encrypt(p)

    data = {
        "username": u,
        "password": e_password.hex(),
        "salt": salt.hex()
    }

    with open("passwords.key", "a") as f:
        f.write(json.dumps(data))
        f.write("\n")

    os.system('cls')
    print("Password added")

def view_passwords(mp):
    data = []
    with open("passwords.key", "r") as f:
        for line in f:
            data.append(json.loads(line))

    print("Enter the username of the password you wanna view")
    print("Current usernames stored: ")

    for line in data:
        print("-" + line["username"])

    username = input("Input the username: ")

    for d in data:
        if d["username"] == username:
            p_bytes = bytes.fromhex(d["password"])
            salt = bytes.fromhex(d["salt"])
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(mp))
            cipher = Fernet(key)
            d_password = cipher.decrypt(p_bytes)
            os.system('cls')
            print(f"Your password for {d["username"]} is:", d_password.decode())

def edit_passwords(mp):
    file_data = []
    with open("passwords.key", "r") as f:
        for line in f:
            file_data.append(json.loads(line))

    print("Enter the username of the password you wanna edit")
    print("Current usernames stored: ")

    for line in file_data:
        print("-" + line["username"])

    u = input("Input the username of the password you wanna change: ")

    line_number_to_edit = None 
    for i, line in enumerate(file_data):
        if line["username"] == u:
            line_number_to_edit = i
            break  
 
    p = getpass("Enter the new password: ").encode('utf-8')
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(mp))
    cipher = Fernet(key)
    e_password = cipher.encrypt(p)

    data = {
        "username": u,
        "password": e_password.hex(),
        "salt": salt.hex()
    }

    if line_number_to_edit != 0:

        file_data[line_number_to_edit] = data

        with open("passwords.key", "w") as f:
            f.write("")

        with open("passwords.key", "a") as f:
            for line in file_data:
                newData = {
                    "username": line["username"],
                    "password": line["password"],
                    "salt": line["salt"]
                }
                f.write(json.dumps(newData))
                f.write("\n")

        os.system('cls')
        print("Password changed")

    else:
        os.system('cls')
        print("Username not found")

  
def change_master_password(mp):
    file_content = []
    with open("passwords.key", "r") as f:
        for line in f:
            file_content.append(json.loads(line))

    usernames = []
    passwords = []
    salts = []

    for line in file_content:
        usernames.append(line["username"])
        passwords.append(line["password"])
        salts.append(line["salt"])

    d_passwords = []
    for p, s in zip(passwords, salts):
        p_bytes = bytes.fromhex(p)
        salt = bytes.fromhex(s)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(mp))
        cipher = Fernet(key)
        d_passwords.append(cipher.decrypt(p_bytes))
    
    p = getpass("Enter NEW Master Password: ")
    m = hashlib.sha256()
    m.update(p.encode())
    new_mp = m.digest()

    with open("mp.key", 'wb') as f:
        f.write(new_mp)

    with open("passwords.key", "w") as file:
        file.write("")

    for u, p in zip(usernames, d_passwords):

        salt = os.urandom(16)

        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key2 = base64.urlsafe_b64encode(kdf2.derive(new_mp))
        cipher = Fernet(key2)

        d = {
            "username": u,
            "password": cipher.encrypt(p).hex(),
            "salt": salt.hex()
        }

        with open("passwords.key", "a") as f:
            f.write(json.dumps(d))
            f.write("\n")

    os.system('cls')
    print("Master Password changed!")       

def main():
    mp_file_exists = exists("mp.key")
    p_file_exists = exists("passwords.key")

    if not mp_file_exists:
        f = open("mp.key", "w+")
        f.close()

    if not p_file_exists:
        f = open("passwords.key", "w+")
        f.close()

    exit = False

    while not exit:
        view_options()

        with open("mp.key", 'rb') as f:
            x = f.read()

        mp = x
        option = input("Choose the option: ")

        match (option):
            case "1":
                create_master_password()
            case "2":
                if check_master_password():
                    add_password(mp)
            case "3":
                if check_master_password():
                    view_passwords(mp)
            case "4":
                if check_master_password():
                    edit_passwords(mp)
            case "5":
                if check_master_password():
                    change_master_password(mp)
            case "6":
                exit = True

    os.system('cls')

if __name__ == "__main__":
    main()
