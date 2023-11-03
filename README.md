# Password-Manager
This program is a simple terminal-based password manager written in Python. It uses hashing (SHA-256) to create the master password. <br />
This master password is used for authentication and for creating the key to encrypt and decrypt the passwords (Symmetric cipher). <br />
Two files are created when starting the program for the first time. The file called "mp.key", stores the hash of the master password. The file called "passwords.key" stores the encrypted passwords.
