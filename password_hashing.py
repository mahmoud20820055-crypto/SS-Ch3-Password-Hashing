"""
Software Security (SDEV 4303) - Chapter 03: User Authentication
Programming Task: Salted password hashing with SHA-256.

Author : Mahmoud Basel AL-Juaidi (120230589)

Each user record is stored in a text file (users.txt) as one line:
    username:salt_hex:hash_hex
where hash = SHA-256(password + salt).
"""

import getpass
import hashlib
import hmac
import os
import secrets
import sys

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.txt")
SALT_BYTES = 16  # 128-bit random salt


def generate_salt():
    """Return a new random salt as a hex string (cryptographically secure)."""
    return secrets.token_hex(SALT_BYTES)


def hash_password(password, salt):
    """Hash the password concatenated with the salt using SHA-256."""
    return hashlib.sha256((password + salt).encode("utf-8")).hexdigest()


def load_users():
    """Read all user records from the text file into a dictionary."""
    users = {}
    if not os.path.exists(DATA_FILE):
        return users
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            username, salt, pw_hash = line.split(":")
            users[username] = (salt, pw_hash)
    return users


def register(username, password):
    """Register a new user. Returns (success, message)."""
    if not username or ":" in username:
        return False, "Invalid username (must be non-empty and contain no ':')."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if username in load_users():
        return False, f"Username '{username}' already exists."

    salt = generate_salt()
    pw_hash = hash_password(password, salt)
    with open(DATA_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}:{salt}:{pw_hash}\n")
    return True, f"User '{username}' registered successfully.\n  salt = {salt}\n  hash = {pw_hash}"


def login(username, password):
    """Verify a user's credentials. Returns (success, message)."""
    users = load_users()
    if username not in users:
        # Same message as a wrong password so we do not reveal valid usernames.
        return False, "Login failed: invalid username or password."
    salt, stored_hash = users[username]
    computed = hash_password(password, salt)
    # Constant-time comparison to avoid timing attacks.
    if hmac.compare_digest(computed, stored_hash):
        return True, f"Login successful. Welcome, {username}!"
    return False, "Login failed: invalid username or password."


def read_password(prompt):
    """Hide typed password on a real terminal; fall back to input() when piped."""
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    pw = input(prompt)
    print("*" * len(pw))  # echo masked value when input is piped (demo mode)
    return pw


def main():
    while True:
        print("\n===== Password Hashing Demo (SHA-256 + Salt) =====")
        print("1. Register")
        print("2. Login")
        print("3. Show stored records (users.txt)")
        print("4. Exit")
        choice = input("Choose an option: ").strip()
        print(choice) if not sys.stdin.isatty() else None

        if choice == "1":
            username = input("Username: ").strip()
            print(username) if not sys.stdin.isatty() else None
            password = read_password("Password: ")
            ok, msg = register(username, password)
            print(("[OK] " if ok else "[ERROR] ") + msg)
        elif choice == "2":
            username = input("Username: ").strip()
            print(username) if not sys.stdin.isatty() else None
            password = read_password("Password: ")
            ok, msg = login(username, password)
            print(("[OK] " if ok else "[DENIED] ") + msg)
        elif choice == "3":
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, encoding="utf-8") as f:
                    print(f.read().rstrip() or "(empty)")
            else:
                print("(no users registered yet)")
        elif choice == "4":
            print("Goodbye.")
            break
        else:
            print("Invalid option, try again.")


if __name__ == "__main__":
    main()
