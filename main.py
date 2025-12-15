# main.py
import time
import getpass
import string
import secrets

from security import (
    ensure_salt, derive_key_pbkdf2,
    create_master_password, verify_master_password,
    load_vault, save_vault
)

from ratelimit import (
    check_lockout, calculate_backoff,
    record_failure, reset_attempts
)


# ---------------------------
# Password generation
# ---------------------------
def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(chars) for _ in range(length))


# ---------------------------
# CLI Actions
# ---------------------------
def add_entry(vault):
    site = input("Site: ").strip()
    user = input("Username: ").strip()

    if input("Auto-generate password? (y/n): ").lower() == "y":
        length = int(input("Length (16 default): ") or "16")
        pwd = generate_password(length)
        print("Generated:", pwd)
    else:
        pwd = getpass.getpass("Password: ")

    vault[site] = {"username": user, "password": pwd}
    print("Entry added.")


def view_entries(vault):
    if not vault:
        print("No entries saved.")
        return

    for site, data in vault.items():
        print(f"\n{site}")
        print("  Username:", data["username"])
        print("  Password:", data["password"])


def update_entry(vault):
    site = input("Site to update: ").strip()
    if site not in vault:
        print("Not found.")
        return

    user = input("New username (blank = keep): ").strip()
    if user:
        vault[site]["username"] = user

    if input("Change password? (y/n): ").lower() == "y":
        vault[site]["password"] = getpass.getpass("New password: ")

    print("Updated.")


def delete_entry(vault):
    site = input("Site to delete: ").strip()
    if site in vault:
        if input(f"Delete '{site}'? (y/n): ").lower() == "y":
            del vault[site]
            print("Deleted.")
    else:
        print("Not found.")


# ---------------------------
# Login / App flow
# ---------------------------
def authenticate():
    """
    Enforces lockout + backoff.
    Returns master password if correct, else None.
    """
    lock = check_lockout()
    if lock > 0:
        print(f"Too many attempts. Try again in {lock} seconds.")
        return None

    pwd = getpass.getpass("Master Password: ")

    if verify_master_password(pwd):
        reset_attempts()
        print("Login successful.")
        return pwd

    print("Incorrect password.")
    record_failure()

    backoff = calculate_backoff()
    if backoff > 0:
        print(f"Waiting {backoff} seconds...")
        time.sleep(backoff)

    return None


def main():
    salt = ensure_salt()

    import os

    if not os.path.exists("master.hash"):
        print("No master password found. Let's create one.")
        while True:
            pwd1 = getpass.getpass("Enter new master password: ")
            pwd2 = getpass.getpass("Confirm password: ")
            if pwd1 != pwd2:
                print("Passwords do not match. Try again.")
                continue
            if len(pwd1) < 8:
                print("Password too short. Must be at least 8 characters.")
                continue
            create_master_password(pwd1)
            print("Master password created successfully.")
            break

    # login loop
    master_pw = None
    while master_pw is None:
        master_pw = authenticate()

    # derive key
    key = derive_key_pbkdf2(master_pw, salt)

    # load vault
    try:
        vault = load_vault(key)
    except Exception as e:
        print("Vault error:", e)
        return

    # main menu
    while True:
        print("\n 1) Add\n 2) View\n 3) Update\n 4) Delete\n 5) Generate Only\n 6) Exit")
        choice = input("> ").strip()

        if choice == "1":
            add_entry(vault)
            save_vault(key, vault)
        elif choice == "2":
            view_entries(vault)
        elif choice == "3":
            update_entry(vault)
            save_vault(key, vault)
        elif choice == "4":
            delete_entry(vault)
            save_vault(key, vault)
        elif choice == "5":
            length = int(input("Length: ") or "16")
            print("Generated:", generate_password(length))
        elif choice == "6":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()