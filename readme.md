# Secure CLI Password Manager

## Project Description

This project is a **secure command-line password manager** written in Python. It allows users to safely store, view, update, and delete credentials for different websites or services. The application uses strong cryptographic practices such as **bcrypt**, **PBKDF2**, and **Fernet (AES-based authenticated encryption)**, along with **rate limiting and lockout protection** to defend against brute-force attacks.

The vault is encrypted locally, and all sensitive data remains on the user’s machine.

---

## Installation / Setup Instructions

### 1. Prerequisites

* Python **3.9 or higher**
* pip (Python package manager)

### 2. Clone or Download the Project

```bash
git clone https://github.com/SaySopheakdey/secure-password-manager.git
cd password-manager
```

Or download the source files manually and place them in one directory.


### 4. Install Dependencies

```bash
pip install bcrypt cryptography
```

---

## Usage Examples

### 1. Run the Application

```bash
python main.py
```

### 2. First-Time Setup

* If no master password exists, the program will prompt you to create one.
* The master password must be **at least 8 characters long**.
* A cryptographic salt and encrypted vault file will be generated automatically.

### 3. Login

You will be prompted for your master password. The application enforces:

* Exponential backoff after failed attempts
* Account lockout after too many failures

### 4. Main Menu Options

```
1) Add
2) View
3) Update
4) Delete
5) Generate Only
6) Exit
```

#### Add a New Entry

* Store a site name, username, and password
* Option to auto-generate a strong password

#### View Entries

* Displays all stored credentials (after successful decryption)

#### Update an Entry

* Modify username and/or password for an existing site

#### Delete an Entry

* Permanently remove stored credentials for a site

#### Generate Only

* Generate a secure random password without saving it

---

## Dependencies / Libraries Used

* **bcrypt**

  * Secure hashing for the master password

* **cryptography (Fernet)**

  * Symmetric authenticated encryption (AES + HMAC)

* **hashlib (PBKDF2-HMAC-SHA256)**

  * Key derivation from the master password

* **secrets**

  * Cryptographically secure random number generation

* **getpass**

  * Secure password input (hidden from terminal)

* **json / os / time / string**

  * Standard Python libraries for storage, file handling, and timing

---

## Security Features Summary

* Encrypted password vault (AES-based Fernet)
* Strong key derivation using PBKDF2
* Secure password hashing with bcrypt
* Rate limiting and exponential backoff
* Automatic lockout after repeated failures
* Local-only storage (no network usage)

---

For study project