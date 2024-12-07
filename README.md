# Password-Manager

This is the primitive user-friendly password manager application that is designed to store, manage, encrypt and decrypt sensitive credentials of users.The tool helps users generate strog passwords, securely store their credentials and retrieve them when it is needed.

## Features

1) User Authentication:
 - Multi-user feature to sign up with hashed master password
 - Login functionality with password masking for added privacy

2) Password Vault
 - Add, retrieve, update and delete credentials functions
 - Automatic vault locking after a period of inactivity

3) Strong Password Generator
 - Generate random, strong passwords to use with the accounts

4) Encryption
 - AES-256 symmetric encrpytion algorithm is used in CFB (Cipher Feedback) mode that transforms AES into a stream cipher

5) Activity Logging
 - Logs all activities (excluding sensitive information)

## Technologies Used
 - Programming Language and version: Python 3.11.3 64 bit.
 - Cryptography: `PyCryptoDome` external library for encryption and decryption.
 - Database: SQLite for credential and user information storage.
 - Logging: `logging` module for secure activity logs.
 - Input Validation: Custom validation functions for usernames, passwords and servcice names.

## Setup and Installation

1) Clone the repository:

    `git clone https://github.com/kiognj/Password-Manager`
    
    `cd Password-Manager`

2) Install dependencies: Ensure you have installed python 3.6 +, then run

    `pip install -r requirements.txt`

3) Run the application

    `python app.py` or `py app.py`


## How to use

1) Sign Up: Create a username and a master password.

2) Log In: Use your credentials to access the password vault.

3) Manage Credentials: Add, retrieve, update, delete stored credentials.

4) Vault Lock: Automatically locks after some period of inactivity, or choose to log out of the system.

## Security Measures

 - Only hashes of master passwords are stored, and never in plaintext.
 - All credential passwords are encrypted with AES-256 CFB mode before storage.
 - Vault locks after 5 minutes of inactivity.
 - All inputs are validated.
 - Logs almost all activities inside the vault (excluding sensitive users' information)

## Project Structure

    Password-Manager/
    |-- files/
    |   |-- password_manager.db     # SQLite database file (created at runtime)
    |   |-- password_manager.log    # Log storage (created at runtime)
    |-- utilities/
    |   |-- authentication_utils.py # User signup and login functions
    |   |-- crypto_utils.py         # Encryption, decryption, key and password generation functions
    |   |-- db_utils.py             # Database initialization and query functions
    |   |-- logging_utils.py        # Logging setup and management
    |   |-- validation_utils.py     # Input validation functions
    |-- app.py                      # Main entry point for the application and main logic
    |-- README.md                   # Project documentation

## Future Enhancements

 - Add GUI for improved user experience
 - Rebuild main logic, for different tools in main menu
 - Rework service list logic
