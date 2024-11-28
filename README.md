# Password-Manager

This is the primitive user-friendly password manager application that is designed to store, manage, encrypt and decrypt sensitive credentials of users.The tool helps users generate strog passwords, securely store their credentials and retrieve them when it is needed.

## Features

1) User Authentication:
 - Multi-user feature to sign up with hashed master password
 - Login functionality with password masking for added privacy

2) Password Vault

3) Strong Password Generator

4) Encryption

5) Activity Logging

## Technologies Used

## Setup and Installation

## How to use

## Security Measures

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
 - Rewrite main logic