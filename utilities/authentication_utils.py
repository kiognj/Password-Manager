from bcrypt import hashpw, gensalt, checkpw
from utilities.db_utils import add_user, check_user_exists, get_user_password_hash, get_user_id
from utilities.validation_utils import validate_username, validate_password
from utilities.logging_utils import logger
import getpass

def signup():
    """User sign-up process"""
    try:
        # Capturing and validation of username
        username = validate_username(input("\nEnter your desired username: "))
        # Check if username is already in use
        if check_user_exists(username):
            print("Username already taken. Please choose a different one.")
            logger.warning(f"Failed attempt to create a user: Username {username} already taken.")
            return
        # Capturing and validation of master password
        master_password = validate_password(getpass.getpass("Enter your master password: "))
        confirm_password = getpass.getpass("Confirm your master password: ")
        # Check if master password inputs are matching
        if master_password != confirm_password:
            print("Password do not match.")
            logger.warning(f"Failed attempt to create a user: mismatch of the passwords.")
            return
        # Hash the master password and add the user query to the database
        hashed_password = hashpw(master_password.encode('utf-8'), gensalt())
        add_user(username, hashed_password)
        print(f"User '{username}' registered successfully.")
        logger.info(f"User {username} registered successfully.")
    # Raising of all possible username and master password validation errors
    except ValueError as e:
        print(f"Input Error: {e}")
        logger.error(f"Sign Up procces input error: {e}")


def login():
    """User login process"""
    try:
        # Capture user credentials to log in to the password manager
        username = input("Enter your username: ")
        master_password = getpass.getpass("Enter your master password: ")
        # Get database stored hash of the master password of the exact user
        stored_hashed_password = get_user_password_hash(username)
        # Check if the master password is correct by comparing the hashes
        if stored_hashed_password and checkpw(master_password.encode('utf-8'), stored_hashed_password):
            # Get user ID of the user
            user_id = get_user_id(username)
            print(f"\nWelcome back, {username}!")
            logger.info(f"successful login attempt for user '{username}'.")
            return username, user_id, master_password
        else:
            print("Invalid username or password.")
            logger.warning(f"Failed attempt to log in as user {username}.")
            return None, None, None
    # Raising of all possible username and master password validation errors
    except ValueError as e:
        print(f"Input Error: {e}")
        logger.error(f"Log In procces input error: {e}")
    
    