import re

def validate_service_name(service_name):
    """Validate the service name"""
    # Service name should not be empty
    if not service_name or len(service_name.strip()) == 0:
        raise ValueError("Service name cannot be empty.")
    # Service name can only contain letters, numbers and underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', service_name):
        raise ValueError("Service name can only contain letters, numbers, and underscores.")
    return service_name

def validate_username(username):
    """Validate the password manager username"""
    # Username should not be empty
    if not username or len(username.strip()) == 0:
        raise ValueError("Username cannot be empty.")
    # Username maximum length 30 characters
    if len(username) > 30:
        raise ValueError("Username is too long.")
    # Username minimum length 3 characters
    if len(username) < 3:
        raise ValueError("Username is too short.")
    # Username can only contain letters, numbers and underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        raise ValueError("Username can only contain letters, numbers, and underscores.")
    return username

def validate_service_username(username):
    """Validate the services' username"""
    # Service username should not be empty
    if not username or len(username.strip()) == 0:
        raise ValueError("Service username cannot be empty.")
    # Service username maximum length 30 characters
    if len(username) > 30:
        raise ValueError("Service username is too long.")
    # Service username minimum length 3 characters
    if len(username) < 3:
        raise ValueError("Service username is too short.")
    # Service username can only contain letters, numbers, and some special characters (@._)
    if not re.match(r'^[a-zA-Z0-9_@.]+$', username):
        raise ValueError("Service username can only contain letters, numbers, and some special characters (@._).")
    return username

def validate_password(password):
    """Validate password strength"""
    # Password minimum length 8 characters
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    # Password maximum length 30 characters
    if len(password) > 30:
        raise ValueError("Password is too long.")
    # Password must contain at least one uppercase letter
    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    # Password must contain at least one digit
    # if not any(char.isdigit() for char in password):
    #     raise ValueError("Password must contain at least one digit.")
    # Password must contain at least one special character
    # if not any(char in "!@#$%^&*()_+-=[]{}|;':\",.<>?/`~" for char in password):
    #     raise ValueError("Password must contain at least one special character.")
    return password