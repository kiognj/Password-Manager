from utilities.crypto_utils import generate_key, encrypt, decrypt, generate_password
from utilities.db_utils import delete_credential, init_db, add_credential, fetch_credential, fetch_all_services, check_service_exists, update_service_username, update_service_password
from utilities.validation_utils import validate_service_name, validate_password, validate_service_username
from utilities.logging_utils import logger
from utilities.authentication_utils import signup, login
from Crypto.Random import get_random_bytes
import time, getpass

# Set the timeout to the vault
VAULT_TIMEOUT = 300
last_activity = time.time()

def check_vault_timeout():
    """Check if the vault is still active"""
    global last_activity
    if time.time() - last_activity > VAULT_TIMEOUT:
        return False
    # Reset the vault timer
    last_activity = time.time()
    return True

def main():
    # Initialize global variable for the vault timeout
    global last_activity
    # Initialize database
    init_db()
    while True:
        # Main Menu of the Password Manager
        print("\nWelcome to the Password Manager!")
        print("\n1. Sign Up\n2. Log in\n3. Exit\n")
        choice = input("Choose an option: ").strip()

        # Sign Up process activated
        if choice == "1":
            signup()
        # Log In process activated
        elif choice == "2":
            log_user, user_id, master_password = login()
            if master_password:
                while True:
                    # Enter the User Menu
                    print("\n1. Add Credential\n2. Show List of all Credentials\n3. Retrieve Credential\n4. Update Credential\n5. Delete Credential\n6. Log Out\n")
                    choice = input("Choose an option: ").strip()
                    # Before proceeding to the Password Manager Tools check the vault timeout of inactivity
                    if not check_vault_timeout():
                        # If 'Log out' option selected proceed without re-entering the master-password
                        if choice == "6":
                            print("Exiting the password manager.")
                            logger.info(f"User '{log_user}' log out of the password manager.")
                            break
                        # Re-enter the master-password to stay logged in after some time of inactivity
                        else:
                            print("\nVault locked due to inactivity.")
                            re_password = getpass.getpass("Re-enter your master password to unlock the vault: ").strip()
                            if master_password == re_password:
                                # Stay logged in and reset the vault timer
                                last_activity = time.time()
                                logger.info(f"User '{log_user}' logged back in after some time of inactivity.")
                                continue
                            else:
                                # Log out due to re-entering incorrect master-password 
                                print("The password is incorrect! Logging out...")
                                logger.warning(f"User '{log_user}' exited the password manager due to inactivity.")
                                break
                    # First Tool: Add Credential
                    if choice == "1": 
                        try:
                            # Capturing and validation of service name
                            service_name = validate_service_name(input("Enter service name: ").strip())
                            # Check if service already exists
                            if check_service_exists(service_name, user_id):
                                print(f"The service '{service_name}' already exists in your vault.")
                                logger.warning(f"User '{username}' tried to add credentials of the exsisting service.")
                                continue
                            # Capturing and validation of service username
                            username = validate_service_username(input("Enter username: ").strip())
                            # Ask if needed to generate strong password
                            generate = input("Do you want to generate a strong password? (yes/no): ").lower().strip()
                            if generate in ["yes", "y"]:
                                # Generate strong password
                                password = generate_password()
                                print(f"Generated password: {password}")
                            else:
                                # Capturing and validation of password
                                password = validate_password(getpass.getpass("Enter password: ").strip())
                            # Generate random salt, generate key out of salt and master-password, encrypt password with new-generated key
                            salt = get_random_bytes(16)
                            key = generate_key(master_password, salt)
                            encrypted_password = encrypt(password, key, salt)
                            # Add new credential to the database
                            add_credential(service_name, username, encrypted_password, salt, user_id)
                            print("Credential added successfully!")
                            logger.info(f"User '{log_user}' successfully added new credential.")
                            # Reset the vault timer
                            last_activity = time.time()
                        # Raising of all possible input errors
                        except ValueError as e:
                            print(f"Input Error: {e}")
                            logger.error(f"Add credential proccess input error: {e}")
                    # Second Tool: Show List of Credentials
                    elif choice == "2":
                        # Retrieve the list of all services added by the user
                        services = fetch_all_services(user_id)
                        if not services:
                            print("No credentials stored yet.")
                            continue
                        print("Available services:")
                        for idx, service in enumerate(services, start=1):
                            print(f"{idx}. {service}")
                    # Third Tool: Retrieve Credential
                    elif choice == "3":
                        try:
                            # Retrieve the list of all services added by the user
                            services = fetch_all_services(user_id)
                            if not services:
                                print("No credentials stored yet.")
                                continue
                            # Capturing and validation of service name
                            service_name = validate_service_name(input("Enter the service name: ").strip())
                            # Check if service exists
                            if service_name not in services:
                                print("Invalid service name. Please try again.")
                                logger.warning(f"User '{log_user}' tried to retrieve credentials of the unexsisting service.")
                                continue
                            # Retreive the credentials of the service
                            result = fetch_credential(service_name, user_id)
                            if result:
                                username, encrypted_password, salt = result
                                # Generate key for decryption out of master-password and retrieved from the database salt
                                key = generate_key(master_password, salt)
                                try:
                                    # Decrypt the retrieved password from the database
                                    decrypted_password = decrypt(encrypted_password, key)
                                    print(f"Service: {service_name}\nUsername: {username}\nPassword: {decrypted_password}")
                                    logger.info(f"User '{log_user}' successfully retrieved credential of '{service_name}'.")
                                    # Reset the vault timer
                                    last_activity = time.time()
                                # Raising of decryption errors
                                except ValueError as e:
                                    print(e)
                                    logger.error(f"Fetch credential proccess decryption error: {e}")
                            else:
                                # If the service is not found in the database warn the user
                                print("Credential not found!")
                                logger.warning(f"User '{log_user}' tried to fetch credentials of the unexsisting service.")
                        # Raising of all possible input errors
                        except ValueError as e:
                            print(f"Input Error: {e}")
                            logger.error(f"Fetch credential proccess input error: {e}")
                    # Fourth Tool: Update Credential
                    elif choice == "4":
                        try:
                            # Retrieve the list of all services added by the user
                            services = fetch_all_services(user_id)
                            if not services:
                                print("No credentials stored yet.")
                                continue
                            # Capturing and validation of service name
                            service_name = validate_service_name(input("Enter the service name of the credential to update: ").strip())
                            # Check if service exists
                            if service_name not in services:
                                logger.warning(f"User '{log_user}' tried to update credentials of the unexsisting service.")
                                print("Invalid service name. Please try again.")
                                continue
                            # Ask if needed to update username of service
                            update_username = input("Do you want to update the username? (yes/no): ").lower().strip()
                            new_username = None
                            if update_username in ["yes", "y"]:
                                # Capturing and validation of new username
                                new_username = validate_service_username(input("Enter the new username: ").strip())
                            # Ask if needed to update password of service
                            update_password = input("Do you want to update the password? (yes/no): ").lower().strip()
                            new_password = None
                            if update_password in ["yes", "y"]:
                                # Ask if needed to generate the new password
                                generate = input("Do you want to generate a strong password? (yes/no): ").strip()
                                if generate in ["yes", "y"]:
                                    # Generate the new password
                                    new_password = generate_password()
                                    print(f"Generated password: {new_password}")
                                else:
                                    # Capturing and validation of new password
                                    new_password = validate_password(getpass.getpass("Enter the new password: ").strip())
                            # Update the username if it was needed to
                            if new_username is not None:
                                # Update the database with a new username for the service
                                updated_username = update_service_username(service_name, user_id, new_username)
                                if updated_username:
                                    print(f"Username updated successfully for '{service_name}'.")
                                    logger.info(f"User '{log_user}' successfully updated username for '{service_name}'")
                                    # Reset the vault timer
                                    last_activity = time.time()
                            # Update the password if it was needed to
                            if new_password is not None:
                                # Generate random salt, generate key out of salt and master-password, encrypt password with new-generated key
                                salt = get_random_bytes(16)
                                key = generate_key(master_password, salt)
                                new_encrypted_password = encrypt(new_password, key, salt)
                                # Update the database with a new username for the service
                                updated_password = update_service_password(service_name, user_id, new_encrypted_password, salt)
                                if updated_password:
                                    print(f"Password updated successfully for '{service_name}'.")
                                    logger.info(f"User '{log_user}' successfully updated password for '{service_name}'")
                                    # Reset the vault timer
                                    last_activity = time.time()
                            # If the were nothing to update warn the user
                            if not (new_password or new_username):
                                print(f"No updates were made for '{service_name}'")
                                logger.warning(f"User '{log_user}' failed to update credentials for '{service_name}'")
                        # Raising of all possible input errors
                        except ValueError as e:
                            print(f"No updates were made for '{service_name}'")
                            print(f"Input Error: {e}")
                            logger.error(f"Update credential proccess input error: {e}")
                    # Fifth Tool: Delete Credential
                    elif choice == "5":
                        try:
                            # Retrieve the list of all services added by the user
                            services = fetch_all_services(user_id)
                            if not services:
                                print("No credentials stored yet.")
                                continue
                            # Capturing and validation of service name
                            service_name = validate_service_name(input("Enter the service name of the credential to delete: ").strip())
                            # Check if service exists
                            if service_name not in services:
                                print("Invalid service name. Please try again.")
                                logger.warning(f"User '{log_user}' tried to delete credentials of the unexsisting service.")
                                continue
                            # Confirm the deletion by typing in 'confirm' word
                            confirm = input(f"Please type 'confirm' to confirm the deletion of the credential for '{service_name}': ").strip()
                            if confirm == "confirm":
                                # Delete the credential in the database
                                if delete_credential(service_name, user_id):
                                    print(f"Credential for '{service_name}' deleted successfully!")
                                    logger.info(f"User '{log_user}' sucessfully deleted credentials.")
                                # Deletion cancelled due to no service name found in the database
                                else:
                                    print(f"No credential found for '{service_name}'.")
                                    logger.warning(f"User '{log_user}' tried to delete credentials of the unexsisting service.")
                            # Deletion cancelled due no confirmation of the deletion
                            else:
                                print("Deletion canceled.")
                                logger.error(f"User '{log_user}' failed to delete credentials for '{service_name}'.")
                        # Raising of all possible input errors
                        except ValueError as e:
                            print("Deletion canceled.")
                            print(f"Input Error: {e}")
                            logger.error(f"Delete credential proccess input error: {e}")
                    # Sixth Tool: Log Out
                    elif choice == "6":
                        # Log out of the Password Manager
                        print("Logging out of the password manager.")
                        logger.info(f"User '{log_user}' log out of the password manager.")
                        break
                    # Unexpected choice of the Password Manager Tools
                    else:
                        print("Invalid choice. Please try again.")
        # Exit process activated
        elif choice == "3":
            print("Exiting the password manager.")
            logger.info(f"Exited the password manager.")
            exit()
        # Unexpected choice of the Password Manager
        else:   
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()