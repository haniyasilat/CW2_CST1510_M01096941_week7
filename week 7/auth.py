import bcrypt
import os
USER_DATA_FILE='users.txt'

def hash_password(plain_text_password):
    password_bytes=plain_text_password.encode('utf-8')
    salt =bcrypt.gensalt()
    hashed_password=bcrypt.hashpw(password_bytes, salt)
    return hashed_password

def verify_password(plain_text_password, hashed_password):
    
    password_bytes=plain_text_password.encode('utf-8')
    hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_password)


def register_user(username, password):
    if user_exists(username):
        print(f"Error: Username '{username}' already exists.")
        return False
    hashed_password= hash_password(password)
    hashed_password_str = hashed_password.decode('utf-8')
    with open('users.txt', 'a') as f:
        f.write(f'{username},{hashed_password_str}\n')
    print(f"User '{username}'registered.")
    return True

def user_exists(username):
    try:
        with open('users.txt', 'r') as f:
            for line in f:
                stored_username = line.strip().split(',')[0]
                if stored_username == username:
                    return True
        return False
    except FileNotFoundError:
        print("User file not found.")
        return False
    
def login_user(username, password): 
    """Log in an existing user."""
    with open("users.txt", "r") as f: 
      for line in f.readlines(): 
        user, h = line.strip().split(',', 1) 
        if user == username:
            if verify_password(password, h):
                return True
            else:
                print("Error: Invalid password.")
                return False
    print("Error: Username not found.")
    return False

def validate_username(username):
    if not username[0].isalpha():
        return False, "Username must start with a letter."

    if len(username)<=3:
        return False, 'Username should be more than 3 characters'
    return True, "Username is valid"

def validate_password(password):
    has_upper = False
    has_lower = False
    has_digit = False
    has_space = False
    for char in password:
        if char.isupper():
            has_upper=True
        elif char.islower():
            has_lower=True
        elif char.isdigit():
            has_digit=True
        elif char.isspace():
            has_space=True
    if has_space:
        return False, "Error: Password contains a space!"
       

    if has_upper and has_lower and has_digit:
        return True, "Password is valid"
    else:
        # Provide specific feedback about what's missing
        missing = []
        if not has_upper: 
            missing.append("uppercase")
        if not has_lower: 
            missing.append("lowercase") 
        if not has_digit: 
            missing.append("digit")
        error_msg = f"Missing: {', '.join(missing)}"
        return False, error_msg 
    
def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register the user
            register_user(username, password)

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ")
            password = input("Enter your password: ")

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access the dashboard)")

                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to return to main menu...")

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()