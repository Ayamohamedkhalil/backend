import re
from werkzeug.security import check_password_hash

def validate_registration_data(data, users_collection):

    def validate_username():
        if 'username' not in data:
            return 'Username is required'
        elif len(data['username']) < 2:
            return 'Username must be at least 2 characters long'
        elif len(data['username']) > 20:
            return 'Username must be no more than 20 characters long'
        else:
            return None

    def validate_email():
        if 'email' not in data:
            return 'Email is required'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', data['email']):
            return 'Invalid email format'
        else:
            return None

    def validate_password():
        if 'password' not in data:
            return 'Password is required'
        elif len(data['password']) < 6:
            return 'Password must be at least 6 characters long'
        elif len(data['password']) > 20:
            return 'Password must be no more than 20 characters long'
        else:
            return None

    def validate_confirm_password():
        if 'confirm_password' not in data:
            return 'Confirm password is required'
        elif data['password'] != data['confirm_password']:
            return 'Passwords do not match'
        else:
            return None

    validation_rules = {
        'username': validate_username,
        'email': validate_email,
        'password': validate_password,
        'confirm_password': validate_confirm_password
    }

    for field, validation_rule in validation_rules.items():
        error_message = validation_rule()
        if error_message:
            return error_message, False

    existing_email = users_collection.find_one({'email': data['email']})
    if existing_email:
        return 'Email already exists', False

    return None, True


def validate_login_data(data, users_collection):
    if 'email' not in data:
        return 'Email is required', False
    if 'password' not in data:
        return 'Password is required', False

    user = users_collection.find_one({'email': data['email']})
    if user and check_password_hash(user['password'], data['password']):
        return None, True
    return 'Invalid email or password', False    


def validate_reset_password(data):
    def validate_password():
        if 'password' not in data:
            return 'Password is required'
        elif len(data['password']) < 6:
            return 'Password must be at least 6 characters long'
        elif len(data['password']) > 20:
            return 'Password must be no more than 20 characters long'
        else:
            return None

    def validate_confirm_password():
        if 'confirm_password' not in data:
            return 'Confirm password is required'
        elif data['password'] != data['confirm_password']:
            return 'Passwords do not match'
        else:
            return None

    validation_rules = {
        'password': validate_password,
        'confirm_password': validate_confirm_password
    }

    for field, validation_rule in validation_rules.items():
        error_message = validation_rule()
        if error_message:
            return error_message, False

    return None, True


def validate_editProfile(data, users_collection):

    def validate_username():
        if 'username' in data:
            if len(data['username']) < 2:
                return 'Username must be at least 2 characters long'
            elif len(data['username']) > 20:
                return 'Username must be no more than 20 characters long'
        return None

    def validate_email():
        if 'email' in data:
            if not re.match(r'[^@]+@[^@]+\.[^@]+', data['email']):
                return 'Invalid email format'
        return None

    def validate_bio():
        if 'bio' in data and len(data['bio']) > 200:
            return 'Bio must be no more than 200 characters long'
        return None

    def validate_gender():
        if 'gender' in data and data['gender'] not in ['Male', 'Female', 'male', 'female']:
            return 'Invalid gender selection'
        return None

    validation_rules = {
        'username': validate_username,
        'email': validate_email,
        'bio': validate_bio,
        'gender': validate_gender
    }

    for field, validation_rule in validation_rules.items():
        error_message = validation_rule()
        if error_message:
            return error_message, False

    return None, True


def validate_Change_password(data):
    def validate_password():
        if 'new_password' not in data:
            return 'New Password is required'
        elif len(data['new_password']) < 6:
            return 'Password must be at least 6 characters long'
        elif len(data['new_password']) > 20:
            return 'Password must be no more than 20 characters long'
        else:
            return None

    def validate_confirm_password():
        if 'confirm_password' not in data:
            return 'Confirm password is required'
        elif data['new_password'] != data['confirm_password']:
            return 'Passwords do not match'
        else:
            return None

    validation_rules = {
        'new_password': validate_password,
        'confirm_password': validate_confirm_password
    }

    for field, validation_rule in validation_rules.items():
        error_message = validation_rule()
        if error_message:
            return error_message, False

    return None, True
