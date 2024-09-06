from flask import Flask, request, jsonify, session
from pymongo import MongoClient
from datetime import datetime, timedelta
import jwt
import random
from werkzeug.security import generate_password_hash, check_password_hash
from validatoin import validate_registration_data, validate_login_data, validate_reset_password,validate_editProfile,validate_Change_password
from functools import wraps
from dotenv import load_dotenv
from config import Config
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from bson import ObjectId, Binary
from PIL import Image
import io


load_dotenv()
app = Flask(__name__)

app.config.from_object(Config)
app.config['SECRET_KEY']
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

client = MongoClient(app.config['MONGO_URI'])

db = client['users']
users_collection = db['users']

diseases_db = client['Diseases']
diseases_collection = diseases_db['diseases']

messages_db = client['Messages']
messages_collection = messages_db['messages']

Faq_db = client['FAQ']
faq_collection = Faq_db['faq']

contact_support_db = client['Contact_support']
contact_support_collection = contact_support_db['contact_support']

tokens_db = client['tokens']
blacklist_tokens = tokens_db['blacklist_tokens']


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')  # Expect the token in the Authorization header
        if not token:
            return jsonify({'Alert': 'Token is missing!'}), 401

        try:
            blacklisted = blacklist_tokens.find_one({'token': token})
            if blacklisted:
                return jsonify({'Alert': 'Please, Login again to continue'}), 401

            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users_collection.find_one({'username': data['user']})
            if not current_user:
                return jsonify({'Alert': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'Alert': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'Alert': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


# ---------------------------- Endpoints -----------------------------

@app.route("/api/home", methods=['GET'])
@token_required
def home(current_user):
    return jsonify({'message': f'Welcome, {current_user["username"]}!'}), 200

#  ------------------- Register ---------------------------

@app.route("/api/register", methods=['POST'])
def register_api():
    data = request.get_json()
    error_message, valid = validate_registration_data(data, users_collection)
    if not valid:
        return jsonify({'error': error_message}), 400

    hashed_password = generate_password_hash(data['password'])
    user_data = {
        'username': data['username'],
        'email': data['email'],
        'password': hashed_password
    }
    users_collection.insert_one(user_data)
    # Generate token
    token = jwt.encode({
        'user': data["username"],
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    # Return user data with token
    return jsonify({
        'message': f'Account created for {data["username"]}!',
        'user': {
            'username': data['username'],
            'email': data['email']
        },
        'token': token
    }), 201

#  ------------------- Login ---------------------------

@app.route("/api/login", methods=['POST'])
def login_api():
    data = request.get_json()
    error_message, valid = validate_login_data(data, users_collection)
    if not valid:
        return jsonify({'error': error_message}), 401

    # Find the user by email
    user = users_collection.find_one({'email': data['email']})

    if user and check_password_hash(user['password'], data['password']):
        # Generate token using the username
        token = jwt.encode({
            'user': user["username"],
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # Return user data with token
        return jsonify({
            'message': 'Login successful!',
            'user': {
                'username': user['username'],
                'email': user['email']
            },
            'token': token
        }), 200
    else:
        return jsonify({'error': 'Invalid email or password'}), 401
    
# ------------------- Disease description ------------------------
    
@app.route("/api/test/<string:testname>/<string:disease_name>", methods=['GET'])
@token_required
def get_disease_description(current_user, testname, disease_name):
    disease = diseases_collection.find_one({'name': disease_name})

    if disease:
        # Prepare the test entry
        test_entry = {
            'test_name': testname,
            'disease_name': disease_name,
            'date': datetime.utcnow().strftime('%Y-%m-%d')
        }

        # Check if the user already has a tests section, if not, create it
        if not current_user.get('tests'):
            users_collection.update_one(
                {'_id': current_user['_id']},
                {'$set': {'tests': []}}
            )

        # Add the test entry to the user's tests list
        users_collection.update_one(
            {'_id': current_user['_id']},
            {'$push': {'tests': test_entry}}  # Adds the test_entry to the list
        )

        return jsonify({
            'name': disease['name'],
            'description': disease['description']
        }), 200
    else:
        return jsonify({'error': 'Disease not found'}), 404

#  -----------------------Get user tests ---------------------------

@app.route("/api/tests", methods=['GET'])
@token_required
def get_user_tests(current_user):
    user = users_collection.find_one({'_id': current_user['_id']})
    
    if not user or 'tests' not in user or len(user['tests']) == 0:
        return jsonify({'message': 'No tests found'}), 404

    return jsonify({'tests': user['tests']}), 200

# ----------------- Resquest Data --------------------------

@app.route("/api/request-data", methods=['POST'])
@token_required
def request_data(current_user):
    # Fetch the user's previous tests
    previous_tests = current_user.get('tests', [])

    if not previous_tests:
        return jsonify({'message': 'No previous tests found'}), 404

    # Prepare the email content
    tests_info = "\n\n".join([f"Test Name: {test['testname']}\nDisease: {test['disease_name']}\nDate: {test['date']}" for test in previous_tests])
    
    # Email content
    subject = "Your Previous Tests Data"
    body = f"Dear {current_user['username']},\n\nHere are your previous tests:\n\n{tests_info}\n\nBest regards,\nYour Team"

    # Send the email
    try:
        sender_email = app.config['SENDER_EMAIL']
        sender_password = app.config['SENDER_PASSWORD']
        recipient_email = current_user['email']

        # Create the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Setup the server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)

        # Send the email
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()

        return jsonify({'message': 'Your previous tests have been sent to your email'}), 200

    except Exception as e:
        return jsonify({'error': f'Failed to send email: {str(e)}'}), 500
    
#  ---------------------- Verification ---------------------------------

@app.route("/api/verify", methods=['POST'])
def verify():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Check if the email exists in the database
    user = users_collection.find_one({'email': email})

    if user:
        verification_code = str(random.randint(1000, 9999))  # Generate a 4-digit code
        expiration_time = datetime.utcnow() + timedelta(minutes=5)  # Set expiration time to 5 minutes from now

        # Store the verification code and expiration time in the database
        users_collection.update_one(
            {'email': email},
            {'$set': {
                'verification_code': verification_code,
                'verification_expiration': expiration_time
            }}
        )
        # Store email in the session
        session['email'] = email

        # Send verification code to user's email
        try:
            sender_email = app.config['SENDER_EMAIL']
            sender_password = app.config['SENDER_PASSWORD']
            subject = "Your Verification Code"
            body = f"Your verification code is {verification_code}"

            # Create the email
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            # Setup the server
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)

            # Send the email
            text = msg.as_string()
            server.sendmail(sender_email, email, text)
            server.quit()

            return jsonify({'message': 'Verification code sent to your email'}), 200

        except Exception as e:
            return jsonify({'error': f'Failed to send email: {str(e)}'}), 500

    else:
        return jsonify({'error': 'Email not found'}), 404
    
# ---------------- Internal -----------------------------

@app.route("/api/resetPasswordInternal", methods=['POST'])
def resetPassword_internal():
    email = session.get('email')
    if not email:
        return jsonify({'error': 'Session expired or email not found'}), 400

    data = request.get_json()
    verification_code = data.get('verification_code')

    if not verification_code:
        return jsonify({'error': 'Verification code is required'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.get('verification_code') != verification_code:
        return jsonify({'error': 'Verification code is incorrect!'}), 400

    # Check if the verification code is expired
    if datetime.utcnow() > user.get('verification_expiration'):
        return jsonify({'error': 'Verification code has expired'}), 400

    # Allow the user to proceed to reset the password
    return jsonify({'message': 'Verification successful, proceed to reset password.'}), 200

# ---------------------- reset Password -------------------------

@app.route("/api/resetPassword", methods=['POST'])
def resetPassword():
    email = session.get('email')
    if not email:
        return jsonify({'error': 'Session expired or email not found'}), 400

    data = request.get_json()
    new_password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not new_password or not confirm_password:
        return jsonify({'error': 'Password and confirmation are required'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400

    error_message, valid = validate_reset_password(data)
    if not valid:
        return jsonify({'error': error_message}), 401

    # If all checks pass, reset the password
    hashed_password = generate_password_hash(new_password)
    users_collection.update_one(
        {'email': email},
        {'$set': {'password': hashed_password}, '$unset': {'verification_code': "", 'verification_expiration': ""}}
    )

    return jsonify({'message': 'Password reset successfully!'}), 200

# ---------------------- Get user profile Info ------------------------------

@app.route("/api/user/profile/<string:username>", methods=['GET'])
@token_required
def get_user_profile(current_user, username):
    # Query the database for the user by username
    if current_user['username'] != username:
        return jsonify({'error': 'You can only access your own profile'}), 403

    user = users_collection.find_one(
        {'username': username},
        {'_id': 0, 'username': 1, 'email': 1, 'gender': 1, 'bio': 1}
    )

    if user:
        profile_data = {
            'name': user.get('username'),
            'email': user.get('email'),
            'gender': user.get('gender'),
            'bio': user.get('bio')
        }
        return jsonify(profile_data), 200
    else:
        return jsonify({'error': 'User not found'}), 404

#  ------------------- Edit Profile ---------------------------

@app.route('/api/edit-profile', methods=['PATCH'])
@token_required
def edit_profile(current_user):
    data = request.get_json()
    photo = request.files.get('photo')

    validation_error, is_valid = validate_editProfile(data, users_collection)
    if not is_valid:
        return jsonify({'error': validation_error}), 400
    update_fields = {}

    # Update email if provided
    if 'email' in data:
        email_exists = users_collection.find_one({'email': data['email']})
        if email_exists and email_exists['username'] != current_user['username']:
            return jsonify({'error': 'Email is already in use by another account.'}), 400
        update_fields['email'] = data['email']

    # Update username if provided
    if 'username' in data:
        username_exists = users_collection.find_one({'username': data['username']})
        if username_exists and username_exists['username'] != current_user['username']:
            return jsonify({'error': 'Username is already taken.'}), 400
        update_fields['username'] = data['username']

    # Update gender if provided
    if 'gender' in data:
        update_fields['gender'] = data['gender']

    # Update bio if provided
    if 'bio' in data:
        update_fields['bio'] = data['bio']

    if photo:
        image = Image.open(photo)
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format=image.format)
        img_byte_arr = img_byte_arr.getvalue()

        # Store the image in MongoDB as binary data
        update_fields['photo'] = Binary(img_byte_arr)

    # Apply updates if there are any fields to update
    if update_fields:
        users_collection.update_one({'username': current_user['username']}, {'$set': update_fields})

    # Fetch updated user data
    updated_user = users_collection.find_one({'username': update_fields.get('username', current_user['username'])})

    return jsonify({
        'message': 'Profile updated successfully!',
        'user': {
            'username': updated_user.get('username'),
            'email': updated_user.get('email'),
            'gender': updated_user.get('gender'),
            'bio': updated_user.get('bio')
        }
    }), 200

# -------------------------- Change password -------------------------------------
@app.route('/api/changePassword', methods=['PUT'])
@token_required
def changePassword(current_user):
    data = request.get_json()
    if 'current_password' not in data :
        return jsonify({'error': 'Current password is required.'}), 400

    if not check_password_hash(current_user['password'], data['current_password']):
        return jsonify({'error': 'Current password is incorrect.'}), 400

    validation_error, is_valid = validate_Change_password(data)
    if not is_valid:
        return jsonify({'error': validation_error}), 400

    hashed_password = generate_password_hash(data['new_password'])

    users_collection.update_one({'username': current_user['username']},
                                {'$set': {'password': hashed_password}})  # Update the user's passw
    return jsonify({'message': 'Password updated successfully!'}), 200

# ------------------ Contact Us ------------------------------

@app.route("/api/contactUS", methods=['POST'])
@token_required
def contact_us(current_user):
    data = request.get_json()
    firstname = data.get('firstname')
    lastname = data.get('lastname')
    email = current_user['email']
    message = data.get('message')

    # Validate input
    if not all([firstname, lastname, email, message]):
        return jsonify({'error': 'All fields are required'}), 400

    # Store the contact information and message in the database
    contact_entry = {
        'firstname': firstname,
        'lastname': lastname,
        'email': email,
        'message': message,
        'created_at': datetime.utcnow()
    }
    messages_collection.insert_one(contact_entry)

    # Send an acknowledgment email to the user
    try:
        sender_email = app.config['SENDER_EMAIL']
        sender_password = app.config['SENDER_PASSWORD']
        subject = "Thank You for Contacting Us"
        body = f"Dear {firstname} {lastname},\n\nThank you for reaching out to us. We have received your message and will get back to you shortly.\n\nBest regards,\nMalaz"

        # Create the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Setup the server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)

        # Send the email
        text = msg.as_string()
        server.sendmail(sender_email, email, text)
        server.quit()

        return jsonify({'message': 'Thank you for contacting us. We have received your message.'}), 200

    except Exception as e:
        return jsonify({'error': f'Failed to send acknowledgment email: {str(e)}'}), 500
    
# --------------- faq ----------------------------

@app.route("/api/faq", methods=['POST'])
@token_required
def get_faq(current_user):
    data = request.get_json()
    question = data.get('question')

    if not question:
        return jsonify({'error': 'Question is required'}), 400

    # Find the FAQ in the database
    faq_entry = faq_collection.find_one({'Question': question})

    if not faq_entry:
        return jsonify({'error': 'No answer found for the provided question'}), 404

    # Assuming the answer is stored as a string with steps separated by commas
    steps = faq_entry.get('answer').split(', ')

    return jsonify({
        'question': faq_entry.get('Question'),
        'answer': faq_entry.get('answer')
    }), 200

# --------------- Contact Support ----------------------

@app.route("/api/contact_support", methods=['GET'])
@token_required
def get_all_faq(current_user):

    contacts = contact_support_collection.find({}, {'_id': 0, 'contact': 1, 'body': 1})

    contacts_list = []
    for c in contacts:
        contacts_list.append({
            'contact': c['contact'],
            'way': c['body']
        })

    return jsonify({'Contacts': contacts_list}), 200

# ------------------ Delete Account ------------------------------

@app.route('/api/delete-account', methods=['DELETE'])
@token_required
def delete_account(current_user):
    data = request.get_json()
    password = data.get('password')
    #checks if password exists in data
    if not password:
        return jsonify({'error': 'Password is required to delete the account.'}), 400

    #checks with the password in the database
    if not check_password_hash(current_user['password'], password):
        return jsonify({'error': 'Incorrect password.'}), 400

    #Delete the user account
    users_collection.delete_one({'username': current_user['username']})

    return jsonify({'message': f'Account for {current_user["username"]} has been deleted.'}), 200

#  ---------------- Logout --------------------------

@app.route("/api/logout", methods=['POST'])
@token_required
def logout(current_user):
    token = request.headers.get('Authorization')

    try:
        # Add the token to the blacklist
        blacklist_tokens.insert_one({'token': token})
        return jsonify({'message': 'Successfully logged out'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to logout: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
