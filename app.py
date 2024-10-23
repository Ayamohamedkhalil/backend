from flask import Flask, request, jsonify, session
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
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
import google.generativeai as genai
import firebase_admin
from firebase_admin import credentials, messaging
import uuid
from pytz import timezone
import json
import base64
import pytz
from flask_apscheduler import APScheduler


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

journal_db = client['Journal']
journal_collection = journal_db['journal']

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

if os.getenv('RAILWAY_ENVIRONMENT') == 'production':  
    # Load the Firebase credentials from the environment variable (on Railway)
    firebase_credentials_json = os.getenv('FIREBASE_CREDENTIALS')
    
    if firebase_credentials_json:
        # Convert the JSON string back to a dictionary
        firebase_credentials_dict = json.loads(firebase_credentials_json)
        cred = credentials.Certificate(firebase_credentials_dict)
        firebase_admin.initialize_app(cred)
    else:
        raise ValueError("Firebase credentials not found in environment variables.")
else:
    # Local environment: Load the credentials from the JSON file
    cred = credentials.Certificate('graduationproject-4f4ab-firebase-adminsdk-spja4-dbb848a1df.json')
    firebase_admin.initialize_app(cred)

def send_push_notification(token, title, body):
    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        token=token,
    )

    response = messaging.send(message)
    print('Successfully sent message:', response)
    return response

#  ------------------- Register ---------------------------

@app.route("/api/register", methods=['POST'])
def register_api():
    try:
        data = request.get_json()

        # Validate the registration data
        error_message, valid = validate_registration_data(data, users_collection)
        if not valid:
            return jsonify({'error': error_message}), 400

        # Check if email already exists
        existing_email = users_collection.find_one({'email': data['email']})
        if existing_email:
            return jsonify({'error': 'Email already exists'}), 400

        hashed_password = generate_password_hash(data['password'])

        fcm_token = data.get('fcm_token')
        if not fcm_token:
            return jsonify({'error': 'FCM token is required'}), 400

        user_data = {
            'username': data['username'],
            'email': data['email'],
            'password': hashed_password,
            'fcm_token': fcm_token  
        }

        try:
            users_collection.insert_one(user_data)
        except Exception as e:
            return jsonify({'error': 'Unable to create user'}), 500

        # Generate JWT token
        try:
            token = jwt.encode({
                'user': data["username"],
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')
        except Exception as e:
            return jsonify({'error': 'Token generation failed'}), 500

        return jsonify({
            'message': f'Account created for {data["username"]}!',
            'user': {
                'username': data['username'],
                'email': data['email']
            },
            'token': token
        }), 201

    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred'}), 500

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
        # Collect the FCM token from the request
        fcm_token = data.get('fcm_token')
        if not fcm_token:
            return jsonify({'error': 'FCM token is required'}), 400

        # Update the user's FCM token
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'fcm_token': fcm_token}}
        )

        # Generate token using the username
        token = jwt.encode({
            'user': user["username"],
            'exp': datetime.utcnow() + timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')

        # Convert UTC time to local time (for example, Africa/Cairo)
        utc_time = datetime.utcnow()
        local_tz = timezone('Africa/Cairo')
        local_time = utc_time.replace(tzinfo=timezone('UTC')).astimezone(local_tz)
        phone_info = data.get('phone')  # Phone type comes from JSON payload

        if not phone_info:
            return jsonify({'error': 'Phone information is required'}), 400

        # Check if the phone already exists in login_activity
        existing_activity = users_collection.find_one(
            {'username': user['username'], 'login_activity.mobile': phone_info}
        )

        if existing_activity:
            # Update the time and date of the existing phone entry
            users_collection.update_one(
                {'username': user['username'], 'login_activity.mobile': phone_info},
                {'$set': {
                    'login_activity.$.time': local_time.strftime('%I:%M %p'),
                    'login_activity.$.date': local_time.strftime('%d-%m-%Y')
                }}
            )
        else:
            # Add a new login activity for this phone
            login_activity_object = {
                'mobile': phone_info,
                'time': local_time.strftime('%I:%M %p'),
                'date': local_time.strftime('%d-%m-%Y')
            }

            users_collection.update_one(
                {'username': user['username']},
                {'$push': {'login_activity': login_activity_object}}
            )

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

 #A function to send a reminder notification
def send_reminder_notification():
    users = users_collection.find({"notifications_enabled": True})  # Find all users with notifications enabled
    
    for user in users:
        registration_token = user.get('fcm_token')
        if registration_token:
            try:
                message_title = "Reminder: New Tests Available"
                message_body = "It's time to complete your new tests. Please check the app."
                notification_response = send_push_notification(registration_token, message_title, message_body)

                if notification_response:
                    print(f"Reminder notification sent successfully to {registration_token}")
                else:
                    print(f"Failed to send reminder notification.")

            except Exception as e:
                print(f"Error sending reminder notification: {e}")

# Schedule the reminder notification job
scheduler.add_job(
    id='send_reminder_notification',
    func=send_reminder_notification,
    trigger='interval',
    days=2,  # Set the interval to 2 days
    timezone=pytz.utc  # Make sure to handle timezone
)

# ------------------- Update the fcm_token -----------------------

@app.route("/api/update_fcm_token", methods=['PUT'])
@token_required  
def update_fcm_token(current_user):
    try:
        data = request.get_json()

        # Ensure fcm_token is provided
        fcm_token = data.get('fcm_token')
        if not fcm_token:
            return jsonify({'error': 'FCM token is required'}), 400

        result = users_collection.update_one(
            {'email': current_user['email']}, 
            {'$set': {'fcm_token': fcm_token}}  
        )

        if result.modified_count == 0:
            return jsonify({'error': 'No changes were made or user not found'}), 400

        return jsonify({'message': 'FCM token updated successfully!'}), 200

    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred'}), 500

# ------------------- Update the fcm_token -----------------------

@app.route("/api/update_fcm_token", methods=['PUT'])
@token_required  
def update_fcm_token(current_user):
    try:
        data = request.get_json()

        # Ensure fcm_token is provided
        fcm_token = data.get('fcm_token')
        if not fcm_token:
            return jsonify({'error': 'FCM token is required'}), 400

        result = users_collection.update_one(
            {'email': current_user['email']}, 
            {'$set': {'fcm_token': fcm_token}}  
        )

        if result.modified_count == 0:
            return jsonify({'error': 'No changes were made or user not found'}), 400

        return jsonify({'message': 'FCM token updated successfully!'}), 200

    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred'}), 500
    
# ------------------- Login Activity ---------------------------

@app.route("/api/loginActivity", methods=['GET'])
@token_required
def login_activity(current_user):
    user_data = users_collection.find_one(
        {'username': current_user['username']},
        {'login_activity': 1, '_id': 0}
    )

    if user_data and 'login_activity' in user_data:
        login_activities = [
            {
                'mobile': activity.get('mobile', 'Unknown Device'),
                'time': activity.get('time', 'Unknown Time'),
                'date': activity.get('date', 'Unknown Date')
            }
            for activity in user_data['login_activity']
        ]
        return jsonify({
            'login_activities': login_activities
        }), 200
    else:
        return jsonify({'error': 'No login activity found'}), 404


def generate_unique_id():
    return str(uuid.uuid4())

# ------------------- Disease description ------------------------
    
@app.route("/api/test/<string:testname>/<string:disease_name>", methods=['GET'])
@token_required
def get_disease_description(current_user, testname, disease_name):
    disease = diseases_collection.find_one({'name': disease_name})

    if disease:
        # Prepare the disease entry
        disease_entry = {
            'disease_name': disease_name,
            'date': datetime.utcnow().strftime('%Y-%m-%d')
        }

        # Check if the user already has tests, if not, create it
        if not current_user.get('tests'):
            users_collection.update_one(
                {'_id': current_user['_id']},
                {'$set': {'tests': []}}
            )

        # Find if this testname already exists in the user's tests
        user_tests = current_user.get('tests', [])
        test_found = False

        for test in user_tests:
            if test['test_name'] == testname:
                test_found = True
                users_collection.update_one(
                    {'_id': current_user['_id'], 'tests.test_name': testname},
                    {'$push': {'tests.$.diseases': disease_entry}}
                )
                break

        # If the testname doesn't exist, create a new one
        if not test_found:
            new_test_entry = {
                'test_name': testname,
                'diseases': [disease_entry]
            }
            users_collection.update_one(
                {'_id': current_user['_id']},
                {'$push': {'tests': new_test_entry}}
            )

        registration_token = current_user.get('fcm_token') 
        if registration_token:
            try:
                message_title = f"Test '{testname}' Completed"
                message_body = f"You successfully completed the test for {disease_name}."
                notification_response = send_push_notification(registration_token, message_title, message_body)
                
                if notification_response:
                    print(f"Notification sent successfully to {registration_token}")
                else:
                    print(f"Failed to send notification.")

            except Exception as e:
                print(f"Error sending notification: {e}")

        return jsonify({
            'name': disease['name'],
            'description': disease['description'],
            'link': disease['link']
        }), 200

    else:
        return jsonify({'error': 'Disease not found'}), 404

#  -----------------------Get user tests ---------------------------

@app.route("/api/previous_tests", methods=['GET'])
@token_required
def get_user_tests(current_user):
    user = users_collection.find_one({'_id': current_user['_id']})

    if not user or 'tests' not in user or len(user['tests']) == 0:
        return jsonify({'message': 'No tests found'}), 404

    tests = []
    for test in user['tests']:
        testname = test['test_name']
        for disease in test['diseases']:
            tests.append({
                'testname': testname,
                'disease_name': disease['disease_name'],
                'date': disease['date']
            })

    return jsonify({'tests': tests}), 200

# ----------------- Resquest Data --------------------------

@app.route("/api/request-data", methods=['POST'])
@token_required
def request_data(current_user):
    # Fetch the user's previous tests
    previous_tests = current_user.get('tests', [])

    if not previous_tests:
        return jsonify({'message': 'No previous tests found'}), 404

    tests_info = []
    
    for test in previous_tests:
        test_name = test.get('test_name', 'N/A')
        
        # Loop through diseases in the test
        for disease in test.get('diseases', []):
            disease_name = disease.get('disease_name', 'Unknown disease')
            disease_date = disease.get('date', 'Unknown date')
            # Format each test and disease into the desired structure
            tests_info.append(
                f"Test Name: {test_name}\n"
                f"Disease: {disease_name}\n"
                f"Date: {disease_date}\n"
            )
    
    email_body_content = "\n".join(tests_info)

    # Email content
    subject = "Your Previous Tests Data"
    body = (
        f"Dear {current_user['username']},\n\n"
        "Here are your previous tests:\n\n"
        f"{email_body_content}\n"
        "Best regards,\nMalaz"
    )

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
        verification_code = str(random.randint(1000, 9999))  
        expiration_time = datetime.utcnow() + timedelta(minutes=5)

        # Store the verification code and expiration time in the database
        users_collection.update_one(
            {'email': email},
            {'$set': {
                'verification_code': verification_code,
                'verification_expiration': expiration_time
            }}
        )

        # Store email in session and set the cookie
        session['email'] = email

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

            # Return success message
            response = jsonify({'message': 'Verification code sent to your email'})
            response.set_cookie('email', email, httponly=True, samesite='Lax')  # Set the email in a secure cookie

            return response, 200

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
        return jsonify({'error': error_message}), 400

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

def validate_image_size(base64_image):
    # Decode the base64 image to check its size
    image_data = base64.b64decode(base64_image.split(',')[1])  # Strip metadata if present
    return len(image_data) <= 1 * 1024 * 1024  # 1 MB limit

@app.route('/api/edit-profile', methods=['PATCH'])
@token_required
def edit_profile(current_user):
    data = request.get_json()
    validation_error, is_valid = validate_editProfile(data, users_collection)

    if not is_valid:
        return jsonify({'error': validation_error}), 400

    update_fields = {}

    if 'email' in data:
        email_exists = users_collection.find_one({'email': data['email']})
        if email_exists and email_exists['username'] != current_user['username']:
            return jsonify({'error': 'Email is already in use by another account.'}), 400
        update_fields['email'] = data['email']

    if 'username' in data:
        username_exists = users_collection.find_one({'username': data['username']})
        if username_exists and username_exists['username'] != current_user['username']:
            return jsonify({'error': 'Username is already taken.'}), 400
        update_fields['username'] = data['username']

    if 'gender' in data:
        update_fields['gender'] = data['gender']

    if 'bio' in data:
        update_fields['bio'] = data['bio']

    if 'picture' in data:
        base64_image = data['picture']

    if not validate_image_size(base64_image):
            return jsonify({'error': 'Image size exceeds 1 MB limit.'}), 400
    
    update_fields['picture'] = base64_image

    if update_fields:
        users_collection.update_one({'username': current_user['username']}, {'$set': update_fields})

    updated_user = users_collection.find_one({'username': update_fields.get('username', current_user['username'])})

    return jsonify({
        'message': 'Profile updated successfully!',
        'user': {
            'username': updated_user.get('username'),
            'email': updated_user.get('email'),
            'gender': updated_user.get('gender'),
            'bio': updated_user.get('bio'),
            'picture': updated_user.get('picture')  
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
    
# --------------- Add faq ----------------------------

@app.route("/api/add_faq", methods=['POST'])
@token_required
def add_faq(current_user):
    data = request.json
    question = data.get('question')
    answer = data.get('answer')

    if not question or not answer:
        return jsonify({'error': 'Question and answer are required'}), 400

    # Check if the question already exists in the database
    existing_faq = faq_collection.find_one({'Question': question})
    if existing_faq:
        return jsonify({'message': 'Question already exists'}), 409

    # Insert the new FAQ into the collection
    faq_collection.insert_one({
        'Question': question,
        'answer': answer
    })

    return jsonify({'message': 'FAQ added successfully'}), 200


# --------------- FAQ ----------------------

@app.route("/api/faq", methods=['GET'])
@token_required
def get_faq(current_user,):
    faqs = faq_collection.find({}, {'_id': 0, 'Question': 1, 'answer': 1})

    # Prepare the response in the desired format
    faq_list = []
    for faq in faqs:
        faq_list.append({
            'question': faq['Question'],
            'answer': faq['answer']
        })

    return jsonify({'faq': faq_list}), 200

# --------------- Contact Support ----------------------

@app.route("/api/contact_support", methods=['GET'])
@token_required
def get_all_contacts(current_user):

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
    # checks if password exists in data
    if not password:
        return jsonify({'error': 'Password is required to delete the account.'}), 400

    # checks with the password in the database
    if not check_password_hash(current_user['password'], password):
        return jsonify({'error': 'Incorrect password.'}), 400

    journal_collection.delete_many({'email': current_user['email']})
    users_collection.delete_one({'username': current_user['username']})

    return jsonify({'message': f'Account for {current_user["username"]} has been deleted.'}), 200

#  -----------------------delete user tests ---------------------------

@app.route("/api/deleteAllTests", methods=['POST'])
@token_required
def delete_all_tests(current_user):
    # Define the filter and update operation
    filter_query = {'_id': current_user['_id']}
    update_query = {'$set': {'tests': []}}

    # Perform the update operation
    result = users_collection.update_one(filter_query, update_query)

    if result.modified_count > 0:
        return jsonify({'message': 'All tests deleted successfully'}), 200
    else:
        return jsonify({'error': 'Failed to delete tests'}), 500

# --------------- gemini -------------------------

genai.configure(api_key=app.config['GOOGLE_API_KEY'])
model = genai.GenerativeModel("gemini-1.5-flash")

@app.route('/api/ask-gemini', methods=['POST'])
def generate_story():
    
    data = request.get_json()
    prompt = data.get('prompt', '')

    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400
    
    fixed_prompt = "Give steps to help this user get better based on their journal content:"
    complete_prompt = f"{fixed_prompt}\n{prompt}"

    response = model.generate_content(complete_prompt)
    return jsonify({'response': response.text}), 200

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
    
# --------------- Create Journal --------------------
def generate_unique_id():
    return str(uuid.uuid4())

@app.route("/api/create_journal", methods=['POST'])
@token_required
def create_journal(current_user):
    data = request.get_json()

    if 'title' not in data or 'content' not in data:
        return jsonify({'error': 'title and content are required'}), 400

    title = data['title']
    content = data['content']
    unique_id = generate_unique_id()
    current_date = datetime.utcnow() 

    # New journal entry structure
    new_entry = {
        '_id': unique_id,
        'title': title,
        'content': content
    }

    # Check if there's already a journal for today
    journal_entry = journal_collection.find_one({
        'email': current_user['email'],
        'journal.entries.date': current_date.strftime('%d-%m-%Y')  
    })

    if journal_entry:
        # Append the new entry to the existing journal for the current date
        journal_collection.update_one(
            {'email': current_user['email'], 'journal.entries.date': current_date.strftime('%d-%m-%Y')},
            {'$push': {'journal.$.entries': new_entry}}  # Push new entry to the matching journal date
        )
    else:
        # If no journal entry exists for today, create a new journal entry
        new_journal_entry = {
            'date': current_date.strftime('%d-%m-%Y'),  # Store formatted date
            'entries': [new_entry]
        }

        # Update the user's journal array with the new journal entry
        journal_collection.update_one(
            {'email': current_user['email']},
            {'$push': {'journal': new_journal_entry}},  # Push new journal to the user's journal array
            upsert=True
        )

    return jsonify({'message': 'Journal entry created successfully!'}), 201

# ------------- Edit Journal ---------------------

@app.route("/api/edit_journal", methods=['PUT'])
@token_required
def edit_journal(current_user):
    data = request.get_json()

    if 'id' not in data or 'new_content' not in data:
        return jsonify({'error': 'id and new_content are required'}), 400

    journal_id = data['id']
    new_title = data.get('new_title')  # Optional field
    new_content = data['new_content']
    new_date = datetime.utcnow().strftime('%d-%m-%Y')  # Current date

    # Construct the update fields
    update_fields = {
        'journal.$[journal].entries.$[entry].content': new_content,
        'journal.$[journal].entries.$[entry].date': new_date
    }
    if new_title:
        update_fields['journal.$[journal].entries.$[entry].title'] = new_title

    # Perform the update
    result = journal_collection.update_one(
        {
            'email': current_user['email'],
            'journal.entries._id': journal_id  # Locate the journal entry by its unique ID
        },
        {
            '$set': update_fields
        },
        array_filters=[
            {'journal.date': {'$eq': datetime.utcnow().strftime('%d-%m-%Y')}},  # Match journal entry by date
            {'entry._id': journal_id}  # Match the specific entry by ID
        ]
    )

    if result.matched_count == 0:
        return jsonify({'error': 'Journal entry not found or does not match the user'}), 404

    return jsonify({'message': 'Journal entry updated successfully with new date!'}), 200

# ------------ Get journals -----------------------

@app.route("/api/get-journals", methods=['POST'])
@token_required
def get_journals(current_user):
    # Ensure the request body is valid JSON, even if empty
    try:
        data = request.get_json(silent=True) or {}
    except:
        return jsonify({'error': 'Invalid JSON format'}), 400

    # Get 'year', 'month', and 'day' from the request (all optional)
    year = data.get('year')
    month = data.get('month')
    day = data.get('day')

    # Case 1: No filters provided, return all journals
    if not year and not month and not day:
        all_journals = journal_collection.find_one({
            'email': current_user['email'] 
        })

        if all_journals and 'journal' in all_journals:
            return jsonify({'journals': all_journals['journal']}), 200
        else:
            return jsonify({'message': 'No journals found for this user'}), 404

    # Case 2: Return all months and their journals for the selected year
    elif year and not month and not day:
        journal_entries = journal_collection.find_one({
            'email': current_user['email'], 
            'journal.date': {
                '$regex': f'.*-.*-{year}$'  # Match year in 'dd-mm-yyyy' format
            }
        })

        if journal_entries:
            # Extract journals grouped by months
            months_with_journals = {}
            for entry in journal_entries['journal']:
                entry_month = entry['date'].split('-')[1]
                if entry_month not in months_with_journals:
                    months_with_journals[entry_month] = []
                months_with_journals[entry_month].append(entry)

            return jsonify({'months': months_with_journals}), 200
        else:
            return jsonify({'message': f'No journal entries found for {year}'}), 404

    # Case 3: Return all days and their journals for the selected month in the selected year
    elif year and month and not day:
        journal_entries = journal_collection.find_one({
            'email': current_user['email'],
            'journal.date': {
                '$regex': f'.*-{month}-{year}$'  # Match month and year in 'dd-mm-yyyy' format
            }
        })

        if journal_entries:
            # Extract journals grouped by days in the month
            days_with_journals = {}
            for entry in journal_entries['journal']:
                entry_day = entry['date'].split('-')[0]
                if entry_day not in days_with_journals:
                    days_with_journals[entry_day] = []
                days_with_journals[entry_day].append(entry)

            return jsonify({'days': days_with_journals}), 200
        else:
            return jsonify({'message': f'No journal entries found for {month}-{year}'}), 404

    # Case 4: Return journal entries for the specific day in the selected month and year
    elif year and month and day:
        date = f'{day}-{month}-{year}'
        journal_entry = journal_collection.find_one({
            'email': current_user['email'],
            'journal': {
                '$elemMatch': {'date': date}
            }
        })

        if journal_entry:
            # Filter the journal entries to return only the entries with the matching date
            filtered_journals = [entry for entry in journal_entry['journal'] if entry['date'] == date]
            return jsonify({'journals': filtered_journals}), 200
        else:
            return jsonify({'message': f'No journal entries found for {date}'}), 404

    # If no year is provided, return an error
    else:
        return jsonify({'error': 'Year is required to fetch journals'}), 400
    
# ------------------------------------- The End :) ------------------------

if __name__ == '__main__':
    scheduler.init_app(app)
    scheduler.start()
    app.run(debug=True)
