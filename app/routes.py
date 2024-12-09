from flask import Blueprint, request, jsonify, render_template
from sqlalchemy.exc import SQLAlchemyError
from .models import User, Session, ProfileCard, SocialLinks
from app.hashing import HashPass
from flask_jwt_extended import create_access_token
from . import db
import random
import string
import jwt
import datetime
from flask import current_app as app
import base64




main = Blueprint('main', __name__)

round = 7

session_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=round))


@main.route('/')
def online():
    return render_template('status.html')

@main.route('/creare-cont' , methods=['POST'])
def insert_data():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    firstName = data.get('firstName')
    lastName = data.get('lastName')
    userName = data.get('username')

    try: 
        has = HashPass.passwordHash(password) #password is hashed
        new_user = User( userName, email, lastName, firstName , has)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': "The user account is create with succes"}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    

    

@main.route("/intra-in-cont", methods=["POST"])
def sing_up():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    add_session_string = session_string

    try:
        check_user = User.query.filter_by(email=email).first()
        if not check_user:
            return jsonify({'message': 'User not found', 'code' : '202'}), 202

        user = HashPass.check_password(check_user.password, password)
        if user:
            access_token = create_access_token(identity=check_user.id, expires_delta=datetime.timedelta(days=1))    
            insert_session = Session(add_session_string, access_token)
            dummy_profile = ProfileCard(
                occupation="May I ask you what do you do?",
                homeaddress="How far are you ?",
                country="I guess you are from Nice ?",
                county="France ?",
                user_id=check_user.id,
                image=b""  # Assuming image is stored as binary data
            )
            dummy_social_links = SocialLinks(
                linkedin="https://linkedin.com/",
                facebook="https://facebook.com/",
                github="https://github.com/",
                instagram="https://instagram.com/",
                twitter="https://twitter.com/",
                youtube="https://youtube.com/",
                description="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
                user_id=check_user.id
            )            

            db.session.add(insert_session)
            db.session.commit()

            db.session.add(dummy_profile)
            db.session.commit()

            db.session.add(dummy_social_links)
            db.session.commit()
            return jsonify({'message': add_session_string, "code" : "200"}), 200
        else:   
            return jsonify({'message': 'Password or user are incorrect', "code": "202"}), 202
    


    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500    




@main.route("/checkUserAndEmailForAvailability", methods=["POST"])
def checkEmailForAvailability_db():
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")

    valid = None

    if email:
        valid = User.query.filter_by(email=email).first()
    elif username:
        valid = User.query.filter_by(username=username).first()
    else:
        return jsonify({'message': 'Email or username must be provided'}), 400
    if valid:
        return jsonify({'message': 'true'}), 200
    else:
        return jsonify({'message': 'false'}), 200


@main.route("/setContactDetail", methods=['POST'])
def setContactDetailDb():
    data = request.get_json()

    image = data.get("image")
    occupation = data.get("occupation")
    homeaddress = data.get("homeAddress")
    country = data.get("country")
    county = data.get("county")
    image_binary = base64.b64decode(image)
    secret_key = app.config['JWT_SECRET_KEY']
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]

    try:
        ses = Session.query.filter_by(session_string=token).first()
        if ses:
            try:
                decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["HS256"])
                user_id = decoded_token.get('sub')
            except jwt.DecodeError:
                return jsonify({'error': 'Invalid token format'}), 400
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError as e:
                return jsonify({'error': 'Invalid token', 'message': str(e)}), 401

            try:
                # Retrieve the existing profile
                profile = ProfileCard.query.filter_by(user_id=user_id).first()
                if profile:
                    # Update the existing profile with real data
                    profile.occupation = occupation
                    profile.homeaddress = homeaddress
                    profile.country = country
                    profile.county = county
                    profile.image = image_binary
                else:
                    # Create a new profile if it doesn't exist
                    profile = ProfileCard(occupation, homeaddress, country, county, user_id, image_binary)
                    db.session.add(profile)

                db.session.commit()
            except SQLAlchemyError as e:
                db.session.rollback()
                return jsonify({'error': str(e)}), 500

            return jsonify({'message': 'Contact details set successfully'}), 200
        else:
            return jsonify({'message': 'Session not found'}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 400


@main.route("/setSocialLink", methods=['POST'])
def setSocialLinkDb():
    data = request.get_json()
    secret_key = app.config['JWT_SECRET_KEY']
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]

    try:
        ses = Session.query.filter_by(session_string=token).first()
        if ses:
            try:
                decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["HS256"])
                user_id = decoded_token.get('sub')
            except jwt.DecodeError:
                return jsonify({'error': 'Invalid token format'}), 400
            except jwt.ExpiredSignatureError:
                return jsonify({'error': 'Token has expired'}), 401
            except jwt.InvalidTokenError as e:
                return jsonify({'error': 'Invalid token', 'message': str(e)}), 401

            # Retrieve the existing social links
            social_links = SocialLinks.query.filter_by(user_id=user_id).first()

            if social_links:
                # Update the existing social links with new data
                social_links.linkedin = data.get("linkedIn", social_links.linkedin)
                social_links.facebook = data.get("faceBook", social_links.facebook)                
                social_links.github = data.get("gitHub", social_links.github)            
                social_links.instagram = data.get("instagram", social_links.instagram)            
                social_links.twitter = data.get("twitter", social_links.twitter)                
                social_links.youtube = data.get("youtube", social_links.youtube)
                social_links.description = data.get("description", social_links.description)
                
            else:
                # Create new social links if they don't exist
                social_links = SocialLinks(
                    linkedin=data.get("linkedin", ""),
                    facebook=data.get("facebook", ""),
                    github=data.get("github", ""),
                    instagram=data.get("instagram", ""),
                    twitter=data.get("twitter", ""),
                    youtube=data.get("youtube", ""),
                    description=data.get("description", ""),
                    user_id=user_id
                )
                db.session.add(social_links)

            db.session.commit()

            return jsonify({'message': 'Social links updated successfully'}), 200
        else:
            return jsonify({'message': 'Session not found'}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@main.route("/get", methods=['GET'])
def get_profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Authorization header is missing'}), 401
    
    token = auth_header.split(' ')[1]
    secret_key = app.config['JWT_SECRET_KEY']
    
    ses = Session.query.filter_by(session_string=token).first()
    if not ses:
        return jsonify({'error': 'Session not found'}), 401
    
    try:
        decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["HS256"])
        user_id = decoded_token.get('sub')  # Extract user ID from 'sub' key
    except jwt.DecodeError as e:
        return jsonify({'error': 'Invalid token format', 'message': str(e)}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
    
    profile = ProfileCard.query.filter_by(user_id=user_id).first()
    social_links = SocialLinks.query.filter_by(user_id=user_id).first()
    user = User.query.filter_by(id=user_id).first()
    if not profile:
        return jsonify({'error': 'Profile or user not found'}), 404
    image_base64 = base64.b64encode(profile.image).decode('utf-8')
    return jsonify({
        'HomeAddress': profile.homeaddress,
        'Country': profile.country,
        'County': profile.county,
        'Occupation': profile.occupation,
        'Image': image_base64,  # Assuming image is stored as binary data
        'FullName': ' '.join([user.first_name, user.last_name]),
        'Email': user.email,
        'LinkedIn': social_links.linkedin,
        'FaceBook': social_links.facebook,
        'GitHub': social_links.github,
        'Instagram': social_links.instagram,
        'Twitter': social_links.twitter,
        'Youtube': social_links.youtube,
        'Description': social_links.description

    }), 200


@main.route("/changePassword", methods=['POST'])
def change_password():
    data = request.get_json()
    current_password = data.get("currentPassword")
    new_password = data.get("newPassword")
    secret_key = app.config['JWT_SECRET_KEY']
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]

    try:
        ses = Session.query.filter_by(session_string=token).first()
        decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["HS256"])
        user_id = decoded_token.get('sub')

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Verify the current password
        if not HashPass.check_password(user.password, current_password):
            return jsonify({'message': 'Current password is incorrect'}), 400

        # Update the password
        user.password = HashPass.passwordHash(new_password)
        db.session.commit()

        return jsonify({'message': 'Password changed successfully'}), 200
    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token format'}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    


@main.route("/changeEmail", methods=['POST'])
def change_email():
    data = request.get_json()
    new_email = data.get("newEmail")
    secret_key = app.config['JWT_SECRET_KEY']
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]

    try:
        ses = Session.query.filter_by(session_string=token).first()
        decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["HS256"])
        user_id = decoded_token.get('sub')

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Update the email
        user.email = new_email
        db.session.commit()

        return jsonify({'message': 'Email changed successfully'}), 200
    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token format'}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    



@main.route("/changeUsername", methods=['POST'])
def change_username():
    data = request.get_json()
    new_username = data.get("userName")
    secret_key = app.config['JWT_SECRET_KEY']
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]

    try:
        ses = Session.query.filter_by(session_string=token).first()
        decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["HS256"])
        user_id = decoded_token.get('sub')

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Check if the new username already exists
        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            return jsonify({'message': 'Username already taken'}), 400

        # Update the username
        user.username = new_username
        db.session.commit()

        return jsonify({'message': 'Username changed successfully'}), 200
    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token format'}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    

@main.route("/deleteAccount", methods=['DELETE'])
def delete_account():
    secret_key = app.config['JWT_SECRET_KEY']
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]

    try:
        ses = Session.query.filter_by(session_string=token).first()
        decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["HS256"])
        print(decoded_token)
        user_id = decoded_token.get('sub')
        print(user_id)

        user = User.query.filter_by(id=user_id).first()
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Delete related records
        ProfileCard.query.filter_by(user_id=user_id).delete()
        SocialLinks.query.filter_by(user_id=user_id).delete()

        # Delete the user record
        db.session.delete(user)
        db.session.commit()

        return jsonify({'message': 'Account deleted successfully'}), 200
    except jwt.DecodeError:
        return jsonify({'error': 'Invalid token format'}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500