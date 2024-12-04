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
        new_user = User(email, userName, lastName, firstName , has)
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
                occupation="N/A",
                homeaddress="N/A",
                country="N/A",
                county="N/A",
                user_id=check_user.id,
                image=b""  # Assuming image is stored as binary data
            )
            dummy_social_links = SocialLinks(
                linkedin="https://linkedin.com/dummy",
                facebook="https://facebook.com/dummy",
                github="https://github.com/dummy",
                instagram="https://instagram.com/dummy",
                twitter="https://twitter.com/dummy",
                youtube="https://youtube.com/dummy",
                description="N/A",
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
                social_links.linkedin = data.get("linkedin", social_links.linkedin)
                social_links.facebook = data.get("facebook", social_links.facebook)
                social_links.github = data.get("github", social_links.github)
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
        print(f"Decoded token: {decoded_token}")  # Debugging statement
        user_id = decoded_token.get('sub')  # Extract user ID from 'sub' key
        print(f"User ID: {user_id}")  # Debugging statement
    except jwt.DecodeError as e:
        return jsonify({'error': 'Invalid token format', 'message': str(e)}), 400
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
    
    profile = ProfileCard.query.filter_by(user_id=user_id).first()
    social_links = SocialLinks.query.filter_by(user_id=user_id).first()
    print(f"Profile: {social_links.github}")  # Debugging statement
    # profile_with_links = db.session.query(ProfileCard, SocialLinks).filter(
    #         ProfileCard.user_id == user_id,
    #         SocialLinks.user_id == user_id
    #    ).all()
    if not profile:
        return jsonify({'error': 'Profile or user not found'}), 404
    # Convert binary data to base64-encoded string
    image_base64 = base64.b64encode(profile.image).decode('utf-8')
    return jsonify({
        'HomeAddress': profile.homeaddress,
        'Country': profile.country,
        'County': profile.county,
        'Occupation': profile.occupation,
        'Image': image_base64,  # Assuming image is stored as binary data
        'LinkedIn': social_links.linkedin,
        'FaceBook': social_links.facebook,
        'GitHub': social_links.github,
        'Instagram': social_links.instagram,
        'Twitter': social_links.twitter,
        'Youtube': social_links.youtube,
        'Description': social_links.description

    }), 200

