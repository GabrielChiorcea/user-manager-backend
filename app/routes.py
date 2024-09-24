from flask import Blueprint, request, jsonify, render_template
from sqlalchemy.exc import SQLAlchemyError
from .models import User, Session, ProfileCard
from app.hashing import HashPass
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from . import db
import random
import string
import jwt
import datetime
from flask import current_app as app




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
            access_token = create_access_token(identity=check_user.id, )
            insert_session = Session(add_session_string, access_token)
            db.session.add(insert_session)
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

    image = data.get("Image") 
    occupation = data.get("Occupation")
    homeaddress = data.get("HomeAddress")
    country = data.get("Country")
    county = data.get("County")

    secret_key = app.config['JWT_SECRET_KEY']
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]

    ses = Session.query.filter_by(session_string=token).first()

    if ses:
        try:
            decoded_token = jwt.decode(ses.jwt, secret_key, algorithms=["RS256"])
            user_id = decoded_token.get('identity')
        except jwt.DecodeError as e:
            return jsonify({'error': 'Invalid token format', 'message': str(e), 'session' : token, 'tocken': ses.jwt, 'id': user_id, 'decoded_token': type(decoded_token)}), 400
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': 'Invalid token', 'message': str(e)}), 401
        try:
            new_profile = ProfileCard(occupation, homeaddress, country, county, user_id, image)
            db.session.add(new_profile)
            db.session.commit()
        except SQLAlchemyError as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        return jsonify({'message': 'Contact details set successfully'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404





@main.route("/get", methods=['GET'])
def give_mes():
    ip = str(request.remote_addr)
    auth_header = request.headers.get('Authorization')
    secret_key = app.config['JWT_SECRET_KEY']
    token = auth_header.split(' ')[1]
    ses = Session.query.filter_by(session_string=token).first()

    if ses and ses.ip == ip:

        decode_tocken = jwt.decode(ses.jwt, secret_key, algorithms=["RS256"])
        profile = ProfileCard.query.filter_by(user_id=decode_tocken).first()

        return jsonify({'HomeAddress': profile.homeaddress, 
                        'Country': profile.country, 
                        'County': profile.county, 
                        'Occupation': profile.occupation,
                        'Image': profile.image})
    else:
        return jsonify({'message': 'User not found'}), 404


