from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from .models import User, Session
from app.hashing import HashPass
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from . import db
import random
import string




main = Blueprint('main', __name__)

round = 7

session_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=round))


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
        new_user = User(email, has, firstName, lastName, userName)
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
    ip = str(request.remote_addr)

    try:
        check_user = User.query.filter_by(email=email).first()
        if not check_user:
            return jsonify({'message': 'User not found', 'code' : '202'}), 202

        user = HashPass.check_password(check_user.password, password)
        if user:
            access_token = create_access_token(identity=check_user.id)
            insert_session = Session(add_session_string, access_token, ip)
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
    print(valid)
    if valid:
        return jsonify({'message': 'true'}), 200
    else:
        return jsonify({'message': 'false'}), 200





@main.route("/get", methods=['GET'])
def give_mes():
    ip = str(request.remote_addr)
    auth_header = request.headers.get('Authorization')
    auth_header_startSwitch = auth_header.startswith('Bearer ')

    token = auth_header.split(' ')[1]
    ses = Session.query.filter_by(session_string=token).first()
    if ses and auth_header_startSwitch and ses.ip == ip:
        return jsonify({'message': 'User found', 'email': ses.jwt})
    else:
        return jsonify({'message': 'User not found'}), 404
