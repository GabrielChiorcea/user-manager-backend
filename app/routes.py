from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from .models import User, UniqueIdentify
from app.hashing import HashPass
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from . import db, jwt




main = Blueprint('main', __name__)




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
        new_identify = UniqueIdentify(email, userName)
        db.session.add(new_user)
        db.session.commit()
        db.session.add(new_identify)
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

    try:
        check_user = User.query.filter_by(email = email).first()
        user =  HashPass.check_password(check_user.password, password)
        if(user and check_user.email == email):
            access_tocken = create_access_token(identity=check_user.id)
            return jsonify({'message': access_tocken}), 200
        else:
            return jsonify({'message': 'Password or email are incorect' }), 404
    
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e) }), 200
    


@main.route("/checkUserAndEmailForAvailability", methods=["POST"])
def checkEmailForAvailability_db():
    data = request.get_json()
    email = data.get("email")
    username = data.get("username")

    valid = None

    if email:
        valid = UniqueIdentify.query.filter_by(email=email).first()
    elif username:
        valid = UniqueIdentify.query.filter_by(username=username).first()
    else:
        return jsonify({'message': 'Email or username must be provided'}), 400
    print(valid)
    if valid:
        return jsonify({'message': 'true'}), 200
    else:
        return jsonify({'message': 'false'}), 200



@main.route("/get", methods=['GET'])
@jwt_required()
def give_mes():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    if user:
        return jsonify({'message': 'User found', 'name': user.email})
    else:
        return jsonify({'message': 'User not found'}), 404