from datetime import datetime
from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from .models import User
from app.hashing import HashPass
from . import db



main = Blueprint('main', __name__)




@main.route('/creare-cont' , methods=['POST'])
def insert_data():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    firstName = data.get('firstName')
    lastName = data.get('lastName')

    try: 
        has = HashPass.passwordHash(password) #password is hashed
        new_user = User(email, has, firstName, lastName)
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

    try:
        check_user = User.query.filter_by(email = email).first()
        validate =  HashPass.check_password(check_user.password, password)
        if(validate and check_user.email == email):
            return jsonify({'message': 'Password is the same'}), 200
        else:
            return jsonify({'message': 'Password or email are incorect' }), 404
    
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e) }), 200


        
