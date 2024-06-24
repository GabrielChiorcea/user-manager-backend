from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from .models import User
from . import db



main = Blueprint('main', __name__)




@main.route('/sing-up' , methods=['POST'])
def insert_data():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    try:
        new_user = User(email, password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User added successfully'}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    

    

@main.route("/login", methods=["POST"])
def sing_up():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    try:
        check_user = User.query.filter_by(email = email).first()
        if (email == check_user.email and password == check_user.password ):
            return jsonify({'message': 'User exits'}), 200
        else:
            return jsonify({'message': 'User dot not exits'}), 404
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e) }), 200
