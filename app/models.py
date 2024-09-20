from . import db
from sqlalchemy import Column, Integer, String, ForeignKey
from flask_sqlalchemy import SQLAlchemy


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)

    def __init__(self, username, email):
        self.username = username
        self.email = email

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_string = db.Column(db.String(255))
    jwt = db.Column(db.String(255))

    def __init__(self, session_string, jwt):
        self.session_string = session_string
        self.jwt = jwt

class ProfileCard(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    occupation = db.Column(db.String(255))
    homeaddress = db.Column(db.String(255))
    country = db.Column(db.String(255))
    county = db.Column(db.String(255))
    user_id = db.Column(db.Integer, ForeignKey("users.id"))
    image = db.Column(db.LargeBinary)

    def __init__(self, occupation, homeaddress, country, county, user_id, image):
        self.occupation = occupation
        self.homeaddress = homeaddress
        self.country = country
        self.county = county
        self.user_id = user_id
        self.image = image



