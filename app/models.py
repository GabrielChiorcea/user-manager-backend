from . import db
from sqlalchemy import Column, Integer, String, ForeignKey
from flask_sqlalchemy import SQLAlchemy


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    last_name = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __init__(self, username, email, last_name, first_name, password):
        self.username = username
        self.email = email
        self.last_name = last_name
        self.first_name = first_name
        self.password = password

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_string = db.Column(db.String(255))
    jwt = db.Column(db.Text, nullable=False)

    def __init__(self, session_string, jwt):
        self.session_string = session_string
        self.jwt = jwt

class ProfileCard(db.Model):
    __tablename__ = 'profile_card'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    occupation = db.Column(db.String(255))
    homeaddress = db.Column(db.String(255))
    country = db.Column(db.String(255))
    county = db.Column(db.String(255))
    image = db.Column(db.LargeBinary)  # Use LargeBinary for storing large binary data


    def __init__(self, occupation, homeaddress, country, county, user_id, image):
        self.occupation = occupation
        self.homeaddress = homeaddress
        self.country = country
        self.county = county
        self.user_id = user_id
        self.image = image



class SocialLinks(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    linkedin = db.Column(db.String(255))
    facebook = db.Column(db.String(255))
    github = db.Column(db.String(255))
    instagram = db.Column(db.String(255))
    twitter = db.Column(db.String(255))
    youtube = db.Column(db.String(255))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, ForeignKey("users.id"))

    def __init__(self, linkedin, facebook, github, instagram, twitter, youtube, description, user_id):
        self.linkedin = linkedin
        self.facebook = facebook
        self.github = github
        self.instagram = instagram
        self.twitter = twitter
        self.youtube = youtube
        self.description = description
        self.user_id = user_id