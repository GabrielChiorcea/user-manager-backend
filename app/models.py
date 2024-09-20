from . import db
from sqlalchemy import Column, Integer, String, ForeignKey


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), unique= True, nullable=False)
    firstName = db.Column(db.String(255), nullable=False)
    lastName = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)

    def __init__(self, email, password,firstName, lastName, username):
        self.email = email
        self.password = password
        self.firstName = firstName
        self.lastName = lastName
        self.username = username



class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_string = db.Column(db.String(255), unique=True, nullable=False)
    jwt = db.Column(db.String(255), unique=True, nullable=False)

    def __init__(self, session_string, jwt, ip):
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

    def __init__(self, occupation, homeaddress, country, county, user_id, image ):
        self.occupation = occupation
        self.homeaddress = homeaddress
        self.country = country
        self.county = county
        self.user_id = user_id
        self.image = image



