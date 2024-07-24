from . import db

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
    ip = db.Column(db.String(15), unique=True, nullable=False)

    def __init__(self, session_string, jwt, ip):
        self.session_string = session_string
        self.jwt = jwt
        self.ip = ip