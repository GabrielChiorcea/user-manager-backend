from . import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), unique= True, nullable=False)
    firstName = db.Column(db.String(255), nullable=False)
    lastName = db.Column(db.String(255), nullable=False)
    dateOdBirth = db.Column(db.Date, nullable=False)

    def __init__(self, email, password, dateOdBirth, firstName, lastName):
        self.email = email
        self.password = password
        self.dateOdBirth = dateOdBirth
        self.firstName = firstName
        self.lastName = lastName


