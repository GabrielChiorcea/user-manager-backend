from flask import Flask
from . import bcrypt


class HashPass():

    def __init__(self, passw):
        self.passw = passw

    def passwordHash(el):
        passw = bcrypt.generate_password_hash(el, rounds=4).decode('utf-8')
        return passw
    
    def check_password(hash, password):
        validate = bcrypt.check_password_hash(hash ,password)
        return validate

    
