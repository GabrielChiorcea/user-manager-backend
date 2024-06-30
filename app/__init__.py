from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
bcrypt = Bcrypt()



def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://gabi_remo:Eva1Japo2@gabrielchiorcea.eu/gabi_remote'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    
    bcrypt.init_app(app)


    with app.app_context():
        db.create_all()

    from .routes import main
    app.register_blueprint(main)
    CORS(app)
    return app
