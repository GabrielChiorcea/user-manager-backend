from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://gabi_remo:Eva1Japo2@gabrielchiorcea.eu/gabi_remote'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    

    from .routes import main
    app.register_blueprint(main)
    CORS(app)
    return app
