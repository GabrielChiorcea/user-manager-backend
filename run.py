from app import create_app, db
from flask_cors import CORS

app = create_app()
CORS(app, origins=["*"], supports_credentials=True, methods=["GET", "POST", "PUT", "DELETE"])

with app.app_context():
    db.create_all()

main = app



if __name__ == '__main__':
    app.run(debug=True, port= 3000)