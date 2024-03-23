from flask import Flask, request, jsonify
from model import db, User
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_ngrok import run_with_ngrok
from flask_bcrypt import Bcrypt

app = Flask(__name__)
run_with_ngrok(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)


@app.route("/register", methods=['POST'])
def register_user():
    data = request.json
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone_no = data.get('phone_no')
    password = data.get('password')
    if not all([email, first_name, last_name, phone_no, password]):
        return jsonify({'error': 'All fields need to be provided'})
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'User with this email already exists'})
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, first_name=first_name, last_name=last_name,
                    phone_no=phone_no, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(phone_no=data['phone_no']).first()
    if not user:
        return jsonify({'message': 'User not found'})
    if bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'first_name': user.first_name,'last_name' : user.last_name, 'email': user.email , 'phone_no' : user.phone_no})
        return jsonify({'access_token': access_token})
    else:
        return jsonify({'message': 'Invalid credentials'})

@app.route('/retrieve/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify({'user_id': user.user_id, 'first_name': user.first_name, 'last_name': user.last_name, 'phone_no': user.phone_no, 'email': user.email})
    else:
        return jsonify({'message': 'User not found'})

@app.route("/update/<int:user_id>", methods=['PUT'])
@jwt_required()
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'})
    data = request.json
    user.email = data.get('email', user.email)
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.phone_no = data.get('phone_no', user.phone_no)
    db.session.commit()
    return jsonify({'message': 'User updated successfully'})

@app.route("/delete/<int:user_id>", methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'})


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()


