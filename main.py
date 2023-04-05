from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from starlette import status
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional

app = Flask(__name__)
bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app.config['SECTRET_KEY'] = os.getenv('MY_SECTRET_KEY')
base_dir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'project.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    hashed_password = db.Column(db.String(200), nullable=False)
    entries = db.relationship('Entries', backref='user', lazy=True)


class Entries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    native_english_speaker = db.Column(db.Boolean)
    course_instructor = db.Column(db.Integer)
    course = db.Column(db.Integer)
    summer_semester = db.Column(db.Boolean)
    class_size = db.Column(db.Integer)
    score = db.Column(db.Integer)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))


with app.app_context():
    db.create_all()


@app.route("/create_user", methods=['POST'])
def create_user():
    login_info = request.json
    if not login_info or len(login_info['username']) < 5 or len(login_info['password']) < 5:
        return {
            "Message": "Invalid input. Username and Password must have at least 5 characters each.",
            "status_code": status.HTTP_400_BAD_REQUEST
        }
    new_user = Users()
    new_user.username = request.json['username']
    new_user.hashed_password = get_hashed_password(request.json['password'])
    db.session.add(new_user)
    db.session.commit()
    return {
        "message": "Successful",
        "status_code": status.HTTP_201_CREATED
    }


@app.route("/login", methods=["POST"])
def login():
    given_username = request.json['username']
    given_password = request.json['password']
    if not given_username or not given_password:
        return token_exception()
    user = Users.query.filter(Users.username == given_username).first()
    if not user or not verify_password(given_password, user.hashed_password):
        return token_exception()
    token_expires = timedelta(minutes=20)
    token = create_access_token(user.username, user.id, expires_delta=token_expires)
    return {
        "status_code": status.HTTP_200_OK,
        "message": "This token will be necessary for authorization to add new entries.",
        "token": token
    }


@app.route("/delete_user", methods=["DELETE"])
def delete_user():
    auth_header = request.headers.get('Authorization')
    token = confirm_auth_header(auth_header)
    user_details = get_current_user(token)
    user_id = user_details.get('id')
    entries = Entries.query.filter(Entries.owner_id == user_id).all()
    for entry in entries:
        db.session.delete(entry)
        db.session.commit()
    user = Users.query.filter(Users.id == user_id).first()
    db.session.delete(user)
    db.session.commit()
    return jsonify({
        "message": "successful",
        "status_code": status.HTTP_204_NO_CONTENT
    })


@app.route("/entries", methods=["GET"])
def get_entries():
    auth_header = request.headers.get('Authorization')
    token = confirm_auth_header(auth_header)
    user_details = get_current_user(token)
    user_id = user_details.get('id')
    entries = Entries.query.filter(Entries.owner_id == user_id).all()
    list_of_entries = jsonify([dictify_entry(entry) for entry in entries])
    return list_of_entries


@app.route("/add_entry", methods=["POST"])
def add_entry():
    auth_header = request.headers.get('Authorization')
    token = confirm_auth_header(auth_header)
    user_details = get_current_user(token)
    user_id = user_details.get('id')
    entry = request.json
    if not entry:
        return jsonify({'message': 'Invalid entry fields.'})
    if authenticate_entry(entry):
        return authenticate_entry(entry)
    new_entry = Entries()
    new_entry.owner_id = user_id
    new_entry.native_english_speaker = entry['native_english_speaker']
    new_entry.course_instructor = entry['course_instructor']
    new_entry.course = entry['course']
    new_entry.summer_semester = entry['summer_semester']
    new_entry.class_size = entry['class_size']
    new_entry.score = entry['score']
    db.session.add(new_entry)
    db.session.commit()
    return {
        "message": "Successful",
        "status_code": status.HTTP_201_CREATED
    }


@app.route("/update_entry/<int:entry_id>", methods=["PUT"])
def update_entry(entry_id):
    auth_header = request.headers.get('Authorization')
    token = confirm_auth_header(auth_header)
    user_details = get_current_user(token)
    user_id = user_details.get('id')
    entry_to_update = Entries.query.filter(Entries.id == entry_id).first()
    if not entry_to_update:
        return jsonify({"failed": "Entry does not exist.",
                        "status_code": status.HTTP_404_NOT_FOUND})
    if entry_to_update.owner_id != user_id:
        return jsonify({
            "status_code": status.HTTP_401_UNAUTHORIZED,
            "message": "Entry belongs to different user."
                        })
    updated_entry = request.json
    if not updated_entry:
        return jsonify({'message': 'Invalid entry fields.'})
    if authenticate_entry(updated_entry):
        return authenticate_entry(updated_entry)
    entry_to_update.owner_id = user_id
    entry_to_update.native_english_speaker = updated_entry['native_english_speaker']
    entry_to_update.course_instructor = updated_entry['course_instructor']
    entry_to_update.course = updated_entry['course']
    entry_to_update.summer_semester = updated_entry['summer_semester']
    entry_to_update.class_size = updated_entry['class_size']
    entry_to_update.score = updated_entry['score']
    db.session.add(entry_to_update)
    db.session.commit()
    return jsonify({
        "message": "successful",
        "status_code": status.HTTP_204_NO_CONTENT
    })


@app.route("/delete_entry/<int:entry_id>", methods=["DELETE"])
def delete_entry(entry_id):
    auth_header = request.headers.get('Authorization')
    token = confirm_auth_header(auth_header)
    user_details = get_current_user(token)
    user_id = user_details.get('id')
    entry_to_delete = Entries.query.filter(Entries.id == entry_id).first()
    if not entry_to_delete:
        return jsonify({"failed": "Entry does not exist."})
    if entry_to_delete.owner_id != user_id:
        return jsonify({
            "status_code": status.HTTP_401_UNAUTHORIZED,
            "message": "Entry belongs to different user."
        })
    db.session.delete(entry_to_delete)
    db.session.commit()
    return jsonify({
        "message": "successful",
        "status_code": status.HTTP_204_NO_CONTENT
    })


def dictify_entry(entry: Entries):
    res = {
        'id': entry.id,
        'native_english_speaker': entry.native_english_speaker,
        'course_instructor': entry.course_instructor,
        'course': entry.course,
        'summer_semester': entry.summer_semester,
        'class_size': entry.class_size,
        'score': entry.score
    }
    return res


field_dict = {
    "course_instructor": "1-25 (int)",
    "course": "1-26 (int)",
    "class_size": "> 0 (int)",
    "summer_semester": "true/false (boolean)",
    "score": "1-3 (int)"
}

input_error_message = {
                "message": "Invalid inputs",
                "input fields and ranges": field_dict
            }


def authenticate_entry(entry):
    if entry['course_instructor']:
        if not 0 < entry['course_instructor'] < 26:
            return jsonify(input_error_message)
    if entry['course']:
        if not 0 < entry['course'] < 27:
            return jsonify(input_error_message)
    if entry['course_instructor']:
        if not 0 < entry['course_instructor'] < 26:
            return jsonify(input_error_message)

    if entry['class_size']:
        if not 0 < entry['class_size']:
            return jsonify(input_error_message)

    if entry['score']:
        if not 0 < entry['score'] < 4:
            return jsonify(input_error_message)
    return


def confirm_auth_header(auth_header):
    if not auth_header:
        return jsonify({'message': 'Authorization header missing'})
    parts = auth_header.split()
    if parts[0].lower() != 'bearer':
        return jsonify({'message': 'Invalid token type'})
    if len(parts) == 1:
        return jsonify({'message': 'Token missing'})
    elif len(parts) > 2:
        return jsonify({'message': 'Invalid token format'})
    token = parts[1]
    return token


def create_access_token(username: str, user_id: int,
                        expires_delta: Optional[timedelta] = None):
    encode_dict = {"sub": username, "id": user_id}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encode_dict.update({"exp": expire})
    return jwt.encode(encode_dict, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        if not username or not user_id:
            raise get_user_exception()
        return {"username": username, "id": user_id}
    except JWTError:
        raise get_user_exception()


def get_hashed_password(plain_password):
    return bcrypt_context.hash(plain_password)


def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)


def token_exception():
    exception_response = {
        "detail": "invalid username or password.",
        "status_code": status.HTTP_401_UNAUTHORIZED,
    }
    return jsonify(exception_response)


def get_user_exception():
    credentials_exception = {
        "status_code": status.HTTP_401_UNAUTHORIZED,
        "detail": "Could not validate credentials",
        "headers": {"WWW-Authenticate": "Bearer"}}
    return jsonify(credentials_exception)


if __name__ == '__main__':
    app.run(debug=True)