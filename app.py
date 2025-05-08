import os
from flask import Flask, request, jsonify ,render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import re ,random
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)

resend_timestamps = {}
# === Config ===
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

# === Extensions ===
db = SQLAlchemy(app)
jwt = JWTManager(app)
mail = Mail(app)

# === Model ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), nullable=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[!@#$%^&*()_+=\-]", password)
    )

# --- Frontend routes ---
@app.route('/')
def home():
    return render_template('register.html')

@app.route('/verify-form')
def verify_form():
    return render_template('verify.html')

@app.route('/login-form')
def login_form():
    return render_template('login.html')

@app.route('/profile-form')
@jwt_required()
def profile_form():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return render_template('profile.html', user=user)


# --- API routes ---
@app.route('/register', methods=['POST'])
def register():
    data = request.form

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already exists'}), 400

    if not is_strong_password(data['password']):
        return jsonify({
            'message': 'Password must be at least 8 characters long and include upper, lower, digit, and special character.'
        }), 400

    user = User(name=data['name'], email=data['email'])
    user.set_password(data['password'])
    user.verification_code = str(random.randint(100000, 999999))
    db.session.add(user)
    db.session.commit()

    msg = Message("Verify your email", recipients=[user.email])
    msg.body = f"Your verification code is: {user.verification_code}"
    mail.send(msg)

    return jsonify({'message': 'Registered. Check your email to verify.'})

@app.route('/verify', methods=['POST'])
def verify_email():
    data = request.form
    user = User.query.filter_by(email=data['email']).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if user.verification_code != data['code']:
        return jsonify({'message': 'Invalid code'}), 400

    user.is_verified = True
    user.verification_code = None
    db.session.commit()

    # Send welcome message
    msg = Message("Welcome!", recipients=[user.email])
    msg.body = f"Hi {user.name}, your email has been verified. Welcome aboard!"
    mail.send(msg)

    return jsonify({'message': 'Email verified successfully'})

@app.route('/resend-code', methods=['POST'])
def resend_code():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    now = datetime.utcnow()
    last_sent = resend_timestamps.get(email)

    if last_sent and now - last_sent < timedelta(seconds=30):
        return jsonify({'message': 'Please wait before requesting another code'}), 429

    user.verification_code = str(random.randint(100000, 999999))
    db.session.commit()

    msg = Message("Your New Verification Code", recipients=[email])
    msg.body = f"Your new verification code is: {user.verification_code}"
    mail.send(msg)

    resend_timestamps[email] = now

    return jsonify({'message': 'New code sent'})


@app.route('/login', methods=['POST'])
def login():
    data = request.form
    user = User.query.filter_by(email=data['email']).first()
    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    if not user.is_verified:
        return jsonify({'message': 'Email not verified'}), 403

    token = create_access_token(identity=str(user.id), expires_delta=False)
    return jsonify({'token': token})

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"msg": "User not found"}), 404

    return jsonify({
        "name": user.name,
        "email": user.email
    })

# === Init DB ===
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
