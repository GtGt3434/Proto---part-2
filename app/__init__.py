from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from .config import config
import os
import logging
import sys

app = Flask(__name__)
app.config.from_object(config['development'])  # Explicitly setting to development config

# Set up logging to handle UTF-8
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('%(message)s'))
handler.stream = open(handler.stream.fileno(), mode='w', encoding='utf-8', buffering=1)
logging.basicConfig(handlers=[handler], level=logging.INFO)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
jwt = JWTManager(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # The view to redirect to when login is required

@login_manager.user_loader
def load_user(user_id):
    from .models import User  # Import models here to avoid circular import
    return User.query.get(int(user_id))

# Admin creation logic
def create_admin():
    from .models import User  # Import models here to avoid circular import
    admin_username = os.getenv('ADMIN_USERNAME')
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')

    if not admin_username or not admin_email or not admin_password:
        print("Admin credentials are not set in environment variables.")
        return

    # Check if admin already exists
    admin_user = User.query.filter_by(username=admin_username).first()

    if admin_user is None:
        admin_user = User(username=admin_username, email=admin_email, role='admin')
        admin_user.set_password(admin_password)
        db.session.add(admin_user)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")

# Call this function when the app starts
with app.app_context():
    db.create_all()  # Ensure tables are created
    create_admin()

from .admin import admin_bp
app.register_blueprint(admin_bp)


from . import routes  # Import routes after app and db initialization

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
