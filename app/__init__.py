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
# Create a logging handler that writes to sys.stderr with utf-8 encoding
handler = logging.StreamHandler(sys.stderr)
handler.setLevel(logging.INFO)  # Set the logging level you need
handler.setFormatter(logging.Formatter('%(message)s'))
handler.stream = open(handler.stream.fileno(), mode='w', encoding='utf-8', buffering=1)

# Add this handler to the root logger
logging.basicConfig(handlers=[handler], level=logging.INFO)

# Alternatively, if you want to set it directly:
logger = logging.getLogger()
logger.addHandler(handler)

db = SQLAlchemy(app)
mail = Mail(app)
jwt = JWTManager(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'  # The view to redirect to when login is required

from . import routes, models

@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))
    
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])