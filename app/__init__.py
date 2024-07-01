from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_jwt_extended import JWTManager
from .config import config

app = Flask(__name__)
app.config.from_object(config['development'])  # Explicitly setting to development config

db = SQLAlchemy(app)
mail = Mail(app)
jwt = JWTManager(app)

from . import routes
