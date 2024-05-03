from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from .config import config  # Make sure this import correctly points to your config file's location

app = Flask(__name__)
app.config.from_object(config['development'])  # Explicitly setting to development config

db = SQLAlchemy(app)

from . import routes
