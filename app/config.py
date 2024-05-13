import os
import sys
from dotenv import load_dotenv

# Ensure stdout uses UTF-8 encoding to handle non-ASCII characters
sys.stdout.reconfigure(encoding='utf-8')

# Load environment variables from .env file in the instance folder
dotenv_path = os.path.join(os.path.dirname(__file__), '../instance/.env')
print(f"Loading environment variables from: {dotenv_path}")
load_dotenv(dotenv_path)

print(f"SECRET_KEY: {os.getenv('SECRET_KEY')}")
print(f"DATABASE_USERNAME: {os.getenv('DATABASE_USERNAME')}")
print(f"DATABASE_PASSWORD: {os.getenv('DATABASE_PASSWORD')}")
print(f"DATABASE_HOST: {os.getenv('DATABASE_HOST')}")
print(f"DATABASE_NAME: {os.getenv('DATABASE_NAME')}")

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{os.getenv('DATABASE_USERNAME')}:{os.getenv('DATABASE_PASSWORD')}@{os.getenv('DATABASE_HOST')}/{os.getenv('DATABASE_NAME')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# Development configuration
class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True

# Production configuration
class ProductionConfig(Config):
    DEBUG = False

# Setup the config to use
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

print(f"Database URI: {Config.SQLALCHEMY_DATABASE_URI}")
