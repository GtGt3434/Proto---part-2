import os

class Config:
    SECRET_KEY = 'your_secret_key'  # Change to a real secret key
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root@localhost/charity_platform'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# development configuration
class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True

# production configuration
class ProductionConfig(Config):
    DEBUG = False

# Setup the config to use
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
