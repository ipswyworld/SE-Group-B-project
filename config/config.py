import os
import secrets

class Config:
    DEBUG = False
    TESTING = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False  # Disable SQLAlchemy track modifications
    SECRET_KEY = secrets.token_hex(24)





class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'

config_by_name = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'users': UsersConfig,
}

def get_config():
    config_name = os.getenv('FLASK_ENV', 'development')
    return config_by_name.get(config_name, Config)