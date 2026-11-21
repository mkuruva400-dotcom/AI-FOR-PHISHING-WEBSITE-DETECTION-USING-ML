import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'anti-phishing-shield-super-secret-key-2026')
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    DATABASE_PATH = os.path.join(BASE_DIR, 'instance', 'phishing_history.db')
    MODELS_DIR = os.path.join(BASE_DIR, 'ml_engine', 'saved_models')
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'instance', 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'bmp'}
