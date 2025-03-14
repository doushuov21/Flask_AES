import os

class Config:
    # 基础配置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 加密密钥后缀（必须是6位）
    ENCRYPTION_SUFFIX = os.environ.get('ENCRYPTION_SUFFIX') or 'aes123'
    
    @staticmethod
    def init_app(app):
        if len(Config.ENCRYPTION_SUFFIX) != 6:
            raise ValueError('ENCRYPTION_SUFFIX 必须是6位长度')

    # 邮件服务器配置
    MAIL_SERVER = 'smtp.gmail.com'  # 或其他邮件服务器
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = 'your-email@gmail.com'  # 替换为你的邮箱
    MAIL_PASSWORD = 'your-app-password'     # 替换为你的邮箱密码
    MAIL_DEFAULT_SENDER = 'your-email@gmail.com'

    # 管理员账号配置
    ADMIN_USERNAME = 'admin'
    ADMIN_PASSWORD = 'admin123'