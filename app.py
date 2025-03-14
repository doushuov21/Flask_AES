from flask import Flask, request, jsonify, redirect, url_for, session, render_template, flash, current_app
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
from models import Registration, RegistrationStatus, Admin, APIKey, UserRole
from database import db
from routes.admin import admin_bp, login_required
from routes.user_management import user_bp
from config import Config
from functools import wraps
from flask_mail import Mail, Message
import secrets

def create_app():
    app = Flask(__name__)
    
    # 加载配置
    app.config.from_object(Config)
    Config.init_app(app)
    
    # 初始化扩展
    db.init_app(app)
    
    # 注册蓝图
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)
    
    return app

app = create_app()

# 不需要验证登录的路由
EXEMPT_ROUTES = [
    'static',
    'admin.login',
    'forgot_password',
    'reset_password',
    'register',
    'activate',
    'verify'
]

@app.before_request
def check_login():
    # 如果是豁免路由，不检查登录状态
    if request.endpoint in EXEMPT_ROUTES or (request.endpoint and any(request.endpoint.startswith(route + '.') for route in EXEMPT_ROUTES)):
        return
        
    # 检查是否登录
    if 'admin_id' not in session:
        return redirect(url_for('admin.login'))
        
    # 检查用户和密码版本
    admin = Admin.query.get(session.get('admin_id'))
    if not admin:
        session.clear()
        return redirect(url_for('admin.login'))
        
    # 检查密码版本是否匹配
    if session.get('password_version') != admin.password_version:
        session.clear()
        return redirect(url_for('admin.login'))

# 邮件配置
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 替换为你的邮件服务器
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # 替换为你的邮箱
app.config['MAIL_PASSWORD'] = 'your-password'  # 替换为你的邮箱密码

mail = Mail(app)

class AESCipher:
    def __init__(self, key):
        self.key = key.encode('utf-8')
        
    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)  # 使用ECB模式，不需要IV
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        encrypted_data = base64.b64encode(ct_bytes).decode('utf-8')
        return encrypted_data  # 直接返回加密数据，不需要IV

    def decrypt(self, encrypted_data):
        cipher = AES.new(self.key, AES.MODE_ECB)  # 使用ECB模式
        ct = base64.b64decode(encrypted_data)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('Authorization')
        if not api_key:
            return jsonify({'error': '缺少有效的 API Key'}), 401
        
        api_key_obj = APIKey.query.filter_by(key=api_key, is_active=True).first()
        if not api_key_obj:
            return jsonify({'error': '无效的 API Key'}), 401
            
        # 更新最后使用时间
        api_key_obj.last_used = datetime.now()
        db.session.commit()
        
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['POST'])
@require_api_key
def register():
    """注册新机器码
    请求参数：
    {
        "key": "32位机器码",
        "project_name": "项目名称"
    }
    响应示例：
    成功响应 (200):
    {
        "message": "注册成功，等待激活",
        "data": "加密的响应数据"
    }
    错误响应 (400):
    {
        "error": "无效的密钥长度，需要32位密钥"
    }
    """
    try:
        data = request.get_json()
        key = data.get('key')
        
        if not key or len(key) != 32:
            return jsonify({'error': '无效的密钥长度，需要32位密钥'}), 400
        
        # 查找是否已存在该key的记录
        existing_registration = Registration.query.filter_by(key=key).first()
        
        if existing_registration:
            return jsonify({'error': '该密钥已注册'}), 400
        
        # 生成5位随机编码
        random_code = ''.join(secrets.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(5))
        project_name = f"项目：{random_code}"
        
        # 创建新记录，初始状态为未激活
        registration = Registration(
            key=key,
            project_name=project_name,
            register_time=datetime.now(),
            expire_date=None,  # 初始无过期时间
            last_modified=datetime.now(),
            status=RegistrationStatus.UNACTIVATED.value
        )
        
        db.session.add(registration)
        db.session.commit()
        
        # 准备要加密的数据
        response_data = {
            'project_name': registration.project_name,
            'register_time': registration.register_time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': registration.status,
            'message': '注册成功，等待激活'
        }
        
        # 使用配置的6位后缀替换机器码后6位
        encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
        
        # 使用机器码的前16位作为IV
        iv = key[:16].encode()
        cipher = AES.new(encryption_key.encode(), AES.MODE_CBC, iv)
        
        # 加密数据
        data_str = json.dumps(response_data, ensure_ascii=False)
        padded_data = pad(data_str.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # 组合IV和加密数据
        combined_data = iv + encrypted_data
        encoded_data = base64.b64encode(combined_data).decode('utf-8')
        
        return jsonify({
            'message': '注册成功，等待激活',
            'data': {
                'encrypted_data': encoded_data
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/activate', methods=['POST'])
@require_api_key
def activate():
    """激活机器码
    请求参数：
    {
        "key": "32位机器码",
        "days": 有效期天数（-1表示永久）
    }
    响应示例：
    成功响应 (200):
    {
        "message": "激活成功",
        "data": {
            "encrypted_data": "加密的响应数据"
        }
    }
    错误响应 (404):
    {
        "error": "未找到注册信息"
    }
    """
    try:
        data = request.get_json()
        key = data.get('key')
        days = data.get('days')  # 有效期天数，如果为-1则表示永久激活
        
        if not key:
            return jsonify({'error': '缺少密钥'}), 400
            
        registration = Registration.query.filter_by(key=key).first()
        
        if not registration:
            return jsonify({'error': '未找到注册信息'}), 404
            
        now = datetime.now()
        
        if days == -1:
            # 永久激活
            registration.status = RegistrationStatus.PERMANENT.value
            registration.expire_date = None
        else:
            # 设置有效期
            registration.expire_date = now + timedelta(days=days)
            registration.status = RegistrationStatus.ACTIVATED.value
            
        registration.last_modified = now
        db.session.commit()
        
        # 准备加密响应数据
        response_data = {
            'project_name': registration.project_name,
            'status': registration.status,
            'expire_date': registration.expire_date.strftime('%Y-%m-%d %H:%M:%S') if registration.expire_date else 'permanent',
            'message': '激活成功'
        }
        
        # 使用配置的6位后缀替换机器码后6位
        encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
        
        # 使用机器码的前16位作为IV
        iv = key[:16].encode()
        cipher = AES.new(encryption_key.encode(), AES.MODE_CBC, iv)
        
        # 加密数据
        data_str = json.dumps(response_data, ensure_ascii=False)
        padded_data = pad(data_str.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # 组合IV和加密数据
        combined_data = iv + encrypted_data
        encoded_data = base64.b64encode(combined_data).decode('utf-8')
        
        return jsonify({
            'message': '激活成功',
            'data': {
                'encrypted_data': encoded_data
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify', methods=['POST'])
@require_api_key
def verify():
    """验证机器码状态
    请求参数：
    {
        "key": "32位机器码"
    }
    响应示例：
    成功响应 (200):
    {
        "message": "验证成功",
        "data": {
            "encrypted_data": "加密的响应数据"
        }
    }
    错误响应 (403):
    {
        "error": "注册未激活"
    }
    """
    try:
        data = request.get_json()
        key = data.get('key')
        
        if not key:
            return jsonify({'error': '缺少密钥'}), 400
            
        registration = Registration.query.filter_by(key=key).first()
        
        # 如果未找到注册信息，自动注册
        if not registration:
            # 生成5位随机编码
            random_code = ''.join(secrets.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(5))
            project_name = f"项目：{random_code}"
            
            registration = Registration(
                key=key,
                project_name=project_name,
                register_time=datetime.now(),
                expire_date=None,
                last_modified=datetime.now(),
                status=RegistrationStatus.UNACTIVATED.value
            )
            
            db.session.add(registration)
            db.session.commit()
            
            # 准备加密响应数据
            response_data = {
                'project_name': registration.project_name,
                'register_time': registration.register_time.strftime('%Y-%m-%d %H:%M:%S'),
                'status': registration.status,
                'message': '未注册，已自动注册，等待激活'
            }
            
            # 使用配置的6位后缀替换机器码后6位
            encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
            
            # 使用机器码的前16位作为IV
            iv = key[:16].encode()
            cipher = AES.new(encryption_key.encode(), AES.MODE_CBC, iv)
            
            # 加密数据
            data_str = json.dumps(response_data, ensure_ascii=False)
            padded_data = pad(data_str.encode(), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # 组合IV和加密数据
            combined_data = iv + encrypted_data
            encoded_data = base64.b64encode(combined_data).decode('utf-8')
            
            return jsonify({
                'message': '未注册，已自动注册，等待激活',
                'data': {
                    'encrypted_data': encoded_data
                }
            }), 200
            
        if registration.status == RegistrationStatus.UNACTIVATED.value:
            response_data = {
                'project_name': registration.project_name,
                'register_time': registration.register_time.strftime('%Y-%m-%d %H:%M:%S'),
                'status': registration.status,
                'message': '已注册，等待激活'
            }
            
            # 使用配置的6位后缀替换机器码后6位
            encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
            
            # 使用机器码的前16位作为IV
            iv = key[:16].encode()
            cipher = AES.new(encryption_key.encode(), AES.MODE_CBC, iv)
            
            # 加密数据
            data_str = json.dumps(response_data, ensure_ascii=False)
            padded_data = pad(data_str.encode(), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # 组合IV和加密数据
            combined_data = iv + encrypted_data
            encoded_data = base64.b64encode(combined_data).decode('utf-8')
            
            return jsonify({
                'message': '已注册，等待激活',
                'data': {
                    'encrypted_data': encoded_data
                }
            }), 200
            
        # 检查是否过期（永久激活状态除外）
        if (registration.status != RegistrationStatus.PERMANENT.value and 
            registration.expire_date and registration.expire_date < datetime.now()):
            registration.status = RegistrationStatus.EXPIRED.value
            db.session.commit()
            return jsonify({'error': '注册已过期'}), 403
            
        # 准备加密响应数据
        response_data = {
            'project_name': registration.project_name,
            'status': registration.status,
            'expire_date': registration.expire_date.strftime('%Y-%m-%d %H:%M:%S') if registration.expire_date else 'permanent',
            'message': '验证成功'
        }
        
        # 使用配置的6位后缀替换机器码后6位
        encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
        
        # 使用机器码的前16位作为IV
        iv = key[:16].encode()
        cipher = AES.new(encryption_key.encode(), AES.MODE_CBC, iv)
        
        # 加密数据
        data_str = json.dumps(response_data, ensure_ascii=False)
        padded_data = pad(data_str.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # 组合IV和加密数据
        combined_data = iv + encrypted_data
        encoded_data = base64.b64encode(combined_data).decode('utf-8')
        
        return jsonify({
            'message': '验证成功',
            'data': {
                'encrypted_data': encoded_data
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# 添加主页路由
@app.route('/')
def index():
    if 'admin_id' not in session:
        return redirect(url_for('admin.login'))
    return redirect(url_for('admin.dashboard'))

def get_api_docs():
    """收集所有 API 接口信息"""
    api_routes = []
    
    for rule in app.url_map.iter_rules():
        if rule.endpoint in app.view_functions and rule.methods and 'POST' in rule.methods:
            view_func = app.view_functions[rule.endpoint]
            if view_func.__doc__:
                # 解析 docstring
                doc_lines = [line.strip() for line in view_func.__doc__.split('\n') if line.strip()]
                
                api_info = {
                    'endpoint': rule.rule,
                    'description': doc_lines[0] if doc_lines else '',
                    'method': 'POST',
                    'params': None,
                    'responses': None
                }
                
                # 解析请求参数和响应示例
                current_section = None
                for line in doc_lines[1:]:
                    if '请求参数：' in line:
                        current_section = 'params'
                        api_info['params'] = ''
                    elif '响应示例：' in line:
                        current_section = 'responses'
                        api_info['responses'] = ''
                    elif current_section and line:
                        if current_section == 'params':
                            api_info['params'] = api_info['params'] + line + '\n'
                        elif current_section == 'responses':
                            api_info['responses'] = api_info['responses'] + line + '\n'
                
                api_routes.append(api_info)
    
    return api_routes

@app.route('/docs')
def api_docs():
    api_routes = get_api_docs()
    return render_template('api_docs.html', api_routes=api_routes)

def create_admin():
    """创建默认管理员账号"""
    if Admin.query.count() == 0:
        # 生成16位随机密码
        random_password = ''.join(secrets.choice('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()') for _ in range(16))
        
        admin = Admin(
            username='',  # 用户名留空，等待用户首次设置
            email='admin@example.com',
            role=UserRole.SUPER_ADMIN.value,
            is_first_login=True  # 设置为首次登录
        )
        admin.set_password(random_password)
        db.session.add(admin)
        db.session.commit()
        
        # 在控制台显示初始密码
        print("\n" + "="*50)
        print("首次启动：请设置管理员账号")
        print(f"临时密码: {random_password}")
        print("请使用此临时密码登录并设置您的用户名和新密码")
        print("="*50 + "\n")

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = Admin.query.filter_by(email=email).first()
        
        if user:
            # 生成重置令牌
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            # 发送重置邮件
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('密码重置请求',
                        sender=app.config['MAIL_USERNAME'],
                        recipients=[email])
            msg.body = f'''要重置您的密码，请访问以下链接：
{reset_url}

如果您没有请求重置密码，请忽略此邮件。
'''
            mail.send(msg)
            flash('重置链接已发送到您的邮箱，请查收。')
            return redirect(url_for('login'))
        
        flash('该邮箱地址未注册。')
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = Admin.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expiry < datetime.utcnow():
        flash('重置链接无效或已过期。')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('两次输入的密码不匹配。')
            return render_template('reset_password.html')
        
        # 更新密码
        user.password = password  # 确保这里使用了你的密码哈希方法
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('密码已成功重置，请使用新密码登录。')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'GET':
        admin = Admin.query.get(session['admin_id'])
        if admin.is_first_login:
            return render_template('admin/change_password.html')
        return redirect(url_for('admin.dashboard'))
    
    data = request.get_json()
    username = data.get('username')  # 新增：获取用户名
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    admin = Admin.query.get(session['admin_id'])
    
    # 首次登录时设置用户名
    if admin.is_first_login:
        if not username or len(username.strip()) < 3:
            return jsonify({'error': '用户名不能为空且长度至少为3个字符'}), 400
        # 检查用户名是否已存在
        if Admin.query.filter(Admin.id != admin.id, Admin.username == username).first():
            return jsonify({'error': '用户名已被使用'}), 400
        admin.username = username
    elif not admin.check_password(current_password):
        return jsonify({'error': '当前密码错误'}), 400
    
    if new_password != confirm_password:
        return jsonify({'error': '两次输入的新密码不一致'}), 400
    
    admin.set_password(new_password)
    admin.is_first_login = False
    # 更新密码版本
    admin.password_version = (admin.password_version or 0) + 1
    db.session.commit()
    
    # 清除当前会话，强制重新登录
    session.clear()
    
    return jsonify({
        'message': '设置成功，请使用新的用户名和密码登录',
        'redirect_url': url_for('admin.login')
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()  # 在这里调用创建管理员账号的函数
    app.run(debug=True) 