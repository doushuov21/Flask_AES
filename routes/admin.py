from flask import Blueprint, render_template, request, jsonify, redirect, url_for, session, flash, current_app
from models import Admin, Registration, RegistrationStatus, APIKey
from database import db
from datetime import datetime, timedelta
import secrets
from functools import wraps
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/check-admin', methods=['GET'])
def check_admin():
    try:
        # 检查是否存在管理员账号
        admin = Admin.query.first()
        if not admin:
            # 使用默认账号密码创建管理员账号
            admin = Admin(
                username=current_app.config['ADMIN_USERNAME'],
                email='admin@example.com',
                is_first_login=True
            )
            admin.set_password(current_app.config['ADMIN_PASSWORD'])
            db.session.add(admin)
            db.session.commit()
            
            return jsonify({
                'has_admin': False,
                'message': '已创建默认管理员账号'
            })
        
        return jsonify({
            'has_admin': True,
            'is_first_login': admin.is_first_login
        })
        
    except Exception as e:
        current_app.logger.error(f"Check admin error: {str(e)}")
        return jsonify({'error': '服务器错误'}), 500

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('admin/login.html')
    
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': '用户名和密码不能为空'}), 400
        
        # 检查是否存在管理员账号
        admin = Admin.query.first()
        
        # 首次使用系统的情况
        if not admin:
            if username == current_app.config['ADMIN_USERNAME'] and password == current_app.config['ADMIN_PASSWORD']:
                # 创建默认管理员账号
                admin = Admin(
                    username=current_app.config['ADMIN_USERNAME'],
                    email='admin@example.com',
                    is_first_login=True,
                    role='admin'
                )
                admin.set_password(current_app.config['ADMIN_PASSWORD'])
                db.session.add(admin)
                db.session.commit()
            else:
                return jsonify({'error': '用户名或密码错误'}), 401
        else:
            # 验证用户名和密码
            admin = Admin.query.filter(
                (Admin.username == username) | (Admin.email == username)
            ).first()
            
            if not admin:
                return jsonify({'error': '用户名或密码错误'}), 401
            
            if not admin.check_password(password):
                return jsonify({'error': '用户名或密码错误'}), 401
        
        # 登录成功，设置session
        session['admin_id'] = admin.id
        session['password_version'] = admin.password_version
        admin.last_login = datetime.now()
        db.session.commit()
        
        if admin.is_first_login:
            return jsonify({
                'redirect_url': url_for('admin.change_password'),
                'message': '首次登录，请修改密码'
            })
        
        return jsonify({
            'redirect_url': url_for('admin.dashboard'),
            'message': '登录成功'
        })
        
    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': '服务器错误'}), 500

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    # 获取所有注册信息，按注册时间倒序排列
    registrations = Registration.query.order_by(Registration.register_time.desc()).all()
    
    # 添加调试日志
    current_app.logger.info(f"Found {len(registrations)} registrations")
    for reg in registrations:
        current_app.logger.info(f"Registration: key={reg.key}, project={reg.project_name}, status={reg.status}, activation_code={reg.activation_code}")
    
    return render_template('admin/dashboard.html', registrations=registrations)

@admin_bp.route('/logout')
def logout():
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))

@admin_bp.route('/change-password', methods=['GET', 'POST'])
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

@admin_bp.route('/registration', methods=['POST'])
@login_required
def add_registration():
    data = request.get_json()
    project_name = data.get('project_name')
    description = data.get('description')
    version = data.get('version', '1.0')
    key = data.get('key')  # 使用提供的机器码
    
    if not key or len(key) != 32:
        return jsonify({'error': '无效的机器码长度，需要32位'}), 400
    
    if not description:
        return jsonify({'error': '项目描述不能为空'}), 400
    
    # 检查机器码是否已存在
    if Registration.query.filter_by(key=key).first():
        return jsonify({'error': '该机器码已注册'}), 400
    
    registration = Registration(
        key=key,
        project_name=project_name,
        description=description,
        version=version,
        register_time=datetime.now(),
        expire_date=None,  # 初始无过期时间
        last_modified=datetime.now(),
        status=RegistrationStatus.UNACTIVATED.value  # 初始状态为未激活
    )
    
    db.session.add(registration)
    db.session.commit()
    
    return jsonify({
        'message': '添加成功'
    })

@admin_bp.route('/registration/<key>/activate', methods=['POST'])
@login_required
def activate_registration(key):
    data = request.get_json()
    days = int(data.get('days', 365))
    description = data.get('description', '')  # 获取备注信息
    
    registration = Registration.query.filter_by(key=key).first()
    if not registration:
        return jsonify({'error': '未找到注册信息'}), 404
    
    now = datetime.now()
    
    if days == -1:
        registration.status = RegistrationStatus.PERMANENT.value
        registration.expire_date = None
    else:
        registration.status = RegistrationStatus.ACTIVATED.value
        registration.expire_date = now + timedelta(days=days)
    
    registration.last_modified = now
    registration.description = description  # 更新备注信息
    
    # 准备要加密的数据
    expire_date = registration.expire_date.strftime('%Y-%m-%d %H:%M:%S') if registration.expire_date else 'permanent'
    response_str = json.dumps({
        'project_name': registration.project_name,
        'status': registration.status,
        'expire_date': expire_date,
        'message': '激活成功',
        'description': description  # 在加密数据中包含备注信息
    })
    
    # 使用配置的6位后缀替换机器码后6位
    encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
    
    try:
        # 加密数据
        cipher = AES.new(encryption_key.encode('utf-8'), AES.MODE_ECB)
        padded_data = pad(response_str.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
        
        # 保存激活码到数据库
        registration.activation_code = encoded_data
        
        # 添加调试日志
        current_app.logger.info(f"Activating registration: key={key}")
        current_app.logger.info(f"Generated activation code: {encoded_data}")
        
        db.session.commit()
        
        # 返回激活码
        return jsonify({
            'message': '激活成功',
            'activation_code': encoded_data
        })
        
    except Exception as e:
        current_app.logger.error(f"激活失败: {str(e)}")
        return jsonify({'error': f'激活失败: {str(e)}'}), 500

@admin_bp.route('/registration/<key>', methods=['DELETE'])
@login_required
def delete_registration(key):
    registration = Registration.query.filter_by(key=key).first()
    if not registration:
        return jsonify({'error': '未找到注册信息'}), 404
    
    db.session.delete(registration)
    db.session.commit()
    
    return jsonify({'message': '删除成功'})

@admin_bp.route('/generate-activation-code', methods=['POST'])
@login_required
def generate_activation_code():
    data = request.get_json()
    key = data.get('key')
    
    registration = Registration.query.filter_by(key=key).first()
    if not registration:
        return jsonify({'error': '未找到注册信息'}), 404
        
    # 准备加密数据
    response_data = {
        'project_name': registration.project_name,
        'status': registration.status,
        'expire_date': registration.expire_date.strftime('%Y-%m-%d %H:%M:%S') if registration.expire_date else 'permanent',
        'message': '激活成功'
    }
    
    try:
        # 使用配置的6位后缀替换机器码后6位
        encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
        
        # 使用 ECB 模式创建 cipher
        cipher = AES.new(encryption_key.encode(), AES.MODE_ECB)
        
        # 将数据转换为JSON字符串
        data_str = json.dumps(response_data, ensure_ascii=False, separators=(',', ':'))
        
        # 计算需要填充的字节数
        padding_length = AES.block_size - (len(data_str.encode('utf-8')) % AES.block_size)
        # 使用Zero padding
        padded_data = data_str.encode('utf-8') + (b'\0' * padding_length)
        
        # 加密数据
        encrypted_data = cipher.encrypt(padded_data)
        
        # Base64编码
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
        
        return jsonify({
            'activation_code': encoded_data
        })
    except Exception as e:
        return jsonify({'error': f'生成激活码失败: {str(e)}'}), 500

@admin_bp.route('/api-keys')
@login_required
def api_keys():
    keys = APIKey.query.all()
    return render_template('admin/api_keys.html', keys=keys)

@admin_bp.route('/api-keys', methods=['POST'])
@login_required
def create_api_key():
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'error': '名称不能为空'}), 400
        
    api_key = APIKey(
        key=APIKey.generate_key(),
        name=name
    )
    db.session.add(api_key)
    db.session.commit()
    
    return jsonify({
        'message': '创建成功',
        'key': api_key.key
    })

@admin_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@login_required
def delete_api_key(key_id):
    api_key = APIKey.query.get_or_404(key_id)
    db.session.delete(api_key)
    db.session.commit()
    return jsonify({'message': '删除成功'})

@admin_bp.route('/registration/<key>/update', methods=['POST'])
@login_required
def update_registration(key):
    try:
        data = request.get_json()
        description = data.get('description')
        
        if not description:
            return jsonify({'error': '描述不能为空'}), 400
        
        registration = Registration.query.filter_by(key=key).first()
        if not registration:
            return jsonify({'error': '未找到注册信息'}), 404
        
        registration.description = description
        registration.last_modified = datetime.now()
        db.session.commit()
        
        return jsonify({
            'message': '更新成功',
            'description': description
        })
        
    except Exception as e:
        current_app.logger.error(f"更新失败: {str(e)}")
        return jsonify({'error': f'更新失败: {str(e)}'}), 500 