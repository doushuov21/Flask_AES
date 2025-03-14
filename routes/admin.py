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

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('admin/login.html')
    
    data = request.form
    username = data.get('username')
    password = data.get('password')
    
    # 处理首次登录的情况（空用户名）
    if not username:
        # 查找没有用户名的管理员账号
        admin = Admin.query.filter_by(username='').first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            session['password_version'] = admin.password_version
            admin.last_login = datetime.now()
            db.session.commit()
            return redirect(url_for('admin.change_password'))
    else:
        # 正常登录流程
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            session['password_version'] = admin.password_version
            admin.last_login = datetime.now()
            db.session.commit()
            
            if admin.is_first_login:
                return redirect(url_for('admin.change_password'))
            
            return redirect(url_for('admin.dashboard'))
    
    flash('用户名或密码错误', 'error')
    return redirect(url_for('admin.login'))

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    registrations = Registration.query.all()
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
    key = data.get('key')  # 使用提供的机器码
    
    if not key or len(key) != 32:
        return jsonify({'error': '无效的机器码长度，需要32位'}), 400
    
    # 检查机器码是否已存在
    if Registration.query.filter_by(key=key).first():
        return jsonify({'error': '该机器码已注册'}), 400
    
    registration = Registration(
        key=key,
        project_name=project_name,
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
    
    registration = Registration.query.filter_by(key=key).first()
    if not registration:
        return jsonify({'error': '未找到注册信息'}), 404
    
    if days == -1:
        registration.status = RegistrationStatus.PERMANENT.value
        registration.expire_date = None
    else:
        registration.status = RegistrationStatus.ACTIVATED.value
        registration.expire_date = datetime.now() + timedelta(days=days)
    
    registration.last_modified = datetime.now()
    db.session.commit()
    
    return jsonify({'message': '激活成功'})

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
        'expire_date': registration.expire_date.strftime('%Y-%m-%d %H:%M:%S') if registration.expire_date else 'permanent'
    }
    
    try:
        # 使用配置的6位后缀替换机器码后6位
        encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
        
        # 使用机器码的前16位作为IV，确保相同机器码生成相同的激活码
        iv = key[:16].encode()
        
        # 使用CBC模式创建cipher
        cipher = AES.new(encryption_key.encode(), AES.MODE_CBC, iv)
        
        # 将数据转换为JSON字符串并填充
        data_str = json.dumps(response_data, ensure_ascii=False)
        padded_data = pad(data_str.encode(), AES.block_size)
        
        # 加密数据
        encrypted_data = cipher.encrypt(padded_data)
        
        # 将IV和加密数据组合，并进行Base64编码
        combined_data = iv + encrypted_data
        encoded_data = base64.b64encode(combined_data).decode('utf-8')
        
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