from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, current_app
from models import Admin, UserGroup, Permission, UserRole, AuditLog
from database import db
from functools import wraps
from datetime import datetime
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import json

user_bp = Blueprint('user', __name__)

def require_permission(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            admin = Admin.query.get(session.get('admin_id'))
            if not admin or not admin.has_permission(permission):
                flash('没有权限执行此操作')
                return redirect(url_for('admin.dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_audit(action, details=None):
    admin_id = session.get('admin_id')
    if admin_id:
        log = AuditLog(
            user_id=admin_id,
            action=action,
            details=details,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

@user_bp.route('/management')
@require_permission(Permission.MANAGE_USERS)
def management():
    users = Admin.query.all()
    groups = UserGroup.query.all()
    return render_template('user/management.html', 
                         users=users, 
                         groups=groups,
                         roles=UserRole,
                         permissions=Permission)

@user_bp.route('/users/create', methods=['POST'])
@require_permission(Permission.MANAGE_USERS)
def create_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')
    group_ids = request.form.getlist('groups')

    if Admin.query.filter_by(username=username).first():
        flash('用户名已存在')
        return redirect(url_for('user.management'))

    user = Admin(
        username=username,
        email=email,
        role=role,
        created_by_id=session.get('admin_id')
    )
    user.set_password(password)

    # 添加用户到选定的组
    for group_id in group_ids:
        group = UserGroup.query.get(group_id)
        if group:
            user.groups.append(group)

    db.session.add(user)
    db.session.commit()

    log_audit('创建用户', f'创建用户: {username}')
    flash('用户创建成功')
    return redirect(url_for('user.management'))

@user_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_permission(Permission.MANAGE_USERS)
def delete_user(user_id):
    user = Admin.query.get_or_404(user_id)
    if user.id == session.get('admin_id'):
        return jsonify({'error': '不能删除自己的账号'}), 400
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    log_audit('删除用户', f'删除用户: {username}')
    return jsonify({'message': '用户删除成功'})

@user_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@require_permission(Permission.MANAGE_USERS)
def edit_user(user_id):
    user = Admin.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.email = request.form.get('email')
        user.role = request.form.get('role')
        
        if request.form.get('password'):
            user.set_password(request.form.get('password'))
            
        # 更新用户组
        user.groups = []
        group_ids = request.form.getlist('groups')
        for group_id in group_ids:
            group = UserGroup.query.get(group_id)
            if group:
                user.groups.append(group)
                
        db.session.commit()
        log_audit('编辑用户', f'编辑用户: {user.username}')
        flash('用户更新成功')
        return redirect(url_for('user.management'))
        
    groups = UserGroup.query.all()
    return render_template('user/edit.html', user=user, roles=UserRole, groups=groups)

@user_bp.route('/groups/create', methods=['POST'])
@require_permission(Permission.MANAGE_GROUPS)
def create_group():
    name = request.form.get('name')
    description = request.form.get('description')
    permissions = request.form.getlist('permissions')

    if UserGroup.query.filter_by(name=name).first():
        flash('组名已存在')
        return redirect(url_for('user.management'))

    group = UserGroup(
        name=name,
        description=description
    )
    
    # 添加权限
    group.set_permissions(permissions)

    db.session.add(group)
    db.session.commit()
    
    log_audit('创建用户组', f'创建用户组: {name}')
    flash('用户组创建成功')
    return redirect(url_for('user.management'))

@user_bp.route('/groups/<int:group_id>', methods=['DELETE'])
@require_permission(Permission.MANAGE_GROUPS)
def delete_group(group_id):
    group = UserGroup.query.get_or_404(group_id)
    
    name = group.name
    db.session.delete(group)
    db.session.commit()
    
    log_audit('删除用户组', f'删除用户组: {name}')
    return jsonify({'message': '用户组删除成功'})

@user_bp.route('/groups/<int:group_id>/edit', methods=['GET', 'POST'])
@require_permission(Permission.MANAGE_GROUPS)
def edit_group(group_id):
    group = UserGroup.query.get_or_404(group_id)
    
    if request.method == 'POST':
        group.name = request.form.get('name')
        group.description = request.form.get('description')
        
        # 更新权限
        permissions = request.form.getlist('permissions')
        group.set_permissions(permissions)
                
        db.session.commit()
        log_audit('编辑用户组', f'编辑用户组: {group.name}')
        flash('用户组更新成功')
        return redirect(url_for('user.management'))
        
    return render_template('user/edit_group.html', group=group, permissions=Permission)

@user_bp.route('/audit-logs')
@require_permission(Permission.MANAGE_USERS)
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('user/audit_logs.html', logs=logs)

@user_bp.route('/api/decrypt', methods=['POST'])
@require_permission(Permission.MANAGE_USERS)
def decrypt_data():
    try:
        data = request.get_json()
        encrypted_data = data.get('encrypted_data')
        key = data.get('key')

        if not encrypted_data or not key:
            return jsonify({'error': '加密数据和密钥都是必需的'}), 400

        # 验证密钥长度
        key_length = len(key)
        if key_length not in [16, 24, 32]:
            return jsonify({'error': f'密钥长度必须是16、24或32字节，当前长度是{key_length}字节'}), 400

        try:
            # 解码Base64编码的加密数据
            encrypted_bytes = base64.b64decode(encrypted_data)
        except Exception:
            return jsonify({'error': '无效的Base64编码'}), 400

        # 验证加密数据长度
        if len(encrypted_bytes) < 16:
            return jsonify({'error': '加密数据长度不足（至少需要16字节的IV）'}), 400

        # 提取IV（前16字节）和加密数据
        iv = encrypted_bytes[:16]
        encrypted_content = encrypted_bytes[16:]

        # 验证加密内容长度
        if len(encrypted_content) % 16 != 0:
            return jsonify({'error': '加密数据长度不是16的倍数'}), 400

        try:
            # 使用配置的6位后缀替换机器码后6位
            encryption_key = key[:-6] + current_app.config['ENCRYPTION_SUFFIX']
            
            # 创建AES解密器
            cipher = AES.new(encryption_key.encode('utf-8'), AES.MODE_CBC, iv)
            
            # 解密数据
            decrypted_padded = cipher.decrypt(encrypted_content)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            
            # 将解密后的数据解析为JSON
            json_data = json.loads(decrypted_data.decode('utf-8'))
            
            return jsonify({'data': json_data})
        except ValueError as e:
            return jsonify({'error': f'解密失败: {str(e)}。请检查密钥是否正确。'}), 400
        except json.JSONDecodeError:
            return jsonify({'error': '解密成功但结果不是有效的JSON格式'}), 400
        except UnicodeDecodeError:
            return jsonify({'error': '解密成功但无法解码为UTF-8文本'}), 400
    except Exception as e:
        return jsonify({'error': f'处理请求时发生错误: {str(e)}'}), 500 