from database import db
from enum import Enum
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
from datetime import datetime

class RegistrationStatus(Enum):
    UNACTIVATED = 'unactivated'  # 未激活
    ACTIVATED = 'activated'      # 已激活
    EXPIRED = 'expired'         # 已过期
    PERMANENT = 'permanent'     # 永久激活

class UserRole(Enum):
    SUPER_ADMIN = 'super_admin'  # 超级管理员
    ADMIN = 'admin'              # 管理员
    OPERATOR = 'operator'        # 操作员
    VIEWER = 'viewer'            # 查看者

class Permission(Enum):
    MANAGE_USERS = 'manage_users'          # 管理用户
    MANAGE_GROUPS = 'manage_groups'        # 管理用户组
    MANAGE_KEYS = 'manage_keys'            # 管理API密钥
    ACTIVATE_REGISTRATIONS = 'activate_reg' # 激活注册
    VIEW_REGISTRATIONS = 'view_reg'        # 查看注册
    VIEW_STATISTICS = 'view_stats'         # 查看统计

# 用户组和权限关联表
group_permissions = db.Table('group_permissions',
    db.Column('group_id', db.Integer, db.ForeignKey('user_group.id'), primary_key=True),
    db.Column('permission_name', db.String(50), primary_key=True)
)

# 用户和用户组关联表
user_groups = db.Table('user_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('admin.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('user_group.id'), primary_key=True)
)

class UserGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    permission_names = db.Column(db.JSON, default=list)  # 存储权限名称列表
    users = db.relationship('Admin', secondary=user_groups,
                          backref=db.backref('groups', lazy='dynamic'))

    def has_permission(self, permission):
        if isinstance(permission, Permission):
            return permission.value in self.permission_names
        return permission in self.permission_names

    def set_permissions(self, permissions):
        """设置权限列表"""
        self.permission_names = [p.value if isinstance(p, Permission) else p for p in permissions]

    def get_permissions(self):
        """获取权限列表"""
        return [p for p in Permission if p.value in (self.permission_names or [])]

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(32), unique=True, nullable=False)
    project_name = db.Column(db.String(100), nullable=False)
    register_time = db.Column(db.DateTime, nullable=False)
    expire_date = db.Column(db.DateTime, nullable=True)  # 允许为空，用于永久激活状态
    last_modified = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default=RegistrationStatus.UNACTIVATED.value)
    activation_code = db.Column(db.Text, nullable=True)  # 添加激活码字段

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(120), unique=True)
    role = db.Column(db.String(20), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_first_login = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime)
    created_by_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    reset_token = db.Column(db.String(100))
    reset_token_expiry = db.Column(db.DateTime)
    password_version = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Admin {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_permission(self, permission):
        # 超级管理员拥有所有权限
        if self.role == UserRole.SUPER_ADMIN.value:
            return True
        # 检查用户组权限
        for group in self.groups:
            if group.has_permission(permission):
                return True
        return False

# 审计日志
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

    user = db.relationship('Admin', backref='audit_logs')

class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    @staticmethod
    def generate_key():
        return f"sk-{secrets.token_hex(24)}"  # 生成类似 sk-*** 格式的key 