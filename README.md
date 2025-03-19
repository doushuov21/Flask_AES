# 授权管理系统

一个基于 Flask 的授权管理系统，用于管理软件授权和激活码。

## 功能特点

- 管理员账户系统
  - 首次登录自动创建管理员账户
  - 密码修改和安全验证
  - 会话管理和自动登出

- 授权管理
  - 添加和管理注册信息
  - 生成和验证激活码
  - 支持永久和限时授权
  - 实时状态监控

- API 密钥管理
  - 创建和管理 API 密钥
  - API 访问控制和验证

- 加密系统
  - 基于 AES-ECB 的加密方案
  - 支持自定义加密密钥
  - Base64 编码支持

## 技术栈

- Python 3.8+
- Flask Web 框架
- SQLAlchemy ORM
- PyCrypto 加密库
- Bootstrap 5 UI 框架

## 安装说明

1. 克隆项目并进入目录：
```bash
git clone <repository_url>
cd Flask_AES
```

2. 创建并激活虚拟环境：
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

4. 初始化数据库：
```bash
flask db upgrade
```

5. 运行应用：
```bash
flask run
```

## 配置说明

1. 环境变量配置（创建 .env 文件）：
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key
ENCRYPTION_SUFFIX=aes123
```

2. 数据库配置（config.py）：
```python
SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
```

## API 文档

### 注册接口
- 端点：`/register`
- 方法：POST
- 请求头：需要有效的 API Key
- 请求体：
```json
{
    "key": "32位机器码",
    "name": "项目名称",
    "description": "项目描述",
    "version": "项目版本"
}
```

### 激活接口
- 端点：`/activate`
- 方法：POST
- 请求头：需要有效的 API Key
- 请求体：
```json
{
    "key": "32位机器码",
    "days": "有效期天数（-1表示永久）"
}
```

### 验证接口
- 端点：`/verify`
- 方法：POST
- 请求头：需要有效的 API Key
- 请求体：
```json
{
    "key": "32位机器码",
    "name": "项目名称（可选）",
    "description": "项目描述（可选）"
}
```

## 安全说明

- 所有密码都经过加密存储
- API 密钥使用安全的随机生成方法
- 激活码使用 AES-ECB 加密
- 支持会话超时和自动登出
- 所有敏感操作都需要身份验证

## 开发说明

1. 代码结构：
```
.
├── app.py              # 应用入口
├── config.py           # 配置文件
├── models.py           # 数据模型
├── routes/            # 路由模块
│   ├── admin.py       # 管理员路由
│   └── user.py        # 用户路由
├── templates/         # 模板文件
│   └── admin/        # 管理员页面模板
└── static/           # 静态文件
```

2. 数据库迁移：
```bash
flask db migrate -m "migration message"
flask db upgrade
```

## 许可证

MIT License

## 部署方式

### 1. 本地部署

[... existing installation steps ...]

### 2. Docker 部署

1. 使用 docker-compose（推荐）：
```bash
# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

2. 手动构建和运行：
```bash
# 构建镜像
docker build -t flask-aes .

# 运行容器
docker run -d -p 5000:5000 flask-aes
```

## 环境变量配置

系统支持以下环境变量配置：

| 环境变量 | 说明 | 默认值 | 必填 |
|---------|------|--------|------|
| ENCRYPTION_SUFFIX | AES加密后缀，用于生成激活码的密钥后6位 | aes123 | 是 |
| SECRET_KEY | Flask会话密钥，用于加密会话数据 | None | 是 |
| DATABASE_URL | 数据库连接URL | sqlite:///app.db | 否 |
| MAIL_SERVER | 邮件服务器地址 | smtp.gmail.com | 否 |
| MAIL_PORT | 邮件服务器端口 | 587 | 否 |
| MAIL_USE_TLS | 是否使用TLS | True | 否 |
| MAIL_USERNAME | 邮箱账号 | None | 否 |
| MAIL_PASSWORD | 邮箱密码或应用专用密码 | None | 否 |
| MAIL_DEFAULT_SENDER | 默认发件人 | None | 否 |

### 环境变量说明

1. **ENCRYPTION_SUFFIX**
   - 用途：生成激活码时替换机器码后6位
   - 建议：生产环境中修改默认值
   - 要求：必须是6位字符

2. **SECRET_KEY**
   - 用途：Flask会话加密
   - 建议：使用强随机字符串
   - 安全性：生产环境必须修改

3. **DATABASE_URL**
   - 用途：数据库连接配置
   - 格式：
     - SQLite: `sqlite:///app.db`
     - MySQL: `mysql://user:pass@localhost/dbname`
     - PostgreSQL: `postgresql://user:pass@localhost/dbname`

4. **邮件配置**
   - 用途：发送密码重置等系统邮件
   - 配置组：
     - MAIL_SERVER
     - MAIL_PORT
     - MAIL_USE_TLS
     - MAIL_USERNAME
     - MAIL_PASSWORD
   - 说明：如需邮件功能，所有邮件相关配置都必须设置

### 配置方式

1. 使用 .env 文件（本地开发）：
```bash
ENCRYPTION_SUFFIX=your_suffix
SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///app.db
```

2. 使用 docker-compose.yml（Docker部署）：
```yaml
environment:
  - ENCRYPTION_SUFFIX=your_suffix
  - SECRET_KEY=your_secret_key
  - DATABASE_URL=sqlite:///app.db
```

3. 使用环境变量（生产部署）：
```bash
export ENCRYPTION_SUFFIX=your_suffix
export SECRET_KEY=your_secret_key
```

### 数据持久化

使用 Docker 部署时，建议挂载以下目录：
```yaml
volumes:
  - ./data:/app/data     # 数据库文件
  - ./logs:/app/logs     # 日志文件
```
