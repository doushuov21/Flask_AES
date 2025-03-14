# Flask AES 授权系统

基于 Flask 的软件授权管理系统，使用 AES 加密实现机器码注册、激活和验证功能。

## 功能特点

### 1. 用户管理
- 多级用户权限系统（超级管理员、管理员、操作员、查看者）
- 用户组管理，支持灵活的权限分配
- 密码安全管理（自动强制修改首次登录密码、密码重置）
- 操作审计日志

### 2. 授权管理
- 机器码注册和管理
- 支持永久和临时授权
- 自动过期检测
- 加密的激活码生成

### 3. API 接口
- `/register`: 注册新机器码
- `/activate`: 激活机器码
- `/verify`: 验证机器码状态
- API Key 认证机制
- 加密数据传输

### 4. 安全特性
- AES-CBC 加密模式
- 动态 IV 生成
- 会话管理和密码版本控制
- API 访问控制和审计

## 技术栈

- Python 3.8+ (Docker 环境使用 Python 3.12)
- Flask
- SQLAlchemy
- PyCryptodome
- Bootstrap
- SQLite/MySQL

## 安装指南

### 1. 本地安装

```bash
# 克隆仓库
git clone https://github.com/doushuov21/Flask_AES.git
cd Flask_AES

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\\Scripts\\activate   # Windows

# 安装依赖
pip install -r requirements.txt

# 初始化数据库
flask db upgrade

# 运行应用
python app.py
```

### 2. Docker 安装

```bash
# 构建镜像
docker build -t flask-aes .

# 运行容器
docker run -d -p 5000:5000 --name flask-aes flask-aes
```

## Docker 使用指南

### 1. 使用 Docker Compose（推荐）

```bash
# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down

# 重新构建并启动
docker-compose up -d --build
```

在使用 docker-compose 之前，请根据你的环境修改 `docker-compose.yml` 中的环境变量：

```yaml
environment:
  - ENCRYPTION_SUFFIX=aes123        # 修改为你的加密后缀
  - SECRET_KEY=your-secret-key-here # 修改为你的密钥
  - ADMIN_USERNAME=admin            # 修改为你的管理员用户名
  - ADMIN_PASSWORD=admin123         # 修改为你的管理员密码
  - MAIL_USERNAME=your-email@gmail.com    # 修改为你的邮箱
  - MAIL_PASSWORD=your-app-password       # 修改为你的邮箱密码
```

### 2. 手动构建镜像

```bash
# 在项目根目录下构建镜像
docker build -t flask-aes:latest .
```

### 3. 导出镜像

```bash
# 将镜像保存为文件
docker save -o flask-aes.tar flask-aes:latest

# 压缩导出的镜像文件
gzip flask-aes.tar
```

### 4. 导入镜像

```bash
# 解压镜像文件
gunzip flask-aes.tar.gz

# 导入镜像
docker load -i flask-aes.tar
```

### 5. 运行容器

```bash
# 基本运行
docker run -d -p 5000:5000 flask-aes:latest

# 使用持久化存储
docker run -d -p 5000:5000 \
  -v /path/to/data:/app/data \
  -e ENCRYPTION_SUFFIX=your_suffix \
  flask-aes:latest
```

### 6. 容器管理

```bash
# 查看容器状态
docker ps -a

# 停止容器
docker stop flask-aes

# 启动容器
docker start flask-aes

# 删除容器
docker rm flask-aes
```

## 环境变量配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| ENCRYPTION_SUFFIX | AES加密后缀（6位） | aes123 |
| SECRET_KEY | Flask密钥 | dev-key |
| DATABASE_URL | 数据库连接URL | sqlite:///app.db |
| ADMIN_USERNAME | 管理员用户名 | admin |
| ADMIN_PASSWORD | 管理员密码 | admin123 |

## API 文档

### 注册接口 `/register`

**请求参数：**
```json
{
    "key": "32位机器码"
}
```

**响应示例：**
```json
{
    "message": "注册成功，等待激活",
    "data": {
        "encrypted_data": "加密的响应数据"
    }
}
```

### 激活接口 `/activate`

**请求参数：**
```json
{
    "key": "32位机器码",
    "days": "有效期天数（-1表示永久）"
}
```

### 验证接口 `/verify`

**请求参数：**
```json
{
    "key": "32位机器码"
}
```

## 注意事项

1. 首次启动时会创建临时管理员账号：
   - 系统生成16位随机临时密码，显示在控制台/Docker日志中
   - 首次登录时需要设置用户名（至少3个字符）和新密码
   - 用户名设置后不可更改，请谨慎选择
2. 所有API请求需要包含有效的API Key在Header中
3. 加密后缀必须是6位字符
4. 建议在生产环境中修改默认的密钥和管理员密码
5. 数据库文件请做好备份

## 许可证

MIT License

## 贡献指南

1. Fork 项目
2. 创建功能分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request
