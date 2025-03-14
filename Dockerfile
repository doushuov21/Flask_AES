# 使用官方Python镜像
FROM python:3.12-slim

# 添加元数据
LABEL maintainer="Your Name <your.email@example.com>"
LABEL version="1.0"
LABEL description="AES Encryption Flask Application"

# 设置工作目录
WORKDIR /app

# 设置Python环境
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# 复制依赖文件
COPY requirements.txt .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 复制项目文件
COPY . .

# 暴露端口
EXPOSE 5000

# 设置环境变量
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# 创建非root用户
RUN useradd -m appuser && \
    chown -R appuser:appuser /app
USER appuser

# 启动应用
CMD ["sh", "-c", "python manage.py && flask run --host=0.0.0.0"]
