from app import app, db

def init_db():
    with app.app_context():
        db.create_all()
        print("数据库表已创建")

if __name__ == '__main__':
    init_db() 