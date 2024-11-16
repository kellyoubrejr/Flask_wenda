# 配置文件
SECRET_KEY ="asdfasdfjasdfjasd;lf"


HOSTNAME = '127.0.0.1'
PORT = '3306'
USERNAME = 'root'
PASSWORD = 'root'
DATABASE = 'wenda'
DB_URI = 'mysql+pymysql://{}:{}@{}:{}/{}?charset=utf8'.format(USERNAME, PASSWORD, HOSTNAME, PORT, DATABASE)
SQLALCHEMY_DATABASE_URI = DB_URI



# JXsc8bZxmGYRsu8Q


# 网易邮箱配置
MAIL_SERVER = 'smtp.163.com'
MAIL_USE_SSL = True
MAIL_PORT = 465
MAIL_USERNAME = '19105421031@163.com'
MAIL_PASSWORD = 'JXsc8bZxmGYRsu8Q'
MAIL_DEFAULT_SENDER = '19105421031@163.com'