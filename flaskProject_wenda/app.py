from flask import Flask, session, g
import config
from exts import db, mail
from models import UserModel
from blueprints.qa import bp as qa_bp
from blueprints.auth import bp as auth_bp
from flask_migrate import Migrate
# import logging


app = Flask(__name__)

# # 配置日志
# handler = logging.FileHandler('app.log')
# handler.setLevel(logging.INFO)
# app.logger.addHandler(handler)




# 绑定配置文件
app.config.from_object(config)

# 绑定
db.init_app(app)
mail.init_app(app)



migrate = Migrate(app, db)


app.register_blueprint(qa_bp)
app.register_blueprint(auth_bp)


# flask db init：只需要执行一次
# flask db migrate：将orm模型生成迁移脚本
# flask db upgrade：将迁移脚本映射到数据库中
# flask db downgrade：将数据库中的表删除
# flask db history：查看迁移脚本历史
# flask db current：查看当前迁移脚本
# flask db stamp：将迁移脚本打上标签
# flask db show：查看迁移脚本
# flask db status：查看迁移脚本状态

# 钩子函数 hook--->在正常执行的流程中，突然插入一个东西进来，先执行这个东西，然后再执行别的东西
# before_request/ before_first_request/ after_request
# before_request：在每次请求之前执行，如果返回了响应，则不再执行后续的视图函数
# before_first_request：在第一次请求之前执行，如果返回了响应，则不再执行后续的视图函数
# after_request：在每次请求之后执行，如果返回了响应，则不再执行后续的视图函数
# teardown_request：在每次请求之后执行，无论是否返回了响应，都会执行
# before_app_first_request：在第一次请求之前执行，如果返回了响应，则不再执行后续的视图函数
# before_app_request：在每次请求之前执行，如果返回了响应，则不再执行后续的视图函数
@app.before_request
def my_before_request():
    user_id = session.get('user_id')
    if user_id:
        user = UserModel.query.get(user_id)
        setattr(g, "user", user)
    else:
        setattr(g, "user", None)


@app.context_processor    # 上下文处理器
def my_context_processor():
    return {"user": g.user}







if __name__ == '__main__':
    app.run(debug=True)