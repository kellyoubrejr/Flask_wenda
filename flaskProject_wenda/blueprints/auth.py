import bdb

from flask import Blueprint, render_template, jsonify, redirect, url_for, session
from exts import mail, db
from flask_mail import Message
from flask import request
import string
import random
from models import EmailCaptchaModel
from .forms import RegisterForm, LoginForm
from models import UserModel
from werkzeug.security import generate_password_hash, check_password_hash
import logging


# 相当于Flask的一个子模块
bp = Blueprint("auth", __name__, url_prefix="/auth")

logging.basicConfig(level=logging.INFO)  # 设置日志级别


@bp.route("/login", methods=['GET', 'POST'])

def login():
    if request.method == 'GET':
        return render_template("login.html")
    else:
        form = LoginForm(request.form)
        if form.validate():
            email = form.email.data
            password = form.password.data
            user = UserModel.query.filter_by(email=email).first()
            if not user:
                logging.info("邮箱不存在")
                return redirect(url_for("auth.login"))
            if check_password_hash(user.password, password):
                # cookie：
                # cookie中不适合存储太多的数据，只适合存储少量的数据
                # cookie一般用来存放登录授权的东西
                # flask中的session，是经过加密后存储在cookie中的
                session['user_id'] = user.id
                logging.info("登录成功")
                return redirect("/")
            else:
                logging.info("密码错误")
                return redirect(url_for("auth.login"))
        else:
            logging.info(form.errors)
            return redirect(url_for("auth.login"))


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))




@bp.route("/register", methods=['GET', 'POST'])
def register():
    #验证登录的邮箱是否匹配验证码
    if request.method == 'GET':
        return render_template("register.html")
    else:
        form = RegisterForm(request.form)
        if form.validate():
            # return jsonify({"code": 200, "msg": "验证成功"})
            email = form.email.data
            username = form.username.data
            password = form.password.data
            user = UserModel(email=email, username=username, password= generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for("auth.login"))

        else:
            logging.info(form.errors)
            return redirect(url_for("auth.register"))




@bp.route("/captcha/email")
def captcha_email():
    email = request.args.get("email")
    source = string.digits * 4
    captcha = "".join(random.sample(source, 4))
    message = Message(subject="验证码", recipients=[email], body=f"验证码是{captcha}")
    mail.send(message)

    email_captcha = EmailCaptchaModel(email=email, captcha=captcha)
    db.session.add(email_captcha)
    db.session.commit()

    return jsonify({"code": 200, "msg": "发送成功"})
    # RESTful API


@bp.route("/mail/test")
def test_mail():
    message = Message(subject="测试邮件", recipients=["1785266745@qq.com"], body="这是一封测试邮件")
    mail.send(message)
    return "发送成功"

@bp.route('/about')
def about():
    return render_template('about.html')


@bp.route("/info", methods=["GET"])
def user_info():
    # 假设用户信息存储在 session 中
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "用户未登录"}), 401

    # 从数据库获取用户信息
    user = UserModel.query.get(user_id)
    if not user:
        return jsonify({"error": "用户不存在"}), 404

    # 返回用户信息
    return jsonify({
        "username": user.username,
        "email": user.email
    })