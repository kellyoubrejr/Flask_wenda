import logging

from flask import Blueprint, render_template, request, g, redirect, url_for
from .forms import QuestionForm, AnswerForm
from models import questionModel, AnswerModel
from exts import db
from decorators import login_required


bp = Blueprint('qa', __name__, url_prefix='/')


@bp.route('/')
def index():
    questions = questionModel.query.order_by(questionModel.create_time.desc()).all()
    return render_template("index.html", questions=questions)
    # return "hello this is index page"


@bp.route("/qa/public", methods=['GET', 'POST'])
# 装饰器
@login_required
def public_question():
    if request.method == 'GET':
        return render_template("public_question.html")
    else:
        form = QuestionForm(request.form)
        if form.validate():
            title = form.title.data
            content = form.content.data
            question = questionModel(title=title, content=content, author=g.user)
            db.session.add(question)
            db.session.commit()
            # todo: 跳转到这篇问答的详情页
            return redirect("/")
        else:
            print(form.errors)
            return redirect(url_for("qa.public_question"))


@bp.route("/qa/detail/<qa_id>")
def qa_detail(qa_id):
    question = questionModel.query.get(qa_id)
    return  render_template("detail.html", question=question)


# @bp.route("/answer/public", methods=['POST'])
@bp.post("/answer/public")
@login_required
def public_answer():
    form = AnswerForm(request.form)
    if form.validate():
        content = form.content.data
        question_id = form.question_id.data
        answer = AnswerModel(content=content, question_id=question_id, author_id=g.user.id)
        db.session.add(answer)
        db.session.commit()
        return redirect(url_for("qa.qa_detail", qa_id=question_id))
    else:
        return redirect(url_for("qa.qa_detail", qa_id=request.form.get("question_id")))


@bp.route("/search")
def search():
    q = request.args.get("q")
    questions = questionModel.query.filter(questionModel.title.contains(q)).all()
    return render_template("index.html", questions=questions)




