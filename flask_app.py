from flask import Flask, render_template, abort, flash
from flask import redirect, url_for, request, session
from werkzeug.security import generate_password_hash, check_password_hash
import os

from database import get_db, g
 

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, "sqlite3_db"):
        g.sqlite3_db


def get_current_user():
    user_result = None 

    if "user" in session:
        user = session['user']

        db = get_db()
        user_cur = db.execute("SELECT * FROM users WHERE name = ?;", [user])
        user_result = user_cur.fetchone()

    return user_result


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template("500.html"), 500


@app.errorhandler(401)
def unauthorized_access(error):
    return render_template("401.html"), 401


@app.route("/", methods=["POST", "GET"])
def index():
    user = get_current_user()
    db = get_db()
    if request.method == "POST":
        pass 

    questions_cur = db.execute(
        """
        SELECT questions.id AS id, questions.question_text AS question_text, askers.name AS asker, experts.name AS expert  FROM questions 
        JOIN users AS askers ON askers.id = questions.asked_by_id 
        JOIN users AS experts ON experts.id = questions.expert_id 
        WHERE questions.answer_text is not null; 
        """
    )
    questions = questions_cur.fetchall()
    return render_template("home.html", user=user, questions=questions)


@app.route("/register", methods=["POST", "GET"])
def register_page():
    user = get_current_user()
    if request.method == "POST":
        db = get_db()

        name = request.form["name"]
        password = request.form['password']

        name_cur = db.execute("SELECT * FROM users WHERE name = ?", [name])
        name_result = name_cur.fetchone()

        if name_result:
            flash(f"Name is already taken {name}! Choose another name.")

            return redirect(url_for('register_page'))

        hashed_password = generate_password_hash(password=password)

        #store the user name and password in the database
        db.execute("INSERT INTO users (name, password, expert, admin) VALUES (?, ?, ?, ?);",\
                  [name, hashed_password, False, False])
        db.commit()

        flash(f"Registered succefully, {name}!")

        return redirect(url_for('login_page'))
    
    return render_template("register.html", user=user)
 

@app.route("/login", methods=["POST", "GET"])
def login_page():
    user = get_current_user()
    if user:
        return redirect(url_for('index'))

    if request.method == "POST":
        db = get_db()

        name = request.form["name"]
        password = request.form["password"] 

        cur = db.execute("SELECT * FROM users WHERE name = ?;", [name])
        result = cur.fetchone()

        if not result:
            flash(f"The name does not exist {name}!")
            return redirect(url_for('login_page'))

        if check_password_hash(result["password"], password=password):
            session["user"] = result["name"]
            flash(f"Successful login, {name}!")

            return redirect(url_for('index'))
        else:
            flash(f"Try again, wrong password {name}!")

            return redirect(url_for('login_page'))
        
    return render_template("login.html", user=user)


@app.route("/question/<question_id>")
def question_page(question_id):
    user = get_current_user()
    db = get_db()
    question_cur = db.execute(
        """
        SELECT questions.id AS id, questions.question_text AS question_text, questions.answer_text AS answer_text, askers.name AS asker, experts.name AS expert  FROM questions 
        JOIN users AS askers ON askers.id = questions.asked_by_id 
        JOIN users AS experts ON experts.id = questions.expert_id 
        WHERE questions.id = ?; 
        """, 
        [question_id]
    )
    question = question_cur.fetchone()
    return render_template("question.html", user=user, question=question)


@app.route("/ask", methods=["POST", "GET"])
def ask_page():
    user = get_current_user()
    db = get_db()

    if not user:
        flash("Login to ask!")

        return redirect(url_for('login_page'))
    
    if user['admin'] != 0 and user['expert'] != 0:
        return abort(401)
    
    if request.method == "POST":

        expert = int(request.form['expert'])
        question = request.form['question']

        if not user:
            return "User not logged in!"
        
        db.execute("INSERT INTO questions (question_text, asked_by_id, expert_id) VALUES (?, ?, ?);", [question, user['id'], expert])
        db.commit()

        flash(f"Question asked successfully, {session['user']}!")

        return redirect(url_for('index'))
    
    experts_cur = db.execute("SELECT id, name FROM users WHERE expert = 1;")
    experts_result = experts_cur.fetchall()

    return render_template("ask.html", user=user, experts_result=experts_result)


@app.route("/answer/<question_id>", methods=['POST', 'GET'])
def answer_page(question_id):
    user = get_current_user()
    db = get_db()

    if not user:
        return redirect(url_for('login_page'))
    
    if user['expert'] != 1:
        return redirect(url_for('index'))

    user_id = int(user['id'])

    question_cur = db.execute("SELECT expert_id FROM questions WHERE id = ?", [question_id])
    question = question_cur.fetchone()

    if int(question['expert_id']) != user_id:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        answer = request.form['answer']

        db.execute("UPDATE questions SET answer_text = ? WHERE id = ?;", [answer, question_id])
        db.commit()

        flash(f"Question answered successfully, {session['user']}!")

        return redirect(url_for('unanswered_page'))
        
    question_cur = db.execute("SELECT id, question_text FROM questions WHERE id = ?", [int(question_id)])
    question = question_cur.fetchone()

    return render_template("answer.html", user=user, question=question)


@app.route("/unanswered")
def unanswered_page():
    user = get_current_user()
    db = get_db()

    if not user:
        return redirect(url_for('login_page'))
    
    if user['expert'] != 1:
        return redirect(url_for('index'))

    questions_cur = db.execute("""
        SELECT questions.id AS id, questions.question_text AS question_text, users.name AS asker
        FROM questions JOIN users ON users.id = questions.asked_by_id
        WHERE questions.answer_text is null 
        AND questions.expert_id = ?;           
    """, [user["id"]])
    questions = questions_cur.fetchall()

    return render_template("unanswered.html", user=user, questions=questions)


@app.route("/users")
def user_page():
    user = get_current_user()
    db = get_db()

    if not user:
        return redirect(url_for('login_page'))
    
    if user['admin'] != 1:
        abort(401)
    
    users_cur = db.execute("SELECT * FROM users;")
    users_result = users_cur.fetchall()
    return render_template("users.html", user=user, users_result=users_result)


@app.route("/promote/<user_id>")
def promote(user_id):
    user = get_current_user()
    
    if not user:
        abort(401)
    
    if user['admin'] != 1:
        abort(401)
    
    db = get_db()
    db.execute("UPDATE users SET expert = 1 WHERE id = ?;", [user_id])
    db.commit()
    
    flash(f"User promoted successfully, {session['user']}!")

    return redirect(url_for('user_page'))


@app.route("/logout")
def logout_page():
    user = get_current_user()
    if not user:
        return redirect(url_for('index'))
    session.pop("user", None)
    flash(f"Logout successful, {user['name']}!")
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)