from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, PasswordField, TextAreaField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'flask_api'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Init mysql
mysql = MySQL(app)
Articles = Articles()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
      return render_template('about.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/articles')
def articles():
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    if result > 0:
        return render_template("articles.html", articles=articles)
    else:
        msg = 'No Articles found'
        return redirect(url_for('dashboard'), msg=msg)
    cur.close()


@app.route('/article/<string:id>/')
def article(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM articles WHERE id=%s", [id])
    article = cur.fetchone()
    return render_template('article.html', article=article)


class RegisterForm(Form):
    name = StringField('Name', validators=[validators.Length(min=1, max=50)])
    username = StringField('User Name', validators=[validators.Length(min=4, max=25)])
    email = StringField('Email', validators=[validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
      validators.DataRequired(),
      validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET', 'POST'])
def register():
      form = RegisterForm(request.form)
      if request.method == 'POST' and form.validate():
            name = form.name.data
            email = form.email.data
            username = form.username.data
            password = sha256_crypt.encrypt(str(form.password.data))

            # Create cursor
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                (name, email, username, password)
            )

            # Commit to db
            mysql.connection.commit()

            # Close connection
            cur.close()
            flash('You are now registered and can log in', 'success')
            return redirect(url_for('login'))
      return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candicate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])
        if result > 0:
            data = cur.fetchone()
            password = data['password']

            # Compare password
            print(sha256_crypt.verify(password_candicate, password))
            if sha256_crypt.verify(password_candicate, password):
                session['logged_in'] = True
                session['username'] = username
                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Password do not match'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')


def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Create Cursor
    cur = mysql.connection.cursor()

    # Excute
    result = cur.execute("SELECT * FROM articles")
    articles = cur.fetchall()
    if result > 0:
        return render_template('dashboard.html', articles=articles)
    else:
        msg = 'No Articles found'
        return render_template('dashboard.html', msg=msg)
    return render_template('dashboard.html')


class ArticleForm(Form):
    title = StringField('Title', validators=[validators.Length(min=1, max=200)])
    body = TextAreaField('Body', validators=[validators.Length(min=30)])


@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST':
        title = form.title.data
        body = form.body.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Excute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)", (title, body, session['username']))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()
        flash('Article Created', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug=True)
