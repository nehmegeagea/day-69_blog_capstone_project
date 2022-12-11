from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os

# from sqlalchemy import Table, Column, Integer, ForeignKey
# from sqlalchemy.ext.declarative import declarative_base
#
# Base = declarative_base()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
    #'8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250))
    # this will act like a list of BlogPost object attached to each user
    # author refers to author property in BlogPost class
    posts = relationship('BlogPost', back_populates="author")
    # this will act like a list of Comment object attached o each user
    #
    comments = relationship('Comment', back_populates='comment_writer')
db.create_all()


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create a foreign key , user refers to the name of User table
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    #Create references to the User object, posts refers to the posts property in the User class
    #  the author property of BlogPost is now a User object.
    author = relationship("User", back_populates="posts")
    # this will act like a list of Comment Object
    comments = relationship('Comment', back_populates='blog_post')
db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # Create a foreign key , user refers to the name of User table
    user_id=db.Column(db.Integer, db.ForeignKey('user.id'))
    # Create a foreign key , blog_posts refers to the name of BlogPost table
    blogpost_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    #Create references to the BlogPost object
    blog_post = relationship('BlogPost', back_populates="comments")
    comment_writer = relationship('User', back_populates="comments")
db.create_all()
#Create admin_only decorater

from functools import wraps
from flask import abort

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403, description="Resource not authorized")
        return f(*args, **kwargs)
    return decorated_function


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/', methods=["POST", "GET"])
def get_all_posts():
    posts = BlogPost.query.all()
    login = request.args.get("login")
    id = request.args.get("id")
    return render_template("index.html", all_posts=posts, login=login, id=id)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit() :
        hashed_password= generate_password_hash(
            password=form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        if db.session.query(User).filter_by(email=form.email.data).first() :
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('login'))
            # error = "You 've already registred with this email, log in instead!"
            # return render_template('login.html', error = error, form=LoginForm())
        new_user=User(
            email = form.email.data ,
            password = hashed_password,
            name = form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form = form)


@app.route('/login', methods = ["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter_by(email=form.email.data).first()
        if user :
            if check_password_hash(user.password, form.password.data) :
                login_user(user)
                posts = BlogPost.query.all()
                return render_template("index.html", all_posts=posts, login=True, id=user.id)
            else :
                flash("Incorrect password, please try again!")
                return render_template("login.html", form=form)
        else :
            flash("The email you tried to log in with does not exist, please try again!")
            return render_template("login.html", form=form)
    return render_template("login.html", form = form)


@app.route('/logout')
def logout():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, login=False)


@app.route("/post/<int:post_id>")
@login_required
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if current_user.is_authenticated :
            new_comment = Comment(
                text = form.text.data
            )
            db.session.add(new_comment)
            db.session.commit()
        else :
            flash("You need to log in before submitting a comment!")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form, current_user=current_user, comments=requested_post.comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post")
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

