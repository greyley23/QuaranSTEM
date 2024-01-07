from flask import Blueprint, render_template, request, flash, redirect, url_for, abort, current_app
from werkzeug.utils import secure_filename
from .models import User, comment, content
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from functools import wraps
import os


auth = Blueprint('Views', __name__)

@auth.route('/sign-up', methods=['GET', 'POST'])
def Sign_Up():
    if request.method == 'POST':
        username = request.form.get('username')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        user= User.query.filter_by(username=username).first()
        if user:
            flash('username already exists', category = 'error')
        elif not username or len(username) < 5:
            flash('Username must be greater than 5 letters', category='error')
        elif not password1 or len(password1) < 8:
            flash('Password must be greater than 7 letters', category='error')
        elif password1 != password2:
            flash('Passwords are not equal', category='error')
        else:
            new_user= User(username=username, password=generate_password_hash(password1, method='pbkdf2:sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return redirect(url_for('views_blueprint.home'))
    return render_template("SignUp.html")



@auth.route('/login', methods=['GET', 'POST'])
def Login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"Entered Username: {username}")

        user = User.query.filter(User.username.collate('binary') == username).first()

        print(f"User from Database: {user}") 

        if user and check_password_hash(user.password, password):
            flash('logged in successfully!', category='success')
            login_user(user, remember=True)
            return redirect(url_for('views_blueprint.home'))
        else:
            flash('incorrect username or password', category='error')
    else:
        flash('Invalid request method', category='error')
    return render_template("Login.html", user=current_user)


@auth.route('/logout')
@login_required
def Logout():
    logout_user()
    return redirect(url_for("views_blueprint.home"))


@auth.route('/post_comments', methods=['POST','GET'])
def post_comments():
    comment_text = request.form.get('comment_text')
    if comment_text:
        new_comment = comment(user_id=current_user.id, comment_text=comment_text)
        db.session.add(new_comment)
        db.session.commit()
        flash('Comment posted successfully!', 'success')
    else:
        flash('Comment cannot be empty.', 'error')
    
    return render_template('comments.html')

@auth.route('/view_comments', methods= ['GET'])
def view_comments():
    comments = comment.query.all()
    return render_template('view_comments.html', comments=comments)

def admin_required(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)
    return decorated_view

@auth.route('/delete_comment/<int:comment_id>', methods=['POST', 'GET'])
@login_required
@admin_required
def delete_comment(comment_id):
    comment_instance = comment.query.get_or_404(comment_id)
    db.session.delete(comment_instance)
    db.session.commit()
    return redirect(url_for('auth_blueprint.view_comments'))


@auth.route('/admin_panel')
@login_required
@admin_required
def admin_panel():
    return render_template('admin_panel.html')

@auth.route('/upload_content', methods=['POST'])
@login_required
@admin_required
def upload_content():
    image = request.files['image']
    text = request.form['text']
    link = request.form['link']
    topic = request.form['topic']
    uploads_folder = os.path.join(current_app.root_path, 'static', 'uploads')
    os.makedirs(uploads_folder, exist_ok=True)

    filename = secure_filename(image.filename)
    image_path = os.path.join(uploads_folder, filename)
    image.save(image_path)

    new_content = content(image_path=filename, text=text, link=link, topic=topic, user=current_user)
    db.session.add(new_content)
    db.session.commit()

    return redirect(url_for('auth_blueprint.admin_panel'))

@auth.route('/content')
def show_content():
    grouped_content = {}
    try:
        content_items = content.query.order_by(content.topic).all()
        if not content_items:
            print("no comments_items found")
    except Exception as e:
        print(f"error querying the database: {e}")
    
    for item in content_items:
        if item.topic not in grouped_content:
            grouped_content[item.topic] = []
        grouped_content[item.topic].append({
            'image_path': url_for('static', filename='uploads/' + item.image_path),
            'text': item.text,
            'link': item.link,
            })

    return render_template('content.html', grouped_content=grouped_content)


