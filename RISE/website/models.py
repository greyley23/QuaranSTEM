from . import db 
from datetime import datetime
from flask_login import UserMixin 
from sqlalchemy.sql import func

class comment(db.Model):
    id= db.Column(db.Integer, primary_key = True)
    comment_text= db.Column(db.String(10000))
    Timestamp= db.Column(db.DateTime(timezone=True), default=func.now(), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= True)
    user = db.relationship('User', backref='user_comments', lazy=True)

class User(db.Model, UserMixin): 
    id = db.Column(db.Integer, primary_key=True)
    username= db.Column(db.String(150), unique= True, nullable=False)
    password= db.Column(db.String(10000), nullable= False)
    comments = db.relationship('comment', backref='comments_user', lazy=True)
    is_admin= db.Column(db.Boolean, default= False)
class content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('contents', lazy=True))
    image_path = db.Column(db.String(255), nullable=True)
    text = db.Column(db.Text, nullable=True)
    link = db.Column(db.String(255), nullable=True)
    topic = db.Column(db.String(255), nullable=False)

def __repr__(self):
        return f"<File {self.id}: {self.filename}>"