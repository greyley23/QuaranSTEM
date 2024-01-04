from flask import Blueprint, render_template
from flask_login import current_user

views = Blueprint('Views', __name__)

visit_count= 0

@views.route('/')
def home():
    global visit_count
    visit_count +=1
    return render_template("home.html", user=current_user)