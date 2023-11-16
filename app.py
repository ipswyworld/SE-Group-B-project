from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from datetime import datetime
from wtforms import StringField, PasswordField, FileField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import DataRequired, Email, ValidationError, Length, EqualTo
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from config import get_config
from PIL import Image
import io
import os
import base64  # Import base64

app = Flask(__name__, template_folder='templates')
app.config['UPLOAD_FOLDER'] = 'static/profile_pictures'
app.config.from_object(get_config())

# Initialize Flask-SQLAlchemy
db = SQLAlchemy(app)

# Initialize Alembic
migrate = Migrate(app, db)

# Initialize Bcrypt
bcrypt = Bcrypt(app)

MAX_IMAGE_SIZE_IN_BYTES = 16 * 1024 * 1024  # 16 MB (adjust as needed)


# Define a custom filter to base64 encode the data
def b64encode_data(data):
    return base64.b64encode(data).decode('utf-8')  # Decode to convert bytes to a string

app.jinja_env.filters['b64encode'] = b64encode_data  # Register the filter

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    user_picture = db.Column(db.LargeBinary, nullable=True)

    def save_picture(self, user_picture):
        with app.app_context():
            self.user_picture = user_picture
        db.session.commit()

    def get_picture(self):
        return self.user_picture


class SignupForm(db.Model):
    __tablename__ = 'signupform'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = StringField('Username', validators=[DataRequired()], id='username-field')
    email = StringField('Email', validators=[DataRequired(), Email()], id='email-field')
    password = PasswordField('Password', validators=[DataRequired()], id='password-field')
    password_repeat = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')], id='password-repeat-field')
    user_picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg']), FileRequired()], id='picture-field')
    submit = SubmitField('Sign Up', id='submit-button')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email address already in use. Please choose a different email address.')
    
    def validate_picture(form, field):
        if not is_valid_image(field.data):
            raise ValidationError('Invalid image file')
        
def is_valid_image(file):
    try:
        image = Image.open(io.BytesIO(file.read()))
        if image.format.lower() not in ['jpeg', 'png', 'gif', 'jpg']:
            return False
        if len(file.read()) > MAX_IMAGE_SIZE_IN_BYTES:
            return False
        return True
    except Exception as e:
        return False
    
class LoginForm(db.Model):
    __tablename__ = 'loginform'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Issue(db.Model):
    __tablename__ = 'issues'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    user = db.relationship('User', backref='issues')

class CommentForm(FlaskForm):
    text = TextAreaField('Comment', validators=[DataRequired()])
 
class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    issue_id = db.Column(db.Integer, db.ForeignKey('issues.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)
    
    # Define a relationship with the User model to represent the author of the comment
    user = db.relationship('User', backref='comments')
    
    # Define a relationship with the Issue model to represent the issue the comment is associated with
    issue = db.relationship('Issue', backref='comments')

    # Define a one-to-many relationship with reviews
    reviews = db.relationship('Review', backref='comment', lazy='dynamic')

# Create a form for adding reviews
class AddReviewForm(FlaskForm):
    review_text = TextAreaField('Review', validators=[DataRequired()])

class Review(db.Model):
    __tablename__ = 'reviews'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow)

    user = db.relationship('User', backref='reviews')


# Create a form for editing a comment
class EditCommentForm(FlaskForm):
    new_comment_text = TextAreaField('Edit Comment', validators=[DataRequired()])
    
# Create a form for changing the username
class ChangeUsernameForm(FlaskForm):
    current_username = StringField('Current Username', validators=[DataRequired()])
    new_username = StringField('New Username', validators=[DataRequired()])
    submit = SubmitField('Change Username')


# Create a form for changing or removing the profile picture
class ChangeProfilePictureForm(FlaskForm):
    picture = FileField('Profile Picture', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Image files only')])
    submit = SubmitField('Change Profile Picture')

# Create a form for changing the password
class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')


routes = {
    "home": "home",
    "login": "login",
    "signup": "signup",
    "profile": "profile",
    "issues": "issues",
    "add_issue": "add_issue",
    "comments": "comments",
    "add_comment": "add_comment",
    "edit_comment": "edit_comment",
    "delete_comment": "delete_comment",
    "add_review": "add_review",
    "view_reviews": "view_reviews",
    "change_password": "change_password",
    "change_username": "change_username",
    
}

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Successful login
            session['user_id'] = user.id
            session['username'] = user.username  # Set the 'username' in the session
            flash('Login successful', 'success')
            return redirect(url_for(routes['profile'], username=user.username))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_repeat = request.form['password_repeat']
        user_picture = request.files['user_picture']  # Use request.files to get the uploaded picture

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            # Check if the passwords match
            if password != password_repeat:  # Use 'password' and 'password_repeat' directly
                flash('Passwords do not match', 'error')
            elif User.query.filter_by(email=email).first():
                flash('Email already exists', 'error')
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

                new_user = User(username=username, email=email, password=hashed_password)

                # Handle profile picture if provided
                if user_picture:
                    if is_valid_image(user_picture):
                        # Extract and save the profile picture data
                        new_user_picture = user_picture.read()
                        new_user.user_picture = new_user_picture

                db.session.add(new_user)
                db.session.commit()

                flash('Registration successful', 'success')
                return redirect(url_for(routes['login']))

    return render_template('signup.html')

@app.route("/profile/<username>", methods=['GET', 'POST'])
def profile(username):
    user = User.query.filter_by(username=username).first()
    
    if user:
        if request.method == 'POST':
            new_username = request.form['username']
            new_email = request.form['email']
            new_picture = request.files.get('user_picture')

            if new_picture and is_valid_image(new_picture):
                new_user_picture = new_picture.read()
                user.save_picture(new_user_picture)

            user.username = new_username
            user.email = new_email
            db.session.commit()

        comments = Comment.query.filter_by(user=user).all()  # Get comments created by the user
        edit_comment_form = EditCommentForm()

        # Query for the comments along with their associated issue and order by creation date
        comments = db.session.query(Comment, Issue).join(Issue).filter(Comment.user == user).order_by(Comment.created_at.desc()).all()

        change_password_form = ChangePasswordForm()
        change_username_form = ChangeUsernameForm()
        return render_template('profile.html', user=user, comments=comments, edit_comment_form=edit_comment_form, change_password_form=change_password_form, change_username_form=change_username_form)
    return render_template('404.html')

@app.route("/edit_comment/<int:comment_id>", methods=['GET', 'POST'])
def edit_comment(comment_id):
    comment = Comment.query.get(comment_id)

    if not comment:
        flash('Comment not found', 'error')
        return redirect(url_for(routes['profile'], username=session['username']))

    if request.method == 'POST':
        if comment.user_id == session['user_id']:
            new_text = request.form.get('new_comment_text')
            comment.text = new_text
            db.session.commit()
            flash('Comment updated successfully', 'success')
        else:
            flash('You are not authorized to edit this comment', 'error')
        return redirect(url_for(routes['profile'], username=session['username']))

    return render_template('edit_comment.html', comment=comment)

# Add a route to delete a comment
@app.route("/delete_comment/<int:comment_id>", methods=['POST'])
def delete_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if comment.user_id == session['user_id']:
        db.session.delete(comment)
        db.session.commit()
        flash('Comment deleted successfully', 'success')
    else:
        flash('You are not authorized to delete this comment', 'error')

    return redirect(url_for(routes['profile'], username=session['username']))


# Route to serve profile pictures
@app.route('/profile/<username>/picture')
def get_profile_picture(username):
    user = User.query.filter_by(username=username).first()
    
    if user and user.user_picture:
        return send_file(io.BytesIO(user.user_picture), mimetype='image/jpeg')
    else:
        flash('Profile picture not found', 'error')
        return redirect(url_for(routes['home']))

# Route to    
@app.route('/add_issue', methods=['GET', 'POST'])
def add_issue():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        # Get the current user (assuming you have user authentication in place)
        user = User.query.get(session['user_id'])

        new_issue = Issue(title=title, description=description, user=user)
        db.session.add(new_issue)
        db.session.commit()
        flash('Issue added successfully', 'success')
        return redirect(url_for(routes['issues']))
    
    return render_template('add_issue.html')
    
# Route to view issues
@app.route('/issues')
def issues():
    issues = Issue.query.all()
    search_term = request.args.get('search')
    if search_term:
        issues = Issue.query.filter(
            (Issue.title.like(f'%{search_term}%')) | (Issue.description.like(f'%{search_term}%'))
        ).all()
    else:
        issues = Issue.query.all()

    user = None  # Initialize the user as None for guest users
    if 'user_id' in session:
        user = User.query.get(session['user_id'])  # Assuming you store the user ID in the session

    return render_template('issues.html', issues=issues, user=user)


# Add Comment Route
@app.route("/add_comment/<int:issue_id>", methods=["GET", "POST"])
def add_comment(issue_id):
    issue = Issue.query.get(issue_id)
    form = CommentForm()  # Create an instance of the CommentForm

    if request.method == "POST" and form.validate_on_submit():
        text = form.text.data  # Get the comment text from the form

        # Get the current user (assuming you have user authentication in place)
        user = User.query.get(session["user_id"])

        if text:
            new_comment = Comment(text=text, user=user, issue=issue)
            db.session.add(new_comment)
            db.session.commit()
            flash("Comment added successfully", "success")
            return redirect(url_for(routes['comments'], issue_id=issue_id))  # Redirect to the comments page for the issue
    return render_template("add_comment.html", issue=issue, form=form)

# View Comments Route
@app.route("/comments/<int:issue_id>")
def comments(issue_id):
    issue = Issue.query.get(issue_id)
    comments = Comment.query.filter_by(issue=issue).all()

    user = None  # Initialize the user as None for guest users
    if 'user_id' in session:
        user = User.query.get(session['user_id'])  # Assuming you store the user ID in the session

    return render_template("comments.html", issue=issue, comments=comments, user=user)

@app.route("/view_reviews/<int:comment_id>")
def view_reviews(comment_id):
    comment = Comment.query.get(comment_id)

    if not comment:
        flash("Comment not found", "error")
        return redirect(url_for("comments", issue_id=comment.issue.id))

    reviews = Review.query.filter_by(comment=comment).all()
    # Flash an info message when there are no reviews
    if not reviews:
        flash("No reviews available for this comment", "info")

    return render_template("view_reviews.html", comment=comment, reviews=reviews)

@app.route("/add_review/<int:comment_id>", methods=["GET", "POST"])
def add_review(comment_id):
    comment = Comment.query.get(comment_id)
    form = AddReviewForm()  # Create a form for adding reviews

    if request.method == "POST" and form.validate_on_submit():
        review_text = form.review_text.data  # Get the review text from the form

        # Get the current user (assuming you have user authentication in place)
        user = User.query.get(session["user_id"])

        if review_text:
            new_review = Review(text=review_text, user=user, comment=comment)
            db.session.add(new_review)
            db.session.commit()
            flash("Review added successfully", "success")
            return redirect(url_for("comments", issue_id=comment.issue.id))  # Redirect to the comments page for the issue

    return render_template("add_review.html", comment=comment, form=form)

# Route to Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Clear the user_id from the session
    flash('You have been logged out', 'success')
    return redirect(url_for(routes['home'])) # Redirect to the home page or any other desired page

# Profile management routes
# Route to change username
@app.route("/profile/<username>/change-username", methods=['POST', 'GET'])
def change_username(username):
    # Retrieve the current user
    user = User.query.filter_by(username=username).first()

    if not user:
        return render_template('404.html')

    if request.method == 'POST':
        current_username = request.form.get('current_username')
        new_username = request.form.get('new_username')

        if current_username != user.username:
            flash('Current username does not match. Please try again.', 'error')
            return redirect(url_for(routes['profile'], username=username))

        existing_user = User.query.filter_by(username=new_username).first()
        if existing_user:
            flash('The new username is already in use. Please choose another.', 'error')
            return redirect(url_for(routes['profile'], username=username))

        user.username = new_username
        db.session.commit()

        flash('Username updated successfully. Please log in with your new username.', 'success')

        # Clear the user's session data
        session.clear()

        # Optionally, redirect to your login page for the user to log in again
        return redirect(url_for(routes['login']))

    return render_template('change_username.html', user=user)



# Route to handle change password form submission
# Route to change password
@app.route("/profile/<username>/change-password", methods=['GET', 'POST'])
def change_password(username):
    user = User.query.filter_by(username=username).first()

    if not user:
        flash('User not found', 'error')
        return redirect(url_for(routes['profile'], username=username))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not bcrypt.check_password_hash(user.password, current_password):
            flash('Incorrect current password', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password = hashed_password
            db.session.commit()
            flash('Password updated', 'success')
            return redirect(url_for(routes['profile'], username=username))

    return render_template('change_password.html', user=user)

# Route to handle change or remove profile picture form submission
@app.route("/profile/<username>/change-picture", methods=['POST'])
def change_picture(username):
    user = User.query.filter_by(username=username).first()

    if user:
        new_picture = request.files.get('user_picture')

        if new_picture:
            if is_valid_image(new_picture):
                # Save the new profile picture to the directory
                picture_filename = secure_filename(new_picture.filename)
                picture_path = os.path.join(app.config['UPLOAD_FOLDER'], picture_filename)
                new_picture.save(picture_path)

                # Update the 'user_picture' column in the users table
                with open(picture_path, 'rb') as image_file:
                    new_user_picture = image_file.read()
                    user.user_picture = new_user_picture
                    db.session.commit()
                    flash('Profile picture updated', 'success')
            else:
                flash('Invalid image format or size', 'error')
        else:
            # Remove the profile picture
            user.user_picture = None
            db.session.commit()
            flash('Profile picture removed', 'success')

    return redirect(url_for(routes['profile'], username=username))


if __name__ == "__main__":
    app.run(debug=True)