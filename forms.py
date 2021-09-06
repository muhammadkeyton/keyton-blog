from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL,InputRequired,ValidationError
from flask_ckeditor import CKEditorField

def password_check(form,field):
    if len(field.data) < 8:
        raise ValidationError('password must be atleast 8 characters long.')

def email_check(form,field):
    if "@" not in field.data:
        raise ValidationError("Invalid email address make sure you type in a real email address.eg(must contain '@')")
##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired,email_check])
    password = PasswordField("Password", validators=[InputRequired(), password_check])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log in")

class Comment_(FlaskForm):
    comment = CKEditorField("Comment",validators=[DataRequired()])
    submit = SubmitField("Add comment")
