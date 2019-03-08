from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flaskblog.models import User
from flask_login import current_user




class RegistrationForm(FlaskForm):
	username = StringField("Username",validators=[DataRequired(), Length(min=6,max=20)])
	email = StringField("Email",validators=[DataRequired(),Email()])
	password = PasswordField("Passowrd",validators=[DataRequired(),Length(min=6,max=15)])
	confirm_password = PasswordField("Confirm Password",validators=[DataRequired(),Length(min=6,max=15), EqualTo('password')])
	submit = SubmitField("Sign Up")

	def validate_username(self,username):
		user = User.query.filter_by(username=username.data).first()
		if user:
			raise ValidationError('The username you entered is taken, try another one')

	def validate_email(self,email):
		user = User.query.filter_by(email=email.data).first()
		if user:
			raise ValidationError('An account with similar email address is already active, try another one')



class LoginForm(FlaskForm):
	email = StringField("Email",validators=[DataRequired(),Email()])
	password = PasswordField("Passowrd",validators=[DataRequired(),Length(min=6,max=15)])
	remember = BooleanField("Remember Me")
	submit = SubmitField("Sign In")


class UpdateForm(FlaskForm):
	username = StringField("Username",validators=[DataRequired(), Length(min=6,max=20)])
	email = StringField("Email",validators=[DataRequired(),Email()])
	picture = FileField("Update Profile Picture", validators=[FileAllowed(["jpg","png"])])
	submit = SubmitField("Update")

	def validate_username(self,username):
		if username.data != current_user.username:
			user = User.query.filter_by(username=username.data).first()
			if user:
				raise ValidationError('The username you entered is taken, try another one')

	def validate_email(self,email):
		if email.data != current_user.email:
			user = User.query.filter_by(email=email.data).first()
			if user:
				raise ValidationError('An account with similar email address is already active, try another one')



class RequestResetForm(FlaskForm):
	email = StringField("Email",validators=[DataRequired(),Email()])
	submit = SubmitField("Request Password Reset")
	def validate_email(self,email):
		user = User.query.filter_by(email=email.data).first()
		if user is None:
			raise ValidationError('An account with this Email does not exists')


class ResetPasswordForm(FlaskForm):
	password = PasswordField("Passowrd",validators=[DataRequired(),Length(min=6,max=15)])
	confirm_password = PasswordField("Confirm Password",validators=[DataRequired(),Length(min=6,max=15), EqualTo('password')])
	submit = SubmitField("Reset Password")