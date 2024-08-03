from wtforms.fields.form import FormField
from wtforms.fields.list import FieldList

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.fields.simple import PasswordField, TextAreaField
from wtforms.validators import DataRequired, EqualTo
from wtforms.widgets.core import TextArea
from flask_wtf.file import FileField, FileAllowed
from wtforms_sqlalchemy.fields import QuerySelectField


class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password_hash = PasswordField('Password',
                                  validators=[DataRequired(), EqualTo('password_hash2', message='Must match')])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired()])
    profile_pic = FileField('Profile Pic')
    submit = SubmitField("Submit")


class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    profile_pic = FileField('Profile Pic')
    submit = SubmitField("Submit")


class CategoryForm(FlaskForm):
    category_name = StringField('Category Name', validators=[DataRequired()])
    image = FileField('Image')
    submit = SubmitField("Submit")

#
# class BookForm(FlaskForm):
#     title = StringField('Title', validators=[DataRequired()])
#     author = StringField('Author', validators=[DataRequired()])
#     description = StringField('Description', validators=[DataRequired()])
#     image = FileField('image')
#     category = QuerySelectField('Category', query_factory=lambda: Category.query.all(), get_label='name',
#                                 allow_blank=False)
#     submit = SubmitField("Submit")
#
#
# class PreviewForm(FlaskForm):
#     title = StringField('Title', validators=[DataRequired()])
#     author = StringField('Author', validators=[DataRequired()])
#     description = StringField('Description', validators=[DataRequired()])
#     image = FileField('image')
#     category = QuerySelectField('Category', query_factory=lambda: Category.query.all(), get_label='name',
#                                 allow_blank=False)
#     submit = SubmitField("Submit")


class ContentForm(FlaskForm):
    image = FileField('Image')
    content = TextAreaField('Content')
    submit = SubmitField('Submit')


class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post Comment')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Log In')


class PublishForm(FlaskForm):
    submit = SubmitField('Publish')


class EditBookForm(FlaskForm):
    title = StringField('Title')
    description = TextAreaField('Description')
    image = FileField('Image', validators=[FileAllowed(['jpg', 'png'], 'Images only!')])
    content_forms = FieldList(FormField(ContentForm))
    submit = SubmitField('Update Book')


class SearchForm(FlaskForm):
    searched = StringField('Searched', validators=[DataRequired()])
    submit = SubmitField('Submit')
