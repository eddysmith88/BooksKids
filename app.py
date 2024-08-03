from flask import Flask, render_template, request, flash, redirect, url_for, jsonify
import uuid as uuid
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from flask_login import login_user, current_user, logout_user, LoginManager, login_required

from config import Config
from werkzeug.utils import secure_filename
import os

from wtforms.fields.form import FormField
from wtforms.fields.list import FieldList

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.fields.simple import PasswordField, TextAreaField
from wtforms.validators import DataRequired, EqualTo
from wtforms.widgets.core import TextArea
from flask_wtf.file import FileField, FileAllowed
from wtforms_sqlalchemy.fields import QuerySelectField

from forms import UserForm, LoginForm, EditProfileForm, CategoryForm, ContentForm, PublishForm, CommentForm, \
    EditBookForm, SearchForm

app = Flask(__name__)

app.config.from_object(Config)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Flask login stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('home'))


@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('You are logged in.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Wrong password try again.', 'danger')
        else:
            flash('User does not exist')
    return render_template('login.html', form=form)


@app.route('/like/<int:book_id>', methods=['POST'])
@login_required
def like_post(book_id):
    book = Book.query.get_or_404(book_id)
    like = Like.query.filter_by(user_id=current_user.id, book_id=book_id).first()

    if like:
        db.session.delete(like)
        message = 'Like removed'
    else:
        new_like = Like(user_id=current_user.id, book_id=book_id)
        db.session.add(new_like)
        message = 'Like added'

    db.session.commit()

    likes_count = Like.query.filter_by(book_id=book_id).count()

    return jsonify({
        'message': message,
        'likes_count': likes_count,
        'liked': not bool(like)
    })


@app.route('/like/<int:book_id>', methods=['POST'])
@login_required
def like_book(book_id):
    book = Book.query.get_or_404(book_id)
    like = Like.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if like:
        db.session.delete(like)
        message = 'You have unliked this book.'
    else:
        new_like = Like(user_id=current_user.id, book_id=book_id)
        db.session.add(new_like)
        message = 'You have liked this book.'
    db.session.commit()
    likes_count = Like.query.filter_by(book_id=book_id).count()
    return jsonify({'message': message, 'likes_count': likes_count})


@app.route('/favorite/<int:book_id>', methods=['POST'])
@login_required
def favorite_book(book_id):
    book = Book.query.get_or_404(book_id)
    favorite = Favorite.query.filter_by(user_id=current_user.id, book_id=book_id).first()
    if favorite:
        db.session.delete(favorite)
        message = 'This book has been removed from your favorites.'
    else:
        new_favorite = Favorite(user_id=current_user.id, book_id=book_id)
        db.session.add(new_favorite)
        message = 'This book has been added to your favorites.'
    db.session.commit()
    return jsonify({'message': message})


@app.route('/')
def home():
    page = request.args.get('page', 1, type=int)
    book_pagination = Book.query.order_by(Book.date_added.desc()).paginate(page=page, per_page=5)
    category = Category.query.all()
    form = CommentForm()

    return render_template('home.html', book=book_pagination.items, pagination=book_pagination,
                           category=category, form=form)


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    form = UserForm()

    if request.method == 'POST':
        user = User.query.filter_by(username=form.username.data).first()
        if user is None:
            username = request.form['username']
            email = request.form['email']
            password_hash = request.form['password_hash']
            profile_pic = request.files['profile_pic']

            hashed_pw = generate_password_hash(password_hash, method="pbkdf2:sha256")

            if profile_pic and allowed_file(profile_pic.filename):
                filename = secure_filename(profile_pic.filename)
                filename_with_uuid = str(uuid.uuid1()) + "_" + filename
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_uuid))
                image_path = filename_with_uuid

                new_user = User(username=username, email=email, password_hash=hashed_pw, profile_pic=image_path)
                db.session.add(new_user)
                db.session.commit()
                flash('Your account has been created!', 'success')
                return redirect(url_for('login'))  # Redirect to a specific view after successful user creation
        else:
            flash('User already exists with this email.', 'danger')

    our_users = User.query.all()
    return render_template('add_user.html', form=form, our_users=our_users)


@app.route('/edit_profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_profile(user_id):
    form = EditProfileForm()
    name_to_update = User.query.get_or_404(user_id)

    if form.validate_on_submit():
        name_to_update.username = form.username.data
        name_to_update.email = form.email.data
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename_with_uuid = str(uuid.uuid1()) + "_" + filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_uuid))
                name_to_update.profile_pic = filename_with_uuid
        db.session.commit()
        flash('Profile updated!')
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', form=form, name_to_update=name_to_update, user_id=user_id)


@app.route('/admin_menu')
@login_required
def admin_menu():
    if current_user.id == 1:
        return render_template('admin_menu.html')
    else:
        flash('You are not authorized to access this page.')
        return redirect(url_for('home'))


@app.route('/add_book', methods=['GET', 'POST'])
@login_required
def create_book():
    form = PreviewForm()

    if form.validate_on_submit():
        title = form.title.data
        description = form.description.data
        file = form.image.data
        category = request.form['category']
        user_id = current_user.id

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename_with_uuid = str(uuid.uuid1()) + "_" + filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_uuid))
            image_path = filename_with_uuid

            add_book = PreviewBook(title=title, description=description, image=image_path, user_id=user_id,
                                   category_id=category, author=current_user.username)
            try:
                db.session.add(add_book)
                db.session.commit()
                flash("Your book main title has been added!", "success")
                return redirect(url_for('add_content', user_id=add_book.id))
            except Exception as e:
                db.session.rollback()
                flash(f"An error occurred: {e}", "danger")
    else:
        # Log form errors to help with debugging
        for field, errors in form.errors.items():
            for error in errors:
                print(f"Error in the {field} field - {error}")

    return render_template('add_book.html', form=form)


@app.route('/add_content/<int:user_id>', methods=['GET', 'POST'])
@login_required
def add_content(user_id):
    book = PreviewBook.query.get_or_404(user_id)
    form = ContentForm()

    add_contents = Content.query.filter_by(preview_id=book.id).all()

    if form.validate_on_submit():
        content = form.content.data
        file = form.image.data
        user_id = current_user.id
        image_path = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename_with_uuid = str(uuid.uuid1()) + "_" + filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_uuid))
            image_path = filename_with_uuid

        new_content = Content(content=content, image=image_path, preview_id=book.id, user_id=user_id)
        db.session.add(new_content)
        db.session.commit()

        flash("Your content has been added!", "success")
        return redirect(url_for('add_content', user_id=book.id))
        # TODO очистити поле
    else:
        # Log form errors to help with debugging
        for field, errors in form.errors.items():
            for error in errors:
                print(f"Error in the {field} field - {error}")
    return render_template('add_content.html', form=form, book=book,
                           add_contents=add_contents)


@app.route('/new_book/<int:user_id>', methods=['GET', 'POST'])
@login_required
def new_book(user_id):
    book = PreviewBook.query.get_or_404(user_id)
    content = Content.query.filter_by(preview_id=book.id).all()
    form = PublishForm()

    if form.validate_on_submit():
        published = Book(title=book.title, description=book.description, image=book.image,
                         user_id=current_user.id, preview_id=book.id, category_id=book.category_id, author=current_user.username)
        db.session.add(published)
        db.session.commit()
        flash('New book published successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('new_book.html', form=form, book=book, content=content)


@app.route('/add_category', methods=['GET', 'POST'])
@login_required
def add_category():
    form = CategoryForm()
    if form.validate_on_submit():
        # Зберегти файл
        file = form.image.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Додати категорію до бази даних
        add_category = Category(name=form.category_name.data, image=filename)
        form.category_name.data = ''
        db.session.add(add_category)
        db.session.commit()
        flash('Category added', "success")
        return redirect(url_for('admin_menu'))
    return render_template('add_category.html', form=form)


@app.route('/category_list')
@login_required
def category_list():
    category = Category.query.all()
    return render_template('category_list.html', category=category)


@app.route('/books_list')
@login_required
def books_list():
    page = request.args.get('page', 1, type=int)
    book_pagination = Book.query.paginate(page=page, per_page=5)
    categories = Category.query.all()
    form = CommentForm()
    return render_template('books_list.html', book=book_pagination.items, pagination=book_pagination,
                           categories=categories, form=form)


@app.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    content_books = Content.query.filter_by(preview_id=book.preview_id).all()

    book_form = EditBookForm()
    content_forms = [ContentForm(prefix=f'content_{content.id}') for content in content_books]

    if request.method == 'GET':
        book_form.title.data = book.title
        book_form.description.data = book.description
        for form, content in zip(content_forms, content_books):
            form.content.data = content.content

    if book_form.validate_on_submit():
        book.title = book_form.title.data
        book.description = book_form.description.data

        if 'image' in request.files:
            file = request.files['image']
            if file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename_with_uuid = str(uuid.uuid1()) + "_" + filename
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_uuid))
                book.image = filename_with_uuid
        db.session.commit()
        # flash('Book updated successfully!', 'success')
        return redirect(url_for('edit_book', book_id=book.id))

    for form, content in zip(content_forms, content_books):
        if form.validate_on_submit():
            content.content = form.content.data
            if form.image.data:
                file = form.image.data
                if allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filename_with_uuid = str(uuid.uuid1()) + "_" + filename
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename_with_uuid))
                    content.image = filename_with_uuid
            db.session.commit()
            # flash('Content updated successfully!', 'success')
            return redirect(url_for('edit_book', book_id=book.id))

    return render_template('edit_book.html', book_form=book_form, book=book, content_forms=content_forms)


@app.route('/category/<int:category_id>')
def books_by_category(category_id):
    category = Category.query.get_or_404(category_id)
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Ви можете змінити кількість постів на сторінку
    pagination = Book.query.filter_by(category_id=category_id).paginate(page=page, per_page=per_page, error_out=False)
    books = pagination.items
    form = CommentForm()
    return render_template('book_by_category.html', category=category, books=books,
                           pagination=pagination, form=form)


@app.route('/read/<int:book_id>')
def read_page(book_id):
    book = Book.query.get_or_404(book_id)
    contents = Content.query.filter_by(preview_id=book.preview_id).all()
    return render_template('read_page.html', book=book, contents=contents)


@app.route('/book_info:<int:book_id>', methods=['GET', 'POST'])
def book_info(book_id):
    book = Book.query.get_or_404(book_id)
    rec_books = Book.query.filter_by(category_id=book.category_id).all()
    comments = Comment.query.filter_by(book_id=book_id).all()
    likes_count = Like.query.filter_by(book_id=book_id).count()
    liked = Like.query.filter_by(user_id=current_user.id, book_id=book_id).first() is not None
    favorites_count = Favorite.query.filter_by(book_id=book_id).count()

    form = CommentForm()
    formatted_date = book.date_added.strftime('%d.%m.%Y')

    if form.validate_on_submit():
        new_comment = Comment(content=form.content.data, user_id=current_user.id, book_id=book.id)
        db.session.add(new_comment)
        db.session.commit()
        flash('Your comment has been posted!', 'success')
        return redirect(url_for('book_info', book_id=book.id))

    return render_template('book_info.html', comments=comments, likes_count=likes_count, liked=liked,
                           favorites_count=favorites_count, book=book, form=form, formatted_date=formatted_date,
                           rec_books=rec_books)


@app.route('/books/delete/<int:book_id>', methods=['GET', 'POST'])
@login_required
def delete_book(book_id):
    book_to_delete = Book.query.get_or_404(book_id)
    user_id = current_user.id

    delete_content = Content.query.filter_by(preview_id=book_to_delete.id).all()
    if user_id == book_to_delete.user_id:
        try:
            db.session.delete(book_to_delete)
            db.session.delete(delete_content)
            db.session.commit()
            # flash('Post deleted successfully!')
            book = Book.query.order_by(Book.date_added)
            return redirect(url_for('books_list'))
        except:
            # flash('Something wrong! Try again!')
            book = Book.query.order_by(Book.date_added)
            return render_template('books_list.html', book=book)
    else:
        flash('You not author of this post!')
        book = Book.query.order_by(Book.date_added)
        return render_template('home.html', book=book)


# @app.route('/recommends/<int:category_id>')
# @login_required
# def recommends(category_id):
#     category = Category.query.get_or_404(category_id)
#     books = Book.query.filter_by(category_id=category_id)
#
#     return render_template('book_info.html', books=books, category=category)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    favorites = Favorite.query.filter_by(user_id=current_user.id).all()
    favorite_books = [favorite.book for favorite in favorites]
    category = Category.query.all()
    return render_template('profile.html', favorite_books=favorite_books, category=category)


"""Models"""


class User(db.Model, UserMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(65), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    profile_pic = db.Column(db.String(), nullable=True)

    books = db.relationship('Book', backref='user', lazy=True)
    preview_book = db.relationship('PreviewBook', backref='user', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True)
    # comments = db.relationship('Comment', backref='user', lazy=True)
    content = db.relationship('Content', backref='user', lazy=True)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    __tablename__ = 'category'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(65), unique=True, nullable=False)
    image = db.Column(db.String(), nullable=True)

    def __repr__(self):
        return f'<Category {self.name}>'


class Book(db.Model):
    __tablename__ = 'book'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(65), unique=True, nullable=False)
    author = db.Column(db.String(65), unique=False, nullable=False)
    description = db.Column(db.String(), nullable=True)
    image = db.Column(db.String(60), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    preview_id = db.Column(db.Integer, db.ForeignKey('preview_book.id'))
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'))

    likes = db.relationship('Like', backref='book', lazy='dynamic')
    favorites = db.relationship('Favorite', backref='book', lazy='dynamic')
    category = db.relationship('Category', backref='books', lazy=True)

    @property
    def likes_count(self):
        return self.likes.count()

    @property
    def is_liked(self):
        if current_user.is_authenticated:
            return Like.query.filter_by(user_id=current_user.id, book_id=self.id).count() > 0
        return False

    @property
    def is_favorite(self):
        if current_user.is_authenticated:
            return Favorite.query.filter_by(user_id=current_user.id, book_id=self.id).count() > 0
        return False


class PreviewBook(db.Model):
    __tablename__ = 'preview_book'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(65), unique=True, nullable=False)
    author = db.Column(db.String(65), unique=False, nullable=False)
    description = db.Column(db.String(), nullable=True)
    image = db.Column(db.String(60), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    content = db.relationship('Content', backref='preview_book', lazy=True)


class Content(db.Model):
    __tablename__ = 'content'

    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.String(60), nullable=True)
    content = db.Column(db.String(), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    preview_id = db.Column(db.Integer, db.ForeignKey('preview_book.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    book = db.relationship('Book', backref='content', lazy=True)


class Like(db.Model):
    __tablename__ = 'like'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)


class Comment(db.Model):
    __tablename__ = 'comment'

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='comments')
    book = db.relationship('Book', backref='comments')

class Favorite(db.Model):
    __tablename__ = 'favorite'

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date_added = db.Column(db.DateTime, default=datetime.utcnow)


class BookForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    author = StringField('Author', validators=[DataRequired()])
    description = StringField('Description', validators=[DataRequired()])
    image = FileField('image')
    category = QuerySelectField('Category', query_factory=lambda: Category.query.all(), get_label='name',
                                allow_blank=False)
    submit = SubmitField("Submit")


class PreviewForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    # author = StringField('Author', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    image = FileField('image')
    category = QuerySelectField('Category', query_factory=lambda: Category.query.all(), get_label='name',
                                allow_blank=False)
    submit = SubmitField("Submit")


@app.route('/search', methods=['GET', 'POST'])
def search():
    form = SearchForm()
    books = []
    if request.method == 'POST' and form.validate_on_submit():
        # Отримуємо дані з відправленої форми
        searched = form.searched.data
        # Пошук у базі даних
        books = Book.query.filter(Book.title.like('%' + searched + '%')).order_by(Book.title).all()
        return render_template('search.html', form=form, searched=searched, books=books)
    return render_template('search.html', form=form, books=books)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.context_processor
def base():
    form = SearchForm()
    return dict(form=form)


if __name__ == '__main__':
    app.run(debug=True)
