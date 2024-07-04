from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from forms import LoginForm, RegisterForm, MessageForm
from encryption import encrypt_message, decrypt_message, generate_keypair  # Added encryption functions
from models import User, Message, db
from flask_migrate import Migrate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def fetch_or_generate_public_key(user_id):
    user = User.query.get(user_id)
    if user and user.public_key:
        # Deserialize the stored PEM-encoded public key back to RSAPublicKey object
        public_key = serialization.load_pem_public_key(
            user.public_key.encode(),  # Assuming stored as PEM-encoded string
            backend=default_backend()
        )
        return public_key
    else:
        # Generate new keypair and store public key
        private_key, public_key = generate_keypair()
        # Serialize the public key to PEM format for storage
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        user.public_key = pem_public_key  # Store public key as PEM-encoded string in database
        db.session.commit()
        return public_key

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('dashboard.html')
    else:
        return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Fetch existing users and add them as contacts for the new user
        existing_users = User.query.filter(User.id != new_user.id).all()
        for user in existing_users:
            new_user.contacts.append(user)

        db.session.commit()

        flash('You have successfully registered!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    form = MessageForm()
    form.set_choices(current_user.id)  # Set recipient choices for the current user

    if form.validate_on_submit():
        recipient = User.query.get(form.recipient.data)
        if recipient:
            # Fetch or generate public key for encryption
            public_key = fetch_or_generate_public_key(recipient.id)
            if not public_key:
                flash('Recipient does not have a public key set.', 'error')
                return redirect(url_for('send_message'))

            # Encrypt the message
            encrypted_message = encrypt_message(form.message.data, public_key)
            if encrypted_message:
                try:
                    # Create and save the message
                    new_message = Message(content=encrypted_message, sender=current_user, recipient=recipient, timestamp=datetime.utcnow())
                    db.session.add(new_message)
                    db.session.commit()
                    flash('Message sent successfully', 'success')
                except Exception as e:
                    flash(f"An error occurred: {str(e)}", "error")
                    db.session.rollback()
            else:
                flash('Failed to encrypt the message.', 'error')

        else:
            flash('Recipient not found', 'error')

    return render_template('send_message.html', form=form)

@app.route('/inbox')
@login_required
def inbox():
    messages = Message.query.filter_by(recipient=current_user).order_by(Message.timestamp.desc()).all()
    return render_template('inbox.html', messages=messages)

@app.route('/message/<int:message_id>')
@login_required
def view_message(message_id):
    message = Message.query.get_or_404(message_id)
    if message.recipient != current_user:
        abort(403)
    decrypted_message = decrypt_message(message.content, current_user.private_key)
    return render_template('view_message.html', message=message, decrypted_message=decrypted_message)

@app.route('/members')
@login_required
def members():
    contacts = current_user.contacts
    return render_template('members.html', contacts=contacts)

@app.route('/sent_messages')
@login_required
def sent_messages():
    messages = Message.query.filter_by(sender=current_user).order_by(Message.timestamp.desc()).all()
    return render_template('sent_messages.html', messages=messages)

if __name__ == '__main__':
    app.run(debug=True)
