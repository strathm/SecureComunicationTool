from extensions import db
from datetime import datetime
from flask_login import UserMixin
from flask_migrate import Migrate

migrate = Migrate()

# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key = db.Column(db.String(500))  # Adding public_key field for encryption
    private_key = db.Column(db.String(500))  # Adding private_key field for decryption

    # Relationships for messages sent and received
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', back_populates='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', back_populates='recipient', lazy=True)

    # Define contacts relationship for many-to-many
    contacts = db.relationship('User',
                               secondary='contacts',
                               primaryjoin='User.id == contacts.c.user_id',
                               secondaryjoin='User.id == contacts.c.contact_id',
                               backref='contacted_by',
                               lazy=True)

# Define Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships with back_populates
    sender = db.relationship('User', foreign_keys=[sender_id], back_populates='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], back_populates='received_messages')


# Define contacts table for many-to-many relationship
contacts = db.Table('contacts',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('contact_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)
