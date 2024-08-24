from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_admin.contrib.sqla import ModelView
from flask_login import UserMixin, current_user
import random
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, ForeignKey, DateTime, Float

db = SQLAlchemy()

# SecureModelView class
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    test_results = db.relationship('TestResult', back_populates='user', lazy=True)
    accesses = db.relationship('TestAccess', back_populates='user', lazy=True)
    access_requests = db.relationship('TestAccessRequest', back_populates='user', lazy=True)

# Test model
class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    question_count = db.Column(db.Integer, nullable=False, default=10)
    test_results = relationship('TestResult', back_populates='test', cascade='all, delete-orphan')
    questions = relationship('Question', back_populates='test', cascade='all, delete-orphan')
    accesses = db.relationship('TestAccess', back_populates='test', lazy=True, cascade="all, delete-orphan")
    access_requests = db.relationship('TestAccessRequest', back_populates='test', lazy=True, cascade="all, delete-orphan")
   
    def get_random_questions(self):
        """Get a random subset of questions based on question_count."""
        return random.sample(self.questions, min(len(self.questions), self.question_count))
    


# Question model
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=True)
    option_d = db.Column(db.String(200), nullable=True)
    correct_answer = db.Column(db.String(1), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)

    test = db.relationship('Test', back_populates='questions')
    missed_questions = db.relationship('MissedQuestion', back_populates='question', lazy=True)

    def get_user_answer(self, test_result, user_answers=None):
        """
            Get the user's answer to this question.
            :param test_result: The TestResult instance for this test.
            :param user_answers: A dictionary of user answers, if available.
            :return: The user's answer to this question.
            """
            # Check if the question was missed
        missed_question = MissedQuestion.query.filter_by(test_result_id=test_result.id, question_id=self.id).first()
        if missed_question:
                return missed_question.user_answer  # Return the user's incorrect answer
            
            # If not missed, return the answer from the provided dictionary
        if user_answers:
                return user_answers.get(self.id, None)
            
            # If user_answers is not provided, you could handle it as needed
        return None



# TestAccess model
class TestAccess(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    is_accessible = db.Column(db.Boolean, default=True)
    attempts = db.Column(db.Integer, default=0)

    user = db.relationship('User', back_populates='accesses')
    test = db.relationship('Test', back_populates='accesses')

# TestResult model
class TestResult(db.Model):
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
        test_id = Column(Integer, ForeignKey('test.id', ondelete='CASCADE'), nullable=False)
        score = Column(Float, nullable=False)
        date_submitted = Column(DateTime, default=datetime.utcnow)

        user = relationship('User', back_populates='test_results')
        test = relationship('Test', back_populates='test_results')
        missed_questions = relationship('MissedQuestion', back_populates='test_result', cascade='all, delete-orphan')

        def __init__(self, user_id, test_id, score):
            self.user_id = user_id
            self.test_id = test_id
            self.score = score

# TestAccessRequest model
class TestAccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    test_id = db.Column(db.Integer, db.ForeignKey('test.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'approved', 'denied'
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    response_date = db.Column(db.DateTime)
    admin_comment = db.Column(db.String(500))

    user = db.relationship('User', back_populates='access_requests')
    test = db.relationship('Test', back_populates='access_requests')

# MissedQuestion model
class MissedQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    test_result_id = db.Column(db.Integer, db.ForeignKey('test_result.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_answer = db.Column(db.String(200), nullable=False)

    test_result = db.relationship('TestResult', back_populates='missed_questions')
    question = db.relationship('Question', back_populates='missed_questions')
