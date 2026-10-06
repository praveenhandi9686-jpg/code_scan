from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
now = lambda: datetime.now(timezone.utc)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=now)

class CodeReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    language = db.Column(db.String(20), nullable=False)
    source_code = db.Column(db.Text, nullable=False)
    overall_score = db.Column(db.Integer)
    security_score = db.Column(db.Integer)
    quality_score = db.Column(db.Integer)
    maintainability_score = db.Column(db.Integer)
    reliability_score = db.Column(db.Integer)
    summary = db.Column(db.Text, default="")
    ai_status = db.Column(db.String(200), default="")
    created_at = db.Column(db.DateTime, default=now)
    findings = db.relationship("Finding", cascade="all, delete-orphan", backref="review")

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review_id = db.Column(db.Integer, db.ForeignKey("code_review.id"), nullable=False)
    category = db.Column(db.String(30)); severity = db.Column(db.String(10))
    title = db.Column(db.String(200)); line_number = db.Column(db.Integer)
    code = db.Column(db.Text); explanation = db.Column(db.Text)
    impact = db.Column(db.Text); recommendation = db.Column(db.Text)
    suggested_fix = db.Column(db.Text); confidence = db.Column(db.Float)
    status = db.Column(db.String(12), default="Potential")
    source = db.Column(db.String(10), default="static")
    FIELDS = ["category","severity","title","line_number","code","explanation","impact",
              "recommendation","suggested_fix","confidence","status","source"]
    def to_dict(self): return {k: getattr(self, k) for k in ["id"] + self.FIELDS}
