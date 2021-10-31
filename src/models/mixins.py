from datetime import datetime

from src.db.postgres import db


class AuditMixin:
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now)
    update_at = db.Column(
        db.DateTime(timezone=True), default=datetime.now, onupdate=datetime.now
    )
