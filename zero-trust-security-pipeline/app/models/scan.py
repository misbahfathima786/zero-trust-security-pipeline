from datetime import datetime, timezone
import json
from app.extensions import db


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # 'archive', 'source', 'text', 'manifest'
    file_size = db.Column(db.Integer, nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    scans = db.relationship("ScanRun", backref="project", cascade="all, delete-orphan", lazy="dynamic")
    user = db.relationship("User", backref=db.backref("projects", lazy="dynamic"))

    def __repr__(self):
        return f"<Project {self.name} (id={self.id})>"


class ScanRun(db.Model):
    __tablename__ = "scan_runs"

    id = db.Column(db.Integer, primary_key=True)
    run_id = db.Column(db.Integer, unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    commit = db.Column(db.String(40), default="upload")
    branch = db.Column(db.String(80), default="main")
    trigger = db.Column(db.String(40), default="manual_upload")
    overall_status = db.Column(db.String(20), nullable=False, default="running")
    duration_s = db.Column(db.Integer, nullable=True)
    timestamp = db.Column(db.String(40), nullable=False)
    data_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    user = db.relationship("User", backref=db.backref("scan_runs", lazy="dynamic"))

    def get_data(self):
        try:
            return json.loads(self.data_json)
        except Exception:
            return {}

    def set_data(self, data):
        self.data_json = json.dumps(data)

    def __repr__(self):
        return f"<ScanRun #{self.run_id} status={self.overall_status}>"
