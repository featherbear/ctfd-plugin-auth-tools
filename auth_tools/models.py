from sqlalchemy.dialects import mysql

from CTFd.models import db


def case_sensitive_string(length):
    """
    VARCHAR that compares case-sensitively everywhere. MySQL/MariaDB default
    collations are case-insensitive, which would let "aBc" and "AbC" (distinct
    OIDC subjects) collide.
    """
    binary = mysql.VARCHAR(length, collation="utf8mb4_bin")
    return db.String(length).with_variant(binary, "mysql").with_variant(binary, "mariadb")


class AuthIdentity(db.Model):
    """
    Maps an external identity (provider + subject) to a CTFd user.

    CTFd has no built-in column suited to this: ``users.oauth_id`` is an
    integer reserved for MajorLeagueCyber, and ``name``/``email`` can be
    changed by the user. A dedicated table gives a stable, unique key.
    """

    __tablename__ = "auth_tools_identities"
    __table_args__ = (
        db.UniqueConstraint("provider", "subject", name="uq_auth_tools_provider_subject"),
    )

    id = db.Column(db.Integer, primary_key=True)
    # "header" for the reverse-proxy header, or the OIDC issuer URL.
    provider = db.Column(case_sensitive_string(128), nullable=False)
    subject = db.Column(case_sensitive_string(255), nullable=False)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    user = db.relationship("Users", foreign_keys=[user_id], lazy="joined")
