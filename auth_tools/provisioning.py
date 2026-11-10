"""Find, link or create the CTFd user for an external identity."""

import hashlib

from sqlalchemy.exc import IntegrityError

from CTFd.cache import clear_user_session
from CTFd.models import Users, db
from CTFd.utils import get_config
from CTFd.utils.logging import log

from .models import AuthIdentity

NAME_MAX = 128
EMAIL_MAX = 128
SUBJECT_MAX = 255


class ProvisioningError(Exception):
    """Raised when an identity cannot be mapped to a usable account."""


def normalize_subject(subject):
    subject = subject.strip()
    if len(subject) > SUBJECT_MAX:
        return "sha256:" + hashlib.sha256(subject.encode("utf-8")).hexdigest()
    return subject


def lookup(provider, subject):
    identity = AuthIdentity.query.filter_by(
        provider=provider, subject=normalize_subject(subject)
    ).first()
    return identity.user if identity else None


def _unique_name(base):
    base = (base or "user").strip()
    if "@" in base:
        # CTFd rejects names that look like email addresses at registration.
        base = base.split("@", 1)[0] or "user"
    base = base[:NAME_MAX]
    candidate = base
    n = 1
    while Users.query.filter_by(name=candidate).first() is not None:
        n += 1
        suffix = "-{}".format(n)
        candidate = base[: NAME_MAX - len(suffix)] + suffix
    return candidate


def _find_link_target(provider, link_by, name, email):
    if link_by == "email" and email:
        user = Users.query.filter_by(email=email).first()
    elif link_by == "name" and name:
        matches = Users.query.filter_by(name=name).limit(2).all()
        user = matches[0] if len(matches) == 1 else None
    else:
        return None

    if user is None:
        return None
    # Never hand an admin account to an external identity automatically.
    if user.type == "admin":
        return None
    # Don't attach a second identity from the same provider to an account.
    if AuthIdentity.query.filter_by(provider=provider, user_id=user.id).first():
        return None
    return user


def _under_user_limit():
    limit = int(get_config("num_users", default=0) or 0)
    if not limit:
        return True
    return Users.query.filter_by(banned=False, hidden=False).count() < limit


def resolve_user(provider, subject, name=None, email=None, auto_create=True, link_by=""):
    """
    Return the Users row for (provider, subject), linking or creating one if
    needed. Raises ProvisioningError if no account can be used.
    """
    subject = normalize_subject(subject)
    if not subject:
        raise ProvisioningError("Empty identity.")

    user = lookup(provider, subject)
    if user is not None:
        return user

    email = (email or "").strip()[:EMAIL_MAX] or None
    # With no display name supplied, the identity itself is the name, both for
    # linking by name and for naming a new account.
    name = (name or "").strip() or subject

    user = _find_link_target(provider, link_by, name, email)
    created = False
    if user is None:
        if not auto_create:
            raise ProvisioningError("No CTFd account is linked to this identity.")
        if not _under_user_limit():
            raise ProvisioningError("This CTF has reached its maximum number of users.")
        if email and Users.query.filter_by(email=email).first() is not None:
            # Email is unique in CTFd; don't steal it from an unlinked account.
            email = None
        user = Users(name=_unique_name(name), email=email, verified=True)
        db.session.add(user)
        created = True

    try:
        db.session.flush()
        db.session.add(AuthIdentity(provider=provider, subject=subject, user_id=user.id))
        db.session.commit()
    except IntegrityError:
        # Another request created the same identity concurrently (common in
        # header mode, where a page load fires many requests at once).
        db.session.rollback()
        user = lookup(provider, subject)
        if user is None:
            raise
        return user

    log(
        "registrations" if created else "logins",
        "[{date}] {ip} - auth_tools {action} user {name} for {provider} identity {subject}",
        action="created" if created else "linked",
        name=user.name,
        provider=provider,
        subject=subject,
    )
    clear_user_session(user_id=user.id)
    return user
