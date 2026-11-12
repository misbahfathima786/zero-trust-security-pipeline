
import hmac
from urllib.parse import urlparse

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    current_app
)
from flask_login import (
    login_user,
    logout_user,
    current_user
)

from app.extensions import db
from app.models.user import User
from app.forms import LoginForm, SignupForm, ForgotPasswordForm


auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash("Login successful!", "success")

            next_page = request.args.get("next")

            # Only allow safe, local redirects.
            if next_page:
                parsed_url = urlparse(next_page)
                if not parsed_url.scheme and not parsed_url.netloc:
                    return redirect(next_page)

            return redirect(url_for("dashboard.index"))

        flash("Invalid email or password.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = SignupForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        invite_code = current_app.config.get("TEAM_INVITE_CODE")

        if not invite_code:
            flash("Registration is currently unavailable.", "danger")

        elif not hmac.compare_digest(
            form.invite_code.data.strip(),
            invite_code
        ):
            flash("Invalid team invitation code.", "danger")

        elif User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "warning")

        else:
            user = User(
                display_name=form.display_name.data.strip(),
                email=email
            )
            user.set_password(form.password.data)

            db.session.add(user)
            db.session.commit()

            flash("Account created successfully. You can now log in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/signup.html", form=form)


@auth_bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        # Email-based password reset will be implemented later.
        flash(
            "Password reset by email is not available yet. "
            "Please contact your project administrator.",
            "info"
        )

    return render_template("auth/forgot_password.html", form=form)
