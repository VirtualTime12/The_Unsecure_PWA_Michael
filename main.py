from flask import Flask, render_template, request, redirect, session
import user_management as dbHandler
from flask_wtf.csrf import CSRFProtect
from urllib.parse import urlparse, urljoin
import pyotp
import qrcode
from io import BytesIO
import base64
import validation as valid
import os

# Code snippet for logging a message
# app.logger.critical("message")

# from flask_cors import CORS
app = Flask(__name__)
# Enable CORS to allow cross-origin requests (needed for CSRF demo in Codespaces)
# CORS(app)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)


def is_safe_url(target: str) -> bool:
    host_url = request.host_url
    ref_url = urlparse(host_url)
    test_url = urlparse(urljoin(host_url, target))
    return (test_url.scheme in ("http", "https")) and (
        ref_url.netloc == test_url.netloc
    )


@app.route("/setup2fa.html", methods=["GET", "POST"])
def setup_2fa():
    if "username" not in session:
        return redirect("/")

    if request.method == "GET":
        username = session["username"]
        # Generate new secret
        secret = pyotp.random_base32()
        session["temp_secret"] = secret

        # Generate QR code
        totp = pyotp.TOTP(secret)
        qr = qrcode.QRCode()
        qr.add_data(totp.provisioning_uri(name=username, issuer_name="UnsecurePWA"))
        qr.make()

        img = qr.make_image()
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        qr_code_b64 = base64.b64encode(buffer.getvalue()).decode()
        return render_template(
            "/setup2fa.html", qr_code=qr_code_b64, secret=secret, state=True
        )

    elif request.method == "POST":
        code = request.form.get("code", "")
        secret = session.get("temp_secret", "")
        username = session["username"]

        if not code or not secret:
            return render_template("/setup2fa.html", msg="Invalid request", state=True)

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            dbHandler.saveTotp(username, secret)
            session.pop("temp_secret", None)
            return render_template(
                "/home.html", msg="2FA enabled successfully", state=True
            )
        else:
            return render_template(
                "/setup2FA.html", msg="Invalid code", secret=secret, state=True
            )


@app.route("/verify2fa.html", methods=["POST", "GET"])
def verify_2fa():
    if request.method == "GET":
        return render_template("/verify2fa.html")

    elif request.method == "POST":
        username = session.get("temp_username", "")
        code = request.form.get("code", "")

        if not username or not code:
            return render_template("/verify2fa.html", msg="Missing username or code")

        # Retrieve stored secret from database
        secret = dbHandler.getTotp(username)

        if not secret:
            return render_template("/index.html", msg="2FA not enabled for this user")

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            # Verification successful
            session["username"] = username
            session.pop("temp_username", None)
            dbHandler.listFeedback()
            return redirect("/home.html")
        else:
            return render_template("/verify2fa.html", msg="Invalid code")


@app.route("/success.html", methods=["POST", "GET"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not is_safe_url(url):
            return render_template("/index.html", msg="Invalid Redirect URL")
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form.get("feedback", "")

        if not valid.is_present(feedback):
            return render_template(
                "/success.html", state=True, msg="Feedback required to submit"
            )

        if not valid.is_reasonable_length(feedback, 1, 1000):
            return render_template(
                "/success.html",
                state=True,
                msg="Feedback too long (Max 1000 characters)",
            )

        safe_feedback = valid.sanitise(feedback)
        dbHandler.insertFeedback(safe_feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not is_safe_url(url):
            return render_template("/index.html", msg="Invalid Redirect URL")
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        DoB = request.form.get("dob", "")

        if (
            not valid.is_present(username)
            or not valid.is_present(password)
            or not valid.is_present(DoB)
        ):
            return render_template("/signup.html", msg="All areas must be filled")

        if not valid.is_reasonable_length(username, 3, 100):
            return render_template("/signup.html", msg="Username unreasonable length")

        if not valid.is_reasonable_length(password, 8, 250):
            return render_template(
                "/signup.html", msg="Password must be at least 8 characters"
            )

        if not valid.unique_username(username):
            return render_template("/signup.html", msg="Username already taken")

        if not valid.valid_password(password):
            return render_template(
                "/signup.html",
                msg="Password must contain at least one uppercase, lowercase, digit, special character",
            )

        if not valid.safe_chars(username):
            return render_template(
                "/signup.html", msg="Username contains invalid characters"
            )

        if not valid.valid_date(DoB):
            return render_template(
                "/signup.html", msg="Invalid date format. Must be in DD/MM/YYYY"
            )

        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/home.html", methods=["GET"])
def home():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not is_safe_url(url):
            return render_template("/home.html", state=True, msg="Invalid Redirect URL")
        return redirect(url, code=302)
    else:
        return render_template("/home.html", state=True)


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def login():
    # Simple Dynamic menu
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not is_safe_url(url):
            return render_template("/index.html", msg="Invalid Redirect URL")
        return redirect(url, code=302)
    # Pass message to front end
    elif request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("/index.html", msg=msg)
    elif request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if not valid.is_present(username) or not valid.is_present(password):
            return render_template("/index.html", msg="Invalid Login")

        if not valid.safe_chars(username):
            return render_template("index.html", msg="Invalid Login")

        isLoggedIn = dbHandler.retrieveUsers(username, password)

        if isLoggedIn:
            # Check if user has 2FA enabled
            if dbHandler.hasTotp(username):
                session["temp_username"] = username
                return redirect("/verify2fa.html")
            else:
                session["username"] = username
                dbHandler.listFeedback()
                return render_template(
                    "/home.html", value=valid.sanitise(username), state=True
                )

        return render_template("/index.html", msg="Invalid Login")

    return render_template("/index.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="0.0.0.0", port=5000)
    # ssl_context="adhoc")
