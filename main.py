from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask_cors import CORS
import user_management as dbHandler
from flask_wtf.csrf import CSRFProtect
import os
from urllib.parse import urlparse, urljoin


from validation import (
    is_present,
    is_reasonable_length,
    safe_chars,
    valid_date,
    sanitise,
    valid_password,
)

# Code snippet for logging a message
# app.logger.critical("message")

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


@app.route("/success.html", methods=["POST", "GET"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not is_safe_url(url):
            return render_template("/index.html", msg="Invalid Redirect URL")
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form.get("feedback", "")

        if not is_present(feedback):
            return render_template(
                "/success.html", state=True, msg="Feedback required to submit"
            )

        if not is_reasonable_length(feedback, 1, 1000):
            return render_template(
                "/success.html",
                state=True,
                msg="Feedback too long (Max 1000 characters)",
            )

        safe_feedback = sanitise(feedback)
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

        if not is_present(username) or not is_present(password) or not is_present(DoB):
            return render_template("/signup.html", msg="All areas must be filled")

        if not is_reasonable_length(username, 3, 100):
            return render_template("/signup.html", msg="Username unreasonable length")

        if not is_reasonable_length(password, 8, 250):
            return render_template(
                "/signup.html", msg="Password must be at least 8 characters"
            )

        if not valid_password(password):
            return render_template(
                "/signup.html",
                msg="Password must contain at least one uppercase, lowercase, digit, special character",
            )

        if not safe_chars(username):
            return render_template(
                "/signup.html", msg="Username contains invalid characters"
            )

        if not valid_date(DoB):
            return render_template(
                "/signup.html", msg="Invalid date format. Must be in DD/MM/YYYY"
            )

        dbHandler.insertUser(username, password, DoB)
        return render_template("/index.html")
    else:
        return render_template("/signup.html")


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
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
        isLoggedIn = dbHandler.retrieveUsers(username, password)

        if not is_present(username) or not is_present(password):
            return render_template("/index.html", msg="Invalid Login")

        if not safe_chars(username):
            return render_template("index.html", msg="Invalid Login")

        if isLoggedIn:
            dbHandler.listFeedback()
            return render_template("/success.html", value=username, state=isLoggedIn)

        return render_template("/index.html", msg="Invalid Login")

    return render_template("/index.html")


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=False, host="0.0.0.0", port=5000)
    # ssl_context="adhoc")
