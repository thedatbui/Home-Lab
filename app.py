import db
import hashlib
import os
import subprocess
from db import get_db
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
import logging
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(
    __name__,
    template_folder="template",
    instance_relative_config=True,
)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.config.from_mapping(
    # vulnerable to forged Flask session cookies because the signing key is hardcoded
    SECRET_KEY="dev",
    # alternatively, you can use an environment variable for the secret key
    # SECRET_KEY=os.environ.get("SECRET_KEY"),

    DATABASE=os.path.join(app.instance_path, "app.sqlite")
)

os.makedirs(app.instance_path, exist_ok=True)

db.init_app(app)

logging.basicConfig(
    filename='/var/log/myapp/app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

logging.getLogger("werkzeug").setLevel(logging.ERROR)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/users/<int:user_id>")
def users(user_id):
    user = get_db().execute(
        "SELECT id, username, role FROM user WHERE id = ?",
        (user_id,)
    ).fetchone()
    if user is None:
        abort(404)
    return render_template("profile.html", user=user)


@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # using weak hashing algorithm (MD5) for password storage, which is vulnerable to brute-force attacks
        password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
        # alternatively, you can use a stronger hashing algorithm like bcrypt or Argon2 for better security.
        # For example, using bcrypt:
        # password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        db = get_db()
        error = None

        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif db.execute(
            "SELECT id FROM user WHERE username = ?", (username,)
        ).fetchone() is not None:
            error = "User {} is already registered.".format(username)

        if error is None:
            db.execute(
                "INSERT INTO user (username, password) VALUES (?, ?)",
                (username, password_hash)
            )
            db.commit()
            logging.info("New user registered: %s", username)
            return redirect(url_for("login"))

        flash(error)

    return render_template("auth/register.html")

@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        password_hash = hashlib.md5(password.encode("utf-8")).hexdigest()
        print(f"Attempting login for username: {username} with password hash: {password_hash}")
        next_url = request.args.get("next", url_for("index"))
        # here next_url is taken directly from the request arguments without validation, which can lead to open redirect vulnerabilities if an attacker crafts a malicious URL.
        # for example, an attacker could send a link like /login?next=http://malicious-site.com to trick users into visiting a malicious site after login.

        query = "SELECT * FROM user WHERE username = ? AND password = ?"
        user = get_db().execute(query, (username, password_hash)).fetchone()

        if user is not None:
            session.clear()
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            logging.info("Successful login for username: %s - ip: %s", username, request.remote_addr)
            # Intentionally accepts an absolute URL to demonstrate an open redirect.
            return redirect(next_url)
            # Alternatively, you can use a safer approach to prevent open redirects by validating the next_url:
            # if not next_url.startswith("/"):
            #     next_url = url_for("index")
            # return redirect(next_url)

        logging.warning("Failed login attempt for username: %s - ip: %s", username, request.remote_addr)
        return "Invalid username or password"

    return render_template("auth/login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/admin")
def admin():
    username = session.get("username")
    if username is None:
        logging.info("Accessing admin page for username: %s - ip: %s", username, request.remote_addr)
        return redirect(url_for("login", next=request.full_path))

    user = get_db().execute(
        "SELECT role FROM user WHERE username = ?", (username,)
    ).fetchone()
    if user is None or user["role"] != "admin":
        logging.warning("Unauthorized access attempt to admin page by username: %s - ip: %s", username, request.remote_addr)
        abort(403)

    reviews = get_db().execute(
        """
        SELECT review.*, product.name AS product_name, user.username
        FROM review
        JOIN product ON product.id = review.product_id
        JOIN user ON user.id = review.author_id
        ORDER BY review.created DESC
        """
    ).fetchall()
    return render_template("admin.html", reviews=reviews)


@app.route("/product/<int:product_id>", methods=("GET", "POST"))
def product(product_id):
    database = get_db()
    product_row = database.execute(
        "SELECT * FROM product WHERE id = ?", (product_id,)
    ).fetchone()
    if product_row is None:
        abort(404)

    if request.method == "POST":
        username = session.get("username")
        if username is None:
            return redirect(url_for("login", next=request.full_path))

        rating = request.form.get("rating", type=int)
        body = request.form.get("body", "").strip()
        author = database.execute(
            "SELECT id FROM user WHERE username = ?", (username,)
        ).fetchone()

        if author is None or rating not in range(1, 6) or not body:
            flash("Invalid review submission. Please ensure you are logged in, the rating is between 1 and 5, and the review body is not empty.")
        else:
            database.execute(
                """
                INSERT INTO review (product_id, author_id, rating, body)
                VALUES (?, ?, ?, ?)
                """,
                (product_id, author["id"], rating, body),
            )
            database.commit()
            flash("Thank you for your review.")
            return redirect(url_for("product", product_id=product_id))

    reviews = database.execute(
        """
        SELECT review.*, user.username
        FROM review
        JOIN user ON user.id = review.author_id
        WHERE review.product_id = ?
        ORDER BY review.created DESC
        """,
        (product_id,),
    ).fetchall()
    return render_template(
        "product.html", product=product_row, reviews=reviews
    )

@app.route("/admin/createUser", methods=("GET", "POST"))
def admin_create_user():
    username = session.get("username")
    if username is None:
        return redirect(url_for("login", next=request.full_path))

    user = get_db().execute(
        "SELECT role FROM user WHERE username = ?", (username,)
    ).fetchone()
    if user is None or user["role"] != "admin":
        abort(403)

    if request.method == "POST":
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_password_hash = hashlib.md5(new_password.encode("utf-8")).hexdigest()
        new_role = request.form["role"]

        db = get_db()
        error = None

        if not new_username:
            error = "Username is required."
        elif not new_password:
            error = "Password is required."
        elif new_role not in ("customer", "admin"):
            error = "Role must be either 'customer' or 'admin'."
        elif db.execute(
            "SELECT id FROM user WHERE username = ?", (new_username,)
        ).fetchone() is not None:
            error = f"User {new_username} is already registered."
        if error is None:
            logging.info("New user created: %s - ip: %s", new_username, request.remote_addr)
            db.execute(
                "INSERT INTO user (username, password, role) VALUES (?, ?, ?)",
                (new_username, new_password_hash, new_role)
            )
            db.commit()
            flash(f"User {new_username} created successfully.")
            return redirect(url_for("admin_create_user"))

        flash(error)

    return render_template("admin_create_user.html")

@app.route("/all-users")
def get_all_users():
    users = get_db().execute("SELECT * FROM user").fetchall()
    return dict(users=[dict(user) for user in users])

@app.route("/admin/uploads", methods=("GET", "POST"))
def admin_uploads():
    username = session.get("username")
    if username is None:
        return redirect(url_for("login"))

    user = get_db().execute(
        "SELECT role FROM user WHERE username = ?", (username,)
    ).fetchone()
    if user is None or user["role"] != "admin":
        abort(403)
   
    return render_template("admin_uploads.html")
    
@app.route("/admin/diagnostics", methods=("GET", "POST"))
def admin_diagnostics():
    username = session.get("username")
    if username is None:
        return redirect(url_for("login", next=request.full_path))

    user = get_db().execute(
        "SELECT role FROM user WHERE username = ?", (username,)
    ).fetchone()
    if user is None or user["role"] != "admin":
        abort(403)

    # Intentionally allows command injection by executing user-controlled input.
    diagnostics = {
        "disk": "df -h",
        "processes": "ps aux",
        "date": "date",
    }
    selected = request.form.get("diagnostic", "date")
    command = diagnostics.get(selected, diagnostics["date"])
    output = subprocess.check_output(
        command,
        shell=True,
        text=True,
    )

    # Alternatively, you can use a safer approach to prevent command injection by validating the selected diagnostic and using a predefined mapping of commands without executing user-controlled input directly.
    # For example:
    # safe_commands = {
    #     "disk": ["df", "-h"],
    #     "processes": ["ps", "aux"],
    #     "date": ["date"],
    # }
    # selected = request.form.get("diagnostic", "date")
    # command = safe_commands.get(selected, safe_commands["date"])
    # output = subprocess.check_output(command, text=True)

    return render_template(
        "admin_diagnostics.html",
        diagnostics=diagnostics,
        selected=selected,
        output=output,
    )


if __name__ == "__main__":
    # vulnerable to command injection because the Flask app is run with debug mode enabled, which can expose sensitive information and allow arbitrary code execution.
    app.run(debug=True, host="0.0.0.0", port=5000)