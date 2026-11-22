import db
import os
import subprocess
import bcrypt
import logging
import requests, msal
import secrets
import hmac
import hashlib, re

from db import get_db
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv


load_dotenv()

app = Flask(
    __name__,
    template_folder="template",
    instance_relative_config=True,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.config.from_mapping(
    # vulnerable to forged Flask session cookies because the signing key is hardcoded
    # SECRET_KEY="dev",
    # alternatively, you can use an environment variable for the secret key
    SECRET_KEY=os.environ["SECRET_KEY"],
    DATABASE=os.path.join(app.instance_path, "app.sqlite")
)


os.makedirs(app.instance_path, exist_ok=True)
db.init_app(app)

def generate_csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": generate_csrf_token}


@app.before_request
def validate_csrf_token():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None

    submitted_token = request.form.get("_csrf_token", "")
    session_token = session.get("_csrf_token", "")
    if not session_token or not hmac.compare_digest(submitted_token, session_token):
        abort(403, description="Invalid or missing CSRF token")

logging.basicConfig(
    filename='/var/log/myapp/app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logging.getLogger("werkzeug").setLevel(logging.ERROR)


oauth = OAuth(app)
oauth.register(
    name="entra",
    client_id=os.environ["ENTRA_CLIENT_ID"],
    client_secret=os.environ["ENTRA_CLIENT_SECRET"],
    server_metadata_url=(
        f"https://login.microsoftonline.com/{os.environ['ENTRA_TENANT_ID']}"
        "/v2.0/.well-known/openid-configuration"
    ),
    client_kwargs={"scope": "openid profile email"},
)

@app.route("/login/entra")
def login_entra():
    return oauth.entra.authorize_redirect(url_for("auth_callback", _external=True))

@app.route("/auth/callback")
def auth_callback():
    token = oauth.entra.authorize_access_token()
    claims = token["userinfo"]

    username = claims["name"]
    oid = claims["oid"]
    roles = claims.get("roles", [])
    role = "admin" if "ShopAdmin" in roles else "customer"

    db_ = get_db()
    db_.execute(
        """INSERT INTO user (username, entra_oid, password, role) VALUES (?, ?, '', ?)
        ON CONFLICT(entra_oid) DO UPDATE SET username = excluded.username, role = excluded.role""",
        (username, oid, role),
    )
    db_.commit()

    user = db_.execute(
        "SELECT * FROM user WHERE entra_oid = ?", (oid,)
    ).fetchone()

    session.clear()
    session.update({
        "username": username,
        "user_id": user["id"],
        "role": user["role"],
        "entra_oid": oid,
    })
    return redirect(url_for("index"))


def graph_token():
    cca = msal.ConfidentialClientApplication(
        os.environ.get("GRAPH_CLIENT_ID", os.environ["ENTRA_CLIENT_ID"]),
        authority=f"https://login.microsoftonline.com/{os.environ['ENTRA_TENANT_ID']}",
        client_credential=os.environ["GRAPH_CLIENT_SECRET"],
    )
    result = cca.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        raise RuntimeError(result.get("error_description", "Unable to acquire a Microsoft Graph token"))
    return result["access_token"]

def create_entra_user(display_name, nickname, upn, temp_password):
    body = {
        "accountEnabled": True,
        "displayName": display_name,
        "mailNickname": nickname,
        "userPrincipalName": upn,  
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "password": temp_password,
        },
    }
    r = requests.post(
        "https://graph.microsoft.com/v1.0/users",
        headers={"Authorization": f"Bearer {graph_token()}"},
        json=body, timeout=10,
    )
    r.raise_for_status()
    return r.json()

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

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        display_name = request.form["display_name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        db = get_db()
        error = None

        if not display_name:
            error = "Name is required."
        elif not EMAIL_RE.match(email):
            error = "A valid email address is required."
        elif not password:
            error = "Password is required."
        elif db.execute("SELECT id FROM user WHERE username = ?", (email,)).fetchone():
            error = "This email is already registered."

        if error is None:
            local = re.sub(r"[^a-z0-9._-]", "", email.split("@", 1)[0]) or "user"
            suffix = hashlib.sha256(email.encode()).hexdigest()[:4]   # évite les collisions d'UPN
            nickname = f"{local}.{suffix}"
            upn = f"{nickname}@{os.environ['ENTRA_DOMAIN']}"
            entra_user = None
            try:
                entra_user = create_entra_user(display_name, nickname, upn, email, password)
            except requests.HTTPError as exc:
                logging.warning("Entra registration failed for %s: %s", email, exc.response.text)
                msg = (exc.response.json().get("error", {}).get("message", "")
                       if exc.response is not None else "")
                error = msg if "password" in msg.lower() else "Unable to create the account."
            except (requests.RequestException, RuntimeError) as exc:
                logging.warning("Entra registration error for %s: %s", email, exc)
                error = "Unable to create the account."

            if error is None:
                try:
                    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                    db.execute("INSERT INTO user (username, password) VALUES (?, ?)",
                               (email, password_hash))
                    db.commit()
                except Exception:
                    db.rollback()
                    try:
                        requests.delete(
                            f"https://graph.microsoft.com/v1.0/users/{entra_user['id']}",
                            headers={"Authorization": f"Bearer {graph_token()}"},
                            timeout=10,
                        ).raise_for_status()
                    except Exception as cleanup_exc:
                        logging.error("Orphan Entra account %s: %s", upn, cleanup_exc)
                    raise
                logging.info("New user registered: %s", email)
                return redirect(url_for("login"))

        flash(error)
    return render_template("auth/register.html")

@app.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        next_url = request.args.get("next", url_for("index"))
        # here next_url is taken directly from the request arguments without validation, which can lead to open redirect vulnerabilities if an attacker crafts a malicious URL.
        # for example, an attacker could send a link like /login?next=http://malicious-site.com to trick users into visiting a malicious site after login.

        user = get_db().execute(
            "SELECT * FROM user WHERE username = ?", (username,)
        ).fetchone()

        password_hash = user["password"] if user is not None else ""
        valid_password = (
            bool(password_hash)
            and bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
        )

        if user is not None and valid_password:
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
    userName = session.get("username")
    user_id = session.get("user_id")

    if userName is None:
        logging.info("Accessing admin page for user: %s - ip: %s", userName, request.remote_addr)
        return redirect(url_for("login", next=request.full_path))

    if user_id is None:
        logging.info("Accessing admin page for user_id: %s - ip: %s", user_id, request.remote_addr)
        return redirect(url_for("login", next=request.full_path))

    user = get_db().execute(
        "SELECT role FROM user WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None or user["role"] != "admin":
        logging.warning("Unauthorized access attempt to admin page by user_id: %s - ip: %s", user_id, request.remote_addr)
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

        user_id = session.get("user_id")
        if user_id is None:
            return redirect(url_for("login", next=request.full_path))

        rating = request.form.get("rating", type=int)
        body = request.form.get("body", "").strip()

        if rating not in range(1, 6) or not body:
            flash("Invalid review submission. Please ensure you are logged in, the rating is between 1 and 5, and the review body is not empty.")
        else:
            database.execute(
                """
                INSERT INTO review (product_id, author_id, rating, body)
                VALUES (?, ?, ?, ?)
                """,
                (product_id, user_id, rating, body),
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
    
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login", next=request.full_path))

    user = get_db().execute(
        "SELECT role FROM user WHERE id = ?", (user_id,)
    ).fetchone()

    if user is None or user["role"] != "admin":
        abort(403)

    if request.method == "POST":
        new_username = request.form["username"]
        new_password = request.form["password"]
        new_password_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
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

# intentionally vulnerable function to display all users in the database 
@app.route("/all-users")
def get_all_users():
    users = get_db().execute("SELECT * FROM user").fetchall()
    return dict(users=[dict(user) for user in users])

@app.route("/admin/uploads", methods=("GET", "POST"))
def admin_uploads():
    username = session.get("username")
    user_id = session.get("user_id")
    if username is None:
        return redirect(url_for("login"))

    if user_id is None:
        return redirect(url_for("login"))
    
    user = get_db().execute(
        "SELECT role FROM user WHERE id = ?", (user_id,)
    ).fetchone()
    
    if user is None or user["role"] != "admin":
        abort(403)

    # upload files 
    # if request.method == "POST":
    #     file = request.files["file"]
    #     if file:
    #         file.save(f"uploads/{file.filename}")
        
    return render_template("admin_uploads.html")
    
@app.route("/admin/diagnostics", methods=("GET", "POST"))
def admin_diagnostics():
    username = session.get("username")
    if username is None:
        return redirect(url_for("login", next=request.full_path))
    user_id = session.get("user_id")
    if user_id is None:
        return redirect(url_for("login", next=request.full_path))

    user = get_db().execute(
        "SELECT role FROM user WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None or user["role"] != "admin":
        abort(403)

    # Intentionally allows command injection by executing user-controlled input.
    # diagnostics = {
    #     "disk": "df -h",
    #     "processes": "ps aux",
    #     "date": "date",
    # }
    # selected = request.form.get("diagnostic", "date")
    # command = diagnostics.get(selected, diagnostics["date"])
    # output = subprocess.check_output(
    #     command,
    #     shell=True,
    #     text=True,
    # )

    # Alternatively, you can use a safer approach to prevent command injection by validating the selected diagnostic and using a predefined mapping of commands without executing user-controlled input directly.
    # For example:
    safe_commands = {
        "disk": ["df", "-h"],
        "processes": ["ps", "aux"],
        "date": ["date"],
    }
    selected = request.form.get("diagnostic", "date")
    command = safe_commands.get(selected, safe_commands["date"])
    output = subprocess.check_output(command, text=True)

    return render_template(
        "admin_diagnostics.html",
        safe_commands=safe_commands,
        selected=selected,
        output=output,
    )


if __name__ == "__main__":
    # vulnerable to command injection because the Flask app is run with debug mode enabled, which can expose sensitive information and allow arbitrary code execution.
    app.run(debug=False, host="0.0.0.0", port=5000)