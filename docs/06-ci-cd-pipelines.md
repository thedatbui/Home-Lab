# CI/CD Security Pipeline

## Objective

The GitHub Actions workflow automatically runs security checks on:

- a `push` to `main` or `develop`;
- a pull request targeting `main`.

The pipeline covers three areas:

- **SAST**: source-code analysis with Bandit and Semgrep;
- **SCA**: dependency analysis with OWASP Dependency-Check;
- **reports**: preserving the Bandit report as a GitHub Actions artifact.

## Intentionally Present Vulnerabilities

These issues are present for training purposes only and should not be kept in a real application.

### Insecure Flask Configuration

In [`app.py`](../app.py):

- `SECRET_KEY="dev"` uses a known and forgeable key;
- `debug=True` enables debug mode and the Werkzeug debugger;
- `host="0.0.0.0"` exposes the development server on all interfaces.

### Weak Password Hashing

The registration, login, and user-creation routes use MD5:

```python
hashlib.md5(password.encode("utf-8")).hexdigest()
```

MD5 is fast and obsolete for password storage. A password-specific KDF should be used instead, such as `werkzeug.security.generate_password_hash` or bcrypt.

The demonstration administrator account is also hardcoded in [`schema.sql`](../schema.sql).

### Stored XSS

Reviews are rendered with the Jinja `|safe` filter in:

- [`template/product.html`](../template/product.html);
- [`template/admin.html`](../template/admin.html).

This filter disables automatic escaping. A review containing HTML or JavaScript can therefore be executed when viewed.

### Open Redirect

After login, [`app.py`](../app.py) redirects to the `next` parameter without checking whether it is an internal URL:

```python
next_url = request.args.get("next", url_for("index"))
return redirect(next_url)
```

A link such as `/login?next=https://example.com` can therefore redirect the user to an external site.

### Command Execution with `shell=True`

The `/admin/diagnostics` route executes a command with:

```python
subprocess.check_output(command, shell=True, text=True)
```

The command is selected from a list of diagnostics for the lab, but using `shell=True` remains an anti-pattern and would be dangerous if the command or its arguments came directly from a request.

### File Upload and File Paths

The admin upload functionality uses the client-provided filename to build a path. Without strict validation of the filename, MIME type, and storage location, this can lead to path traversal or the upload of an executable file.


### Access Control and CSRF

The `/users/<user_id>` route does not verify that the requested profile belongs to the logged-in user; it illustrates an IDOR risk.

Sensitive forms have no CSRF protection, so another site can attempt to trigger a request using the user's session.

## Tools Used

### Bandit

Bandit analyzes the Python code. In the workflow, it intentionally targets only the application files:

```bash
bandit app.py db.py -f html -o bandit-report.html
```

It can detect dangerous calls, weak hashing, hardcoded passwords, and risky configurations. It does not understand all business logic, authorization rules, or HTTP behavior.

### Semgrep

Semgrep analyzes the rest of the repository: templates, YAML files, GitHub Actions workflows, and other supported files.

The workflow uses:

- `p/owasp-top-ten` for OWASP vulnerabilities;
- `p/security-audit` for security-audit rules;
- `p/secrets` for secrets and tokens.

The `app.py`, `db.py`, `.git`, `instance`, and `reports` paths are excluded from this step because the two Python files are already handled by Bandit.

### OWASP Dependency-Check

Dependency-Check performs SCA. It compares the project's dependencies and files against known vulnerabilities. Its HTML report is generated in `reports/`.

## How `main.yml` Works

The [`main.yml`](../.github/workflows/main.yml) file contains two jobs.

### `sast` Job

1. GitHub Actions checks out the repository with `actions/checkout`.
2. Python 3.11 is installed with `actions/setup-python`.
3. The dependencies from [`requirements.txt`](../requirements.txt) and Semgrep are installed.
4. Bandit analyzes `app.py` and `db.py`.
5. `bandit-report.html` is published as an artifact.
6. Semgrep analyzes the rest of the repository with the three rule configurations.

The Bandit and Semgrep steps use `continue-on-error: true`. The workflow therefore continues producing reports even when findings are detected. This makes the pipeline informative, but it does not block the pull request.

### `sca` Job

The `sca` job waits for `sast` to finish because of:

```yaml
needs: sast
```

It then runs `dependency-check/Dependency-Check_Action`, generates an HTML report in `reports/`, and publishes that directory as the `dependency-check-report` artifact.

## Local Commands

Bandit on the Python files:

```bash
bandit app.py db.py -f html -o bandit-report.html
```

Semgrep on the rest of the repository:

```bash
semgrep scan \
  --config p/owasp-top-ten \
  --config p/security-audit \
  --config p/secrets \
  --exclude app.py \
  --exclude db.py \
  --exclude .git \
  --exclude instance \
  --exclude reports \
  .
```

Dependency-Check is primarily run in GitHub Actions to centralize the NVD database and reports.
