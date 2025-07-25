from flask import Flask, request, render_template, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash
import bleach

app = Flask(__name__)
auth = HTTPBasicAuth()

# Define valid users
users = {
    "admin": generate_password_hash("2301864@SIT.singaporetech.edu.sg")
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username

# --- XSS and SQL injection filters ---
def is_xss_attack(input_str):
    cleaned = bleach.clean(input_str, tags=[], attributes={}, strip=True)
    return cleaned != input_str

def is_sql_injection(input_str):
    keywords = ["select", "insert", "delete", "update", "drop", "--", ";", "' or '1'='1"]
    return any(k in input_str.lower() for k in keywords)

# --- Routes with Basic Auth protection ---
@app.route("/", methods=["GET", "POST"])
@auth.login_required
def home():
    if request.method == "POST":
        search_term = request.form.get("search")
        if is_xss_attack(search_term):
            return render_template("home.html", error="XSS attempt detected. Try again.")
        elif is_sql_injection(search_term):
            return render_template("home.html", error="SQL Injection detected. Try again.")
        else:
            return redirect(url_for("result", term=search_term))
    return render_template("home.html", error=None)

@app.route("/result")
@auth.login_required
def result():
    term = request.args.get("term")
    return render_template("result.html", term=term)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
