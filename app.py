from flask import Flask, render_template

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def login():
    return render_template("login.html")

@app.route("/main")
def main():
    return render_template("main.html")

@app.route("/signup")
def signup():
    return render_template("signup.html")


if __name__ == "__main__":
    app.run(debug=True)