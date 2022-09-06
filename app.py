import os
from cs50 import SQL
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, currrentDateTime, isValidCash, isValidPassword, isValidShare, login_required, lookup, makePurchase, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter for usd
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
#db = SQL("sqlite:///finance.db")
conn = sqlite3.connect("finance.db", check_same_thread=False)
conn.row_factory = sqlite3.Row
cur = conn.cursor()


# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session.get("user_id")
    cash = conn.execute("SELECT cash FROM users WHERE id = ?",
                        (user_id,)).fetchone()["cash"]
    rows = conn.execute(
        "SELECT symbol,shares FROM stocks WHERE user_id = ?", (user_id,))
    stocks = []
    TOTAL = 0
    for row in rows:
        response = lookup(row["symbol"])
        total = row["shares"] * response["price"]
        TOTAL += total
        data = {"symbol": row["symbol"], "name": response["name"], "shares": row["shares"], "price": usd(
            response["price"]), "total": usd(total)}
        stocks.append(data)
    TOTAL = TOTAL + cash
    return render_template("index.html", stocks=stocks, TOTAL=TOTAL, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        """Validating user inputs"""
        # Ensuring fields are not blank
        if not request.form.get("symbol"):
            return apology("Must provide symbol")
        elif not request.form.get("shares"):
            return apology("Must provide shares")
        # Ensuring share is a positive integer
        if not isValidShare(request.form.get("shares")):
            return apology("Share must be a positive integer")
        
        # collecting data
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        # Lookup
        response = lookup(symbol)
        if response is None:
            return apology("Error: Unknown symbol", 443)

        price = response["price"]
        name = response["name"]
        symbol = response["symbol"]
        cash = conn.execute("SELECT cash FROM users WHERE id = ?",
                            (session.get("user_id"),)).fetchone()["cash"]

        cash, total, flag = makePurchase(shares, price, cash)

        if flag:
            # Update user's cash after the transaction
            conn.execute("UPDATE users SET cash = ? WHERE id = ?",
                         (cash, session.get("user_id")))
            # Remember the transaction
            data = (currrentDateTime(), "buy", session.get(
                "user_id"), symbol, name, shares, price, total)
            cur.execute(
                "INSERT INTO transactions(datetime,transaction_type,user_id,symbol,name,shares,price,total) VALUES(?,?,?,?,?,?,?,?)", data)

            # Update user stocks
            # if stock exists update else make insertion
            row = conn.execute("SELECT shares FROM stocks WHERE user_id = ? AND symbol = ?", (session.get(
                "user_id"), symbol)).fetchone()

            if row == None:
                conn.execute("INSERT INTO stocks(user_id,transaction_id, symbol,shares,name) VALUES(?,?,?,?,?)", (session.get(
                    "user_id"), cur.lastrowid, symbol, shares, name))
            else:
                shares += row["shares"]
                conn.execute("UPDATE stocks SET shares = ? WHERE user_id = ? AND symbol = ?",
                             (shares, session.get("user_id"), symbol))
            flash("Purchase successfully made","success")
            conn.commit()
            return redirect("/")
        else:
            flash("Sorry","danger")
            return apology("Insufficient cash")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    rows = conn.execute("SELECT datetime,transaction_type,name, symbol,price,shares,total FROM transactions WHERE user_id = ?",
                        (session.get("user_id"),)).fetchall()
    mylist = []
    for row in rows:
        data = {
            "datetime": row["datetime"],
            "transaction_type": row["transaction_type"],
            "name": row["name"],
            "symbol": row["symbol"],
            "price": usd(row["price"]),
            "shares": row["shares"],
            "total": usd(row["total"])
        }
        mylist.append(data)
    return render_template("history.html", mylist=mylist)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username

        rows = conn.execute("SELECT * FROM users WHERE username = ?",
                            (request.form.get("username"),)).fetchall()
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], (request.form.get("password"))):
            flash('Invalid password provided', 'error')
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash('You were successfully logged in',"success")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Must provide symbol")
        symbol = request.form.get("symbol")
        # lookup
        response = lookup(symbol)
        if response is None:
            return apology("Error: Unknown symbol", 443)
        else:
            return render_template("quoted.html", response=response)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensuring user made inputs to form
        if not request.form.get("username"):
            return apology("must provide username", 403)
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 403)

        # validating user inputs
        
        # Ensuring new username is not an already existing username
        usernames = []
        rows = conn.execute("SELECT username FROM users").fetchall()
        for row in rows:
            usernames.append(row["username"])
        if request.form.get("username") in usernames:
            return apology("username already exist", 403)
        # Ensuring password match with confirmation password
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("Password do not match", 403)
        # Ensuring strong password
        flag, message = isValidPassword(request.form.get("password"))
        if not flag:
            return apology(message,403)
        # register in database after validation
        info = (request.form.get("username"),
                generate_password_hash(request.form.get("password")))
        conn.execute("INSERT INTO users(username,hash) VALUES(?,?)", info)
        conn.commit()
        flash("Registration was successful","success")
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session.get("user_id")
    rows = conn.execute(
        "SELECT * FROM stocks WHERE user_id = ?", (user_id,)).fetchall()
    if request.method == "POST":
        # Validate inputs
        if not request.form.get("symbol") or not request.form.get("shares"):
            return apology("Make a valid input")
        if not isValidShare(request.form.get("shares")):
            return apology("Share must be positive")
        stock = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        for row in rows:
            if row["symbol"] == stock:
                price = lookup(row["symbol"])["price"]

                total = price * shares

                data = (currrentDateTime(), "sold", session.get("user_id"),
                        row["symbol"], row["name"], -shares, price, total)
                cash = conn.execute(
                    "SELECT cash FROM users WHERE id = ?", (user_id,)).fetchone()["cash"]

                if row["shares"] == shares:
                    # Delete the stocks of user
                    conn.execute(
                        "DELETE FROM stocks WHERE symbol = ?", (stock,))

                    # Remember the transaction
                    conn.execute(
                        "INSERT INTO transactions(datetime,transaction_type,user_id,symbol,name,shares,price,total) VALUES(?,?,?,?,?,?,?,?)", data)

                    # Update user's cash after the transaction
                    cash += total
                    conn.execute("UPDATE users SET cash = ? WHERE id = ?",
                                 (cash, session.get("user_id")))
                    message = "Sold successfully"
                    category = "success"
                elif row["shares"] >= shares:
                    # Update the stocks table of user
                    rowshares = row["shares"]
                    rowshares -= shares
                    conn.execute("UPDATE stocks SET shares = ? WHERE user_id = ? AND symbol = ?", (
                        rowshares, user_id, row["symbol"]))

                    # Remember the transaction
                    conn.execute(
                        "INSERT INTO transactions(datetime,transaction_type,user_id,symbol,name,shares,price,total) VALUES(?,?,?,?,?,?,?,?)", data)
                    # Update user's cash after the transaction
                    cash += total
                    conn.execute("UPDATE users SET cash = ? WHERE id = ?",
                                 (cash, session.get("user_id")))
                    message = "Sold successfully"
                    category = "success"
                else:
                    message = "The shares should be less or equals to the shares you have"
                    category = "warning"
                    return apology("Too many Shares")
        flash(message,category)
        conn.commit()
        return redirect("/")
    else:
        stocks = []
        for row in rows:
            stocks.append(row["symbol"])
        return render_template("sell.html", stocks=stocks)

@app.route("/myprofile", methods =["GET","POST"])
@login_required
def myprofile():
    user_id = session.get("user_id")
    if request.method == "GET":
        #Query for username
        username = conn.execute("SELECT username FROM users WHERE id = ?",(user_id,)).fetchone()["username"]
        print(username)
        return render_template("myprofile.html",username = username)
    else:
        pass

@app.route("/changepassword",methods =["GET", "POST"])
@login_required
def change_password():
    user_id = session.get("user_id")
    if request.method == "POST":
        # Ensuring user made inputs to form
        if not request.form.get("password"):
            return apology("must provide password", 403)
        elif not request.form.get("new_password"):
            return apology("must provide new password", 403)
        elif not request.form.get("confirm_password"):
            return apology("must confirm password", 403)
        
        #Validate
        # Query database for username
        rows = conn.execute("SELECT * FROM users WHERE id = ?",
                            (user_id,)).fetchall()
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], (request.form.get("password"))):
            return apology("invalid password", 403)
        elif not request.form.get("new_password") == request.form.get("confirm_password"):
                return apology("Password do not match", 403)
        # Ensuring strong password
        flag, message = isValidPassword(request.form.get("new_password"))
        if not flag:
            return apology(message,403)
        # After validations
        conn.execute("UPDATE users SET hash = ? WHERE id = ?", (generate_password_hash(request.form.get("new_password")),user_id))
        conn.commit()
        flash("Password updated successfully","success")
        return redirect("/")
    else:
        return render_template("changepassword.html")

@app.route("/addcash",methods = ["GET","POST"])
@login_required
def addcash():
    user_id = session.get("user_id")
    if request.method == "POST":
        # Ensuring user made inputs to form
        if not request.form.get("additionalcash"):
            return apology("Must provide cash")
        # Validating input
        elif not isValidCash(request.form.get("additionalcash")):
            return apology("Must provide valid cash")
        # Update After validation
        additionalcash = float(request.form.get("additionalcash"))
        cash = conn.execute(
                    "SELECT cash FROM users WHERE id = ?", (user_id,)).fetchone()["cash"]
        cash = additionalcash + cash
        conn.execute("UPDATE users SET cash = ? WHERE id = ?", (cash,user_id))
        conn.commit()
        flash("Cash added successfully","success")
        return redirect("/")
    else:
        return render_template("addcash.html")

@app.route("/deleteaccount")
@login_required
def deleteaccount():
    user_id =session.get("user_id")
    conn.execute("DELETE FROM users WHERE id = ?",(user_id,))
    conn.execute("DELETE FROM stocks WHERE user_id = ?",(user_id,))
    conn.execute("DELETE FROM transactions WHERE user_id = ?",(user_id,))
    conn.commit()
    session.clear()
    flash("Account deleted successfully","success")
    return redirect("/")

@app.route("/stock/")
@login_required
def stock():
    user_id = session.get("user_id")
    symbol = request.args.get("symbol")

    response = lookup(symbol)
    shares = conn.execute("SELECT * FROM stocks WHERE user_id = ?", (user_id,)).fetchone()["shares"]
    stock = {"name":response["name"],"price":response["price"],"symbol":response["symbol"],"shares":shares}
    return render_template("stock.html",stock = stock)