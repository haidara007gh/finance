from curses.ascii import isdigit
import os
import requests
import urllib.parse
import datetime

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Contact API
    try:
        api_key = os.environ.get("API_KEY")
        url = f"https://cloud.iexapis.com/stable/stock/{urllib.parse.quote_plus(symbol)}/quote?token={api_key}"
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException:
        return None

    # Parse response
    try:
        quote = response.json()
        return {
            "name": quote["companyName"],
            "price": float(quote["latestPrice"]),
            "symbol": quote["symbol"]
        }
    except (KeyError, TypeError, ValueError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

def isValidShare(x):
    if x.isdigit():
        x = int(x)
        if x >= 1 and x % 1 == 0:
            return True
    return False

def makePurchase(shares, price, cash):
    total = shares * price
    if cash >= total:
        cash = cash - total
        print(f"Number of shares: {shares} total: {total} Cash: {cash}")
        return cash, total, True
    return cash, 0, False
        
def currrentDateTime():
    time = datetime.datetime.now()
    return f"{time.strftime('%x')} {time.strftime('%X')}"

def isValidCash(x):
    if x.isdigit():
        x = int(x)
        if x >= 1:
            return True
    return False

def isValidPassword(password):
    specialSymbol = ["$","@","#","%","!"]

    if not len(password)> 3 and not len(password) < 11:
        return False, "Password length must be between 4 and 10"
    if not any(char in specialSymbol for char in password):
        return False, "Must include at least one special symbol"
    if not any(char.isdigit() for char in password):
        return False, "Must include at least one number"
    if not any(char.isalpha() for char in password):
        return False, "Must include at least one letter "
    return True, None