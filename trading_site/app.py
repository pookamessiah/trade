from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import timedelta, datetime
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///trading.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -----------------
# Database Models
# -----------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    real_balance = db.Column(db.Float, default=0.0)
    demo_balance = db.Column(db.Float, default=5000.0)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    trans_type = db.Column(db.String(50))  # "trade", "deposit", "withdrawal"
    amount = db.Column(db.Float)
    description = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -----------------
# Routes
# -----------------

# Home page with multiple sections and image examples
@app.route('/')
def index():
    return render_template('index.html')

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session.permanent = True
            app.permanent_session_lifetime = timedelta(days=7)
            app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

# Dashboard: shows balances and navigation buttons
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# Trade Route: Validate input amount against balance then show timer
@app.route('/trade', methods=['GET', 'POST'])
@login_required
def trade():
    if request.method == 'POST':
        account_type = request.form.get('account_type')
        try:
            trade_amount = float(request.form.get('amount'))
        except:
            flash("Invalid trade amount.", "danger")
            return redirect(url_for('trade'))
        
        # Validate that trade amount does not exceed the selected account balance
        if account_type == 'real':
            if trade_amount > current_user.real_balance:
                flash("Trade amount exceeds your real balance!", "danger")
                return redirect(url_for('trade'))
        elif account_type == 'demo':
            if trade_amount > current_user.demo_balance:
                flash("Trade amount exceeds your demo balance!", "danger")
                return redirect(url_for('trade'))
        
        session['trade_account'] = account_type
        session['trade_amount'] = trade_amount
        return render_template('timer.html')
    return render_template('trade.html')

# Result Route: Process trade outcome and update the selected account's balance
@app.route('/result')
@login_required
def result():
    outcomes = [
        {'result': '+', 'amount': 13, 'desc': 'EURUSD ARBITRAGE'},
        {'result': '+', 'amount': 10, 'desc': 'BTCUSDT Binance/Coinbase'},
        {'result': '+', 'amount': 1, 'desc': 'EURGBP ARBITRAGE'},
        {'result': '-', 'amount': 9, 'desc': 'EURJPY ARBITRAGE'},
        {'result': '+', 'amount': 28, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 55, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 19, 'desc': 'XRPUSDC BYBIT/PAXFUL'},
        {'result': '+', 'amount': 39, 'desc': 'PEPEUSDC MEMECOIN'},
        {'result': '+', 'amount': 77, 'desc': 'TRUMPSOL MEMECOIN'},
        {'result': '+', 'amount': 32, 'desc': 'ADABTC Coinbase/PAXFUL'},
        {'result': '+', 'amount': 42, 'desc': 'Boom 1000 Index Deriv'},
        {'result': '+', 'amount': 89, 'desc': 'BOOM 300 Trade Signal'},
        {'result': '+', 'amount': 56, 'desc': 'Crash 1000 Index Deriv'},
        {'result': '+', 'amount': 49, 'desc': 'CRASH 300 Trade Signal'},
        {'result': '+', 'amount': 89, 'desc': 'Boom 1000 Index Deriv'},
        {'result': '+', 'amount': 80, 'desc': 'BOOM 300 Trade Signal'},
        {'result': '+', 'amount': 37, 'desc': 'Crash 1000 Index Deriv'},
        {'result': '+', 'amount': 31, 'desc': 'CRASH 300 Trade Signal'},
        {'result': '+', 'amount': 19, 'desc': 'ETHUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 9, 'desc': 'SOLUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 10, 'desc': 'TRUMPUSDT MEMECOIN'},
        {'result': '+', 'amount': 56, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 32, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 1, 'desc': 'DOGEUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 1, 'desc': 'SHIBUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 1, 'desc': 'PEPEUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 2, 'desc': 'BTCUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 32, 'desc': 'ETHUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 93, 'desc': 'XRPUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 4, 'desc': 'LTCUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 9, 'desc': 'BCHUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 9, 'desc': 'LINKUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 7, 'desc': 'DOTUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 9, 'desc': 'AVAXUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 1, 'desc': 'MATICUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 89, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 9, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 61, 'desc': 'SOLUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 2, 'desc': 'TRXUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 12, 'desc': 'ADAUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 1, 'desc': 'XLMUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 58, 'desc': 'DOGEUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 34, 'desc': 'SHIBUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 21, 'desc': 'PEPEUSDT Binance/PAXFUL'},
        {'result': '-', 'amount': 11, 'desc': 'TRUMPUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 66, 'desc': 'FLOKIUSDT Binance/PAXFUL'},
        {'result': '-', 'amount': 7, 'desc': 'SANDUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 6, 'desc': 'MANAUSDT Binance/PAXFUL'},
        {'result': '+', 'amount': 89, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 89, 'desc': 'XAUUSD ARBITRAGE FXTM/FBS'},
        {'result': '+', 'amount': 32, 'desc': "LTCUSDT BYBIT/COINBASE"},
        {'result': '+', 'amount': 9, 'desc': "ETHBTC BYBIT/COINBASE"},
        {'result': '-', 'amount': 12, "desc": "ETHBTC BYBIT/COINBASE"},
        {'result':'+', "amount":114,"desc":"ETHBTC BYBIT/COINBASE"},
        {'result': '-', 'amount': 9, 'desc': 'SOLUSDT BYBIT/PAXFUL'}
    ]
    outcome = random.choice(outcomes)
    trade_account = session.get('trade_account')
    trade_amount = session.get('trade_amount')
    
    if trade_account == 'real':
        if outcome['result'] == '+':
            current_user.real_balance += outcome['amount']
        else:
            current_user.real_balance -= outcome['amount']
    elif trade_account == 'demo':
        if outcome['result'] == '+':
            current_user.demo_balance += outcome['amount']
        else:
            current_user.demo_balance -= outcome['amount']
    db.session.commit()
    
    trade_change = outcome['amount'] if outcome['result'] == '+' else -outcome['amount']
    trans = Transaction(
        user_id=current_user.id,
        trans_type='trade',
        amount=trade_change,
        description=f"Trade on {trade_account} account: {outcome['desc']}"
    )
    db.session.add(trans)
    db.session.commit()
    return render_template('result.html', outcome=outcome, account=trade_account, user=current_user)

# Deposit Route: Add funds to the real account
@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
        except:
            flash("Invalid amount.", "danger")
            return redirect(url_for('deposit'))
        current_user.real_balance += amount
        db.session.commit()
        trans = Transaction(user_id=current_user.id, trans_type='deposit', amount=amount, description='Deposit')
        db.session.add(trans)
        db.session.commit()
        flash('Deposit successful!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('deposit.html')

# Withdrawal Route: Subtract funds from the real account
@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
        except:
            flash("Invalid amount.", "danger")
            return redirect(url_for('withdraw'))
        if current_user.real_balance >= amount:
            current_user.real_balance -= amount
            db.session.commit()
            trans = Transaction(user_id=current_user.id, trans_type='withdrawal', amount=-amount, description='Withdrawal')
            db.session.add(trans)
            db.session.commit()
            flash('Withdrawal successful!', 'success')
        else:
            flash('Insufficient funds!', 'danger')
        return redirect(url_for('dashboard'))
    return render_template('withdraw.html')

# Transaction History: List all transactions for the user
@app.route('/transactions')
@login_required
def transactions():
    trans = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template('transactions.html', transactions=trans)

# Admin Panel: Only accessible for admin (username "admin")
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.username != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        try:
            new_balance = float(request.form.get('real_balance'))
        except:
            flash("Invalid balance.", "danger")
            return redirect(url_for('admin'))
        user = User.query.get(user_id)
        user.real_balance = new_balance
        db.session.commit()
        flash('User balance updated!', 'success')
    return render_template('admin.html', users=users)

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# -----------------
# Run the App
# -----------------

if __name__ == "__main__":
    from os import environ
    port = int(environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
