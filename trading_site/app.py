from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import random

load_dotenv()

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

@app.route('/')
def index():
    return render_template('index.html')

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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

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

        if account_type == 'real' and trade_amount > current_user.real_balance:
            flash("Trade amount exceeds your real balance!", "danger")
            return redirect(url_for('trade'))
        elif account_type == 'demo' and trade_amount > current_user.demo_balance:
            flash("Trade amount exceeds your demo balance!", "danger")
            return redirect(url_for('trade'))

        session['trade_account'] = account_type
        session['trade_amount'] = trade_amount
        return render_template('timer.html')
    return render_template('trade.html')

@app.route('/result')
@login_required
def result():
    outcomes = [...]  # Skipping list here due to length, keep as is
    outcome = random.choice(outcomes)
    trade_account = session.get('trade_account')
    trade_amount = session.get('trade_amount')

    if trade_account == 'real':
        current_user.real_balance += outcome['amount'] if outcome['result'] == '+' else -outcome['amount']
    elif trade_account == 'demo':
        current_user.demo_balance += outcome['amount'] if outcome['result'] == '+' else -outcome['amount']

    db.session.commit()

    trade_change = outcome['amount'] if outcome['result'] == '+' else -outcome['amount']
    trans = Transaction(user_id=current_user.id, trans_type='trade', amount=trade_change,
                        description=f"Trade on {trade_account} account: {outcome['desc']}")
    db.session.add(trans)
    db.session.commit()
    return render_template('result.html', outcome=outcome, account=trade_account, user=current_user)

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

@app.route('/transactions')
@login_required
def transactions():
    trans = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template('transactions.html', transactions=trans)

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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    from os import environ
    port = int(environ.get("PORT", 5000))
    app.run(debug=True, port=port)
