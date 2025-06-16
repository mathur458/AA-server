# app.py
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import datetime,re 

app = Flask(__name__)

app.secret_key = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:root@localhost/flask_rbac1'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = datetime.timedelta(minutes=10)

db = SQLAlchemy(app)

# ------------------ Models ------------------
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"<Role {self.name}>"
    
class UserRole(db.Model):
    __tablename__ = 'user_role'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('user_roles', cascade='all, delete-orphan'))
    role = db.relationship('Role', backref=db.backref('user_roles', cascade='all, delete-orphan'))
    
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    deleted = db.Column(db.Boolean, default=False)
    last_password_change = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AccessRight(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(100))

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    login_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class DeletedUserArchive(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(128))
    deletion_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class UserNotification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class PendingRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(120), nullable=False)

# ------------------ Utils ------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Session expired or unauthorized access.")
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.deleted:
            session.clear()
            flash("Access denied. Contact admin.")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        is_json = request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if 'user_id' not in session or session.get('username') != 'admin':
            if is_json:
                return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401
            flash("Access denied. Admin only.")
            return redirect(url_for('login'))

        user = User.query.get(session['user_id'])
        if not user or user.deleted:
            session.clear()
            if is_json:
                return jsonify({'status': 'error', 'message': 'Admin account no longer exists'}), 403
            flash("Admin account no longer exists.")
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

# ------------------ Routes ------------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, deleted=False).first()
        if user and check_password_hash(user.password, password):
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            db.session.add(LoginActivity(user_id=user.id))
            db.session.commit()
            return redirect(url_for('admin_dashboard' if user.username == 'admin' else 'dashboard'))
        else:
            flash('Invalid credentials or user does not exist.')
    return render_template('login.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.filter(User.username != 'admin', User.deleted == False).all()
    roles = ['Customer Data Usage', 'Network Logs', 'Client Requests']
    user_roles = {
        user.id: [r.role for r in AccessRight.query.filter_by(user_id=user.id).all()]
        for user in users
    }
    archives = DeletedUserArchive.query.all()
    
    # ✅ Fetch pending requests
    pending_requests = PendingRequest.query.all()

    return render_template(
        'admin.html',
        users=users,
        roles=roles,
        user_roles=user_roles,
        archives=archives,
        pending_requests=pending_requests  # ✅ Send to template
    )


@app.route('/approve_request/<int:user_id>', methods=['POST'])
@admin_required
def approve_request(user_id):
    # Get the JSON data from fetch
    data = request.get_json()
    if not data or 'roles' not in data:
        return jsonify(status='error', message='Invalid request. Roles missing.'), 400

    roles = data['roles']
    pending = PendingRequest.query.get(user_id)
    if not pending:
        return jsonify(status='error', message='Pending request not found.'), 404

    # Check if user already exists
    if User.query.filter_by(username=pending.domain).first():
        return jsonify(status='error', message='User already exists.'), 400

    try:
        hashed_pw = generate_password_hash(pending.password, method='pbkdf2:sha256', salt_length=4)
        new_user = User(username=pending.domain, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        for role_name in roles:
            db.session.add(AccessRight(user_id=new_user.id, role=role_name))

        db.session.delete(pending)
        db.session.commit()

        return jsonify(status='success', message='User approved successfully!')
    except Exception as e:
        db.session.rollback()
        return jsonify(status='error', message=f'Error: {str(e)}'), 500
    
@app.route('/reject_request/<int:request_id>', methods=['POST'])
@admin_required
def reject_request(request_id):
    request_to_delete = PendingRequest.query.get(request_id)
    if request_to_delete:
        db.session.delete(request_to_delete)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Request rejected successfully.'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Request not found.'}), 404



@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user and user.username != 'admin':
        archive = DeletedUserArchive(username=user.username, password=user.password)
        db.session.add(archive)
        user.deleted = True
        db.session.commit()
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Cannot delete admin or user not found'})

@app.route('/modify_user/<int:user_id>', methods=['POST'])
@admin_required
def modify_user(user_id):
    roles = request.form.getlist('roles')
    password = request.form.get('password')
    user = User.query.get(user_id)
    
    if user:
        if password:
            user.password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=4)
            user.last_password_change = datetime.datetime.utcnow()

        current_roles = set(r.role for r in AccessRight.query.filter_by(user_id=user.id).all())
        new_roles = set(roles)
        added_roles = new_roles - current_roles
        removed_roles = current_roles - new_roles

        AccessRight.query.filter_by(user_id=user.id).delete()
        for role in new_roles:
            db.session.add(AccessRight(user_id=user.id, role=role))

        for role in added_roles:
            db.session.add(UserNotification(user_id=user.id, message=f"Access granted to {role}"))
        for role in removed_roles:
            db.session.add(UserNotification(user_id=user.id, message=f"Access revoked from {role}"))

        db.session.commit()
        return jsonify({'status': 'success'})
    
    return jsonify({'status': 'error', 'message': 'User not found'})

@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    user = User.query.get(user_id)
    days_since_change = (datetime.datetime.utcnow() - user.last_password_change).days
    roles = [r.role for r in AccessRight.query.filter_by(user_id=user_id).all()]

    notification = None
    if days_since_change >= 52 and days_since_change < 60:
        notification = f"Please change your password. It will expire in {60 - days_since_change} days."
    elif days_since_change >= 60:
        user.deleted = True
        db.session.commit()
        session.clear()
        flash("Your account has been deleted due to password expiry.")
        return redirect(url_for('login'))

    notifications = UserNotification.query.filter_by(user_id=user_id, is_read=False).order_by(UserNotification.timestamp.desc()).all()
    return render_template('dashboard.html', roles=roles, notification=notification, notifications=notifications)

@app.route('/customer_data')
@login_required
def customer_data():
    if 'Customer Data Usage' not in [r.role for r in AccessRight.query.filter_by(user_id=session['user_id']).all()]:
        flash("Access denied to Customer Data Usage")
        return redirect(url_for('dashboard'))
    return render_template('customer_data.html')

@app.route('/network_logs')
@login_required
def network_logs():
    if 'Network Logs' not in [r.role for r in AccessRight.query.filter_by(user_id=session['user_id']).all()]:
        flash("Access denied to Network Logs")
        return redirect(url_for('dashboard'))
    return render_template('network_logs.html')

@app.route('/client_requests')
@login_required
def client_requests():
    if 'Client Requests' not in [r.role for r in AccessRight.query.filter_by(user_id=session['user_id']).all()]:
        flash("Access denied to Client Requests")
        return redirect(url_for('dashboard'))
    return render_template('client_requests.html')

@app.route('/login_activity')
@admin_required
def login_activity():
    logs = LoginActivity.query.order_by(LoginActivity.login_time.desc()).all()
    return render_template('login_activity.html', logs=logs)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        domain = request.form['domain']
        password = request.form['password']

        # Password Validation
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for('register'))
        if not re.search(r"[A-Z]", password):
            flash("Password must contain at least one uppercase letter.", "error")
            return redirect(url_for('register'))
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash("Password must contain at least one special character.", "error")
            return redirect(url_for('register'))

        # ✅ Check if user already exists or pending
        if User.query.filter_by(username=domain, deleted=False).first():
            flash('This domain is already registered and approved. Please login.', 'error')
        elif PendingRequest.query.filter_by(domain=domain).first():
            flash('A registration request with this domain is already pending.', 'error')
        else:
            req = PendingRequest(domain=domain, password=password)
            db.session.add(req)
            db.session.commit()
            flash('Your request has been submitted.', 'success')

        return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out or your session has expired.")
    return redirect(url_for('login'))

@app.route('/api/peak_logins')
@admin_required
def peak_logins():
    date_str = request.args.get('date')
    if not date_str:
        return jsonify({'labels': [], 'data': []})
    try:
        date = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
        logins = LoginActivity.query.filter(db.func.date(LoginActivity.login_time) == date).all()
        time_buckets = {'Midnight–6AM': 0, '6AM–12PM': 0, '12PM–6PM': 0, '6PM–Midnight': 0}
        for log in logins:
            hour = log.login_time.hour
            if hour < 6:
                time_buckets['Midnight–6AM'] += 1
            elif hour < 12:
                time_buckets['6AM–12PM'] += 1
            elif hour < 18:
                time_buckets['12PM–6PM'] += 1
            else:
                time_buckets['6PM–Midnight'] += 1
        return jsonify({'labels': list(time_buckets.keys()), 'data': list(time_buckets.values())})
    except Exception as e:
        return jsonify({'error': str(e)})

# ------------------ Main ------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin_pw = generate_password_hash('admin123', method='pbkdf2:sha256', salt_length=4)
            new_admin = User(username='admin', password=admin_pw)
            db.session.add(new_admin)
            db.session.commit()
            print("✅ Admin account created.")
    app.run(debug=True)
