import os
import datetime
import hashlib
import requests
import sqlalchemy
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_apscheduler import APScheduler
from flask_migrate import Migrate, upgrade as alembic_upgrade
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from functools import wraps
from dotenv import load_dotenv, find_dotenv

# Load .env variables
load_dotenv(find_dotenv())

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# --- Database URL logic: PostgreSQL for prod, SQLite fallback for dev ---
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
if not database_url:
    database_url = 'sqlite:///jobs.db'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ADZUNA_APP_ID'] = os.environ.get('ADZUNA_APP_ID')
app.config['ADZUNA_APP_KEY'] = os.environ.get('ADZUNA_APP_KEY')

# --- Flask-Mail config ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['TESTING'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.api_enabled = True
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Many-to-many relationship table for applied jobs
applied_jobs = db.Table('applied_jobs',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('job_id', db.Integer, db.ForeignKey('job_posting.id'))
)

COMPANIES = {
    "Banks": ["JP Morgan", "Morgan Stanley", "Goldman Sachs", "Wells Fargo"],
    "Tech Firms": ["Google", "Microsoft", "Amazon", "Apple", "NVidia", "Atlassian", "Meta", "Texas Instruments",
                  "Applied Materials", "Intel", "Cisco", "Netflix", "Oracle", "Samsung", "Broadcom", "Spotify",
                  "Sony", "Dell", "HP"],
    "Defence": ["Lockheed", "NOrthropp", "Boeing", "Airbus"],
    "Finance": ["BlackRock", "BRidgewater", "DE Shaw", "Jane Street", "Hudson River", "Citadel", "Two Sigma",
               "Fidelity", "Barclays", "HSBC", "Citigroup", "Vanguard"],
    "Consulting": ["Bain", "BCG", "McKinsey", "Accenture", "EY", "PwC", "KPMG", "Deloitte"],
    "US Firms": ["Tesla", "BOA", "Visa", "Couchbase", "OpenAI", "Perplexity", "Anthropic", "IBM", "Boston Dynamics"]
}

INDIAN_CITIES = ['Bangalore', 'Hyderabad', 'Mumbai']
COUNTRY = 'in'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now)
    last_login = db.Column(db.DateTime)
    applied = db.relationship('JobPosting', secondary=applied_jobs, backref='applicants')

class JobPosting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(255), unique=True, nullable=False)
    company = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    location = db.Column(db.String(255))
    description = db.Column(db.Text)
    salary_min = db.Column(db.Float)
    salary_max = db.Column(db.Float)
    application_link = db.Column(db.String(500))
    date_posted = db.Column(db.DateTime)
    date_added = db.Column(db.DateTime, default=datetime.datetime.now)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Auto run migrations on startup if needed
def db_needs_upgrade():
    inspector = sqlalchemy.inspect(db.engine)
    return not inspector.has_table('user')

with app.app_context():
    if db_needs_upgrade():
        print("Running database migrations...")
        alembic_upgrade()
        print("Database migrations complete.")

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # Only block non-admins if not verified
            if not user.is_verified and not user.is_admin:
                flash(
                    'Your account is not verified. '
                    'Please check your email for the verification link.<br>'
                    'Didn\'t get it? <a href="{}?email={}">Resend verification email</a>.'
                    .format(url_for('resend_verification'), email),
                    'warning'
                )
                return redirect(url_for('login'))
            login_user(user)
            user.last_login = datetime.datetime.now()
            db.session.commit()
            if user.is_admin:
                flash('Welcome, admin!', 'success')
            else:
                flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check email and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password, is_verified=False)
        db.session.add(user)
        db.session.commit()
        # Send verification email
        send_verification_email(email)
        flash(
            'A verification email has been sent. Please check your inbox. <b>Also check your spam folder!</b><br>'
            'Didn\'t get it? <a href="{}?email={}">Resend verification email</a>.'
            .format(url_for('resend_verification'), email),
            'info'
        )
        return redirect(url_for('login'))
    return render_template('register.html')

def send_verification_email(email):
    token = serializer.dumps(email, salt='email-verify')
    verify_url = url_for('verify_email', token=token, _external=True)
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #222;">
        <div style="max-width: 480px; margin: 24px auto; padding: 24px; border-radius: 8px; background: #f8fafc; border: 1px solid #e5e7eb;">
            <h2 style="color: #2563eb;">Verify your email for Job Board Monitor</h2>
            <p>Hi,</p>
            <p>Thank you for registering with <b>Job Board Monitor</b>! Please verify your email address to activate your account. This helps us keep your account secure.</p>
            <p>
                <a href="{verify_url}" style="display: inline-block; padding: 12px 24px; background: #2563eb; color: #fff; border-radius: 6px; text-decoration: none; font-weight: bold; margin: 16px 0;">
                    Verify Email
                </a>
            </p>
            <p style="font-size: 0.97em; color: #555;">
                Or copy and paste this link into your browser:<br>
                <span style="word-break: break-all;">{verify_url}</span>
            </p>
            <p style="font-size: 0.97em; color: #555;">
                <b>Note:</b> This link will expire in 24 hours.
            </p>
            <hr style="margin: 24px 0;">
            <p style="font-size: 0.9em; color: #888;">
                If you did not sign up, you can safely ignore this email.<br>
                Need help? Reply to this email or contact support.
            </p>
            <p style="font-size: 0.9em; color: #888;">Best regards,<br>Ashmith Maddala (CEO)<br>Job Board Monitor Team</p>
        </div>
    </body>
    </html>
    """
    msg = Message(
        subject='Verify your email for Job Board Monitor',
        recipients=[email],
        html=html_content
    )
    mail.send(msg)

@app.route('/resend_verification')
def resend_verification():
    email = request.args.get('email')
    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        send_verification_email(email)
        flash('A new verification email has been sent. Please check your inbox.', 'info')
    else:
        flash('No unverified account found for that email.', 'danger')
    return redirect(url_for('login'))

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verify', max_age=3600*24)  # 24 hours
    except Exception:
        flash('Verification link is invalid or expired.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()
        flash('Your email has been verified! You can now log in.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(user.email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request',
                          recipients=[user.email],
                          body=f'Click the link to reset your password: {reset_url}')
            mail.send(msg)
            flash('Password reset link sent to your email.', 'info')
        else:
            flash('No account with that email was found.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except Exception:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if user:
            new_password = request.form.get('password')
            user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    category_filter = request.args.get('category', '')
    company_filter = request.args.get('company', '')
    location_filter = request.args.get('location', '')
    sort_by = request.args.get('sort_by', 'date_added')
    query = JobPosting.query
    if category_filter:
        query = query.filter_by(category=category_filter)
    if company_filter:
        query = query.filter_by(company=company_filter)
    if location_filter:
        query = query.filter(JobPosting.location.contains(location_filter))
    if sort_by == 'date_posted':
        jobs = query.order_by(JobPosting.date_posted.desc())
    else:
        jobs = query.order_by(JobPosting.date_added.desc())
    jobs = jobs.paginate(page=page, per_page=15)
    categories = db.session.query(JobPosting.category).distinct().all()
    companies = db.session.query(JobPosting.company).distinct().all()
    locations = db.session.query(JobPosting.location).distinct().all()
    return render_template('dashboard.html',
                          jobs=jobs,
                          categories=categories,
                          companies=companies,
                          locations=locations,
                          current_category=category_filter,
                          current_company=company_filter,
                          current_location=location_filter,
                          current_sort=sort_by)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/apply/<int:job_id>')
@login_required
def apply_job(job_id):
    job = JobPosting.query.get_or_404(job_id)
    if job not in current_user.applied:
        current_user.applied.append(job)
        db.session.commit()
        flash('Job added to your applied list!', 'success')
    else:
        flash('You have already marked this job as applied.', 'info')
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/unapply/<int:job_id>')
@login_required
def unapply_job(job_id):
    job = JobPosting.query.get_or_404(job_id)
    if job in current_user.applied:
        current_user.applied.remove(job)
        db.session.commit()
        flash('Job removed from your applied list.', 'info')
    return redirect(request.referrer or url_for('profile'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    job_count = JobPosting.query.count()
    company_count = db.session.query(JobPosting.company).distinct().count()
    job_by_category = [
        {'category': category, 'count': count}
        for category, count in db.session.query(
            JobPosting.category, db.func.count(JobPosting.id)
        ).group_by(JobPosting.category).all()
    ]
    job_by_company = [
        {'company': company, 'count': count}
        for company, count in db.session.query(
            JobPosting.company, db.func.count(JobPosting.id)
        ).group_by(JobPosting.company).order_by(db.func.count(JobPosting.id).desc()).limit(10).all()
    ]
    job_by_location = [
        {'location': location, 'count': count}
        for location, count in db.session.query(
            JobPosting.location, db.func.count(JobPosting.id)
        ).group_by(JobPosting.location).order_by(db.func.count(JobPosting.id).desc()).limit(10).all()
    ]
    return render_template(
        'admin/dashboard.html',
        user_count=user_count,
        job_count=job_count,
        company_count=company_count,
        job_by_category=job_by_category,
        job_by_company=job_by_company,
        job_by_location=job_by_location
    )

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    user = User.query.get_or_404(user_id)
    if user.is_admin and User.query.filter_by(is_admin=True).count() == 1:
        flash('Cannot remove the last admin', 'danger')
        return redirect(url_for('admin_users'))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status {"granted to" if user.is_admin else "revoked from"} {user.username}', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/jobs')
@login_required
@admin_required
def admin_jobs():
    page = request.args.get('page', 1, type=int)
    category_filter = request.args.get('category', '')
    company_filter = request.args.get('company', '')
    location_filter = request.args.get('location', '')
    query = JobPosting.query
    if category_filter:
        query = query.filter_by(category=category_filter)
    if company_filter:
        query = query.filter_by(company=company_filter)
    if location_filter:
        query = query.filter(JobPosting.location.contains(location_filter))
    jobs = query.order_by(JobPosting.date_added.desc()).paginate(page=page, per_page=15)
    categories = db.session.query(JobPosting.category).distinct().all()
    companies = db.session.query(JobPosting.company).distinct().all()
    locations = db.session.query(JobPosting.location).distinct().all()
    return render_template('admin/jobs.html',
                         jobs=jobs,
                         categories=categories,
                         companies=companies,
                         locations=locations,
                         current_category=category_filter,
                         current_company=company_filter,
                         current_location=location_filter)

@app.route('/admin/jobs/<int:job_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_job(job_id):
    job = JobPosting.query.get_or_404(job_id)
    db.session.delete(job)
    db.session.commit()
    flash('Job deleted successfully', 'success')
    return redirect(url_for('admin_jobs'))

def get_job_hash(company, title, url):
    return hashlib.md5(f"{company}_{title}_{url}".encode()).hexdigest()

def fetch_jobs_for_company(company_name, category):
    app_id = app.config['ADZUNA_APP_ID']
    app_key = app.config['ADZUNA_APP_KEY']
    new_jobs_found = 0
    for location in INDIAN_CITIES:
        base_url = f"https://api.adzuna.com/v1/api/jobs/{COUNTRY}/search/1"
        params = {
            'app_id': app_id,
            'app_key': app_key,
            'results_per_page': 50,
            'what': company_name,
            'where': location,
            'content-type': 'application/json'
        }
        try:
            response = requests.get(base_url, params=params)
            response.raise_for_status()
            data = response.json()
            if 'results' in data:
                for job in data['results']:
                    job_company = job.get('company', {}).get('display_name', '')
                    if company_name.lower() not in job_company.lower():
                        continue
                    job_title = job.get('title', '')
                    job_url = job.get('redirect_url', '')
                    job_id = get_job_hash(job_company, job_title, job_url)
                    if not JobPosting.query.filter_by(job_id=job_id).first():
                        date_posted = datetime.datetime.now()
                        if 'created' in job:
                            try:
                                date_posted = datetime.datetime.strptime(job['created'].split('T')[0], '%Y-%m-%d')
                            except ValueError:
                                pass
                        new_job = JobPosting(
                            job_id=job_id,
                            company=job_company,
                            category=category,
                            title=job_title,
                            location=job.get('location', {}).get('display_name', 'Unknown'),
                            description=job.get('description', 'No description available'),
                            salary_min=job.get('salary_min'),
                            salary_max=job.get('salary_max'),
                            application_link=job_url,
                            date_posted=date_posted,
                            date_added=datetime.datetime.now()
                        )
                        db.session.add(new_job)
                        new_jobs_found += 1
                if new_jobs_found > 0:
                    db.session.commit()
        except Exception as e:
            print(f"Error fetching jobs for {company_name} in {location}: {e}")
    return new_jobs_found

# Fetch jobs automatically every hour (change hours=24 for once per day)
@scheduler.task('interval', id='check_jobs', hours=1, misfire_grace_time=900)
def check_all_companies():
    with app.app_context():
        print(f"Job checking started at {datetime.datetime.now()}")
        total_new_jobs = 0
        for category, companies in COMPANIES.items():
            for company in companies:
                print(f"Checking jobs for {company}...")
                new_jobs = fetch_jobs_for_company(company, category)
                total_new_jobs += new_jobs
                print(f"Found {new_jobs} new jobs for {company}")
        print(f"Job checking completed at {datetime.datetime.now()}. Total new jobs: {total_new_jobs}")

@app.route('/manual_check')
@login_required
@admin_required
def manual_check():
    scheduler.run_job('check_jobs')
    flash('Job check triggered. Check back soon for new jobs.', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    scheduler.start()
    app.run(debug=True)