from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_apscheduler import APScheduler
from functools import wraps
import requests
import hashlib
import datetime
from dotenv import load_dotenv
import os

# --- Flask-Migrate for safe migrations ---
from flask_migrate import Migrate, upgrade as alembic_upgrade
import sqlalchemy

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['ADZUNA_APP_ID'] = os.environ.get('ADZUNA_APP_ID')
app.config['ADZUNA_APP_KEY'] = os.environ.get('ADZUNA_APP_KEY')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.api_enabled = True

# --- Many-to-many relationship for applied jobs ---
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

# --- AUTO RUN MIGRATIONS ON STARTUP IF NEEDED ---
# def db_needs_upgrade():
#     inspector = sqlalchemy.inspect(db.engine)
#     return not inspector.has_table('user')

# with app.app_context():
#     if db_needs_upgrade():
#         print("Running database migrations...")
#         alembic_upgrade()
#         print("Database migrations complete.")

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
        is_admin = (User.query.count() == 0)
        user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

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

@scheduler.task('interval', id='check_jobs', seconds=3600, misfire_grace_time=900)
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
