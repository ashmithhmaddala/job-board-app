# Job Board Tracker

A Flask web application to track job postings from top companies in India (Bangalore, Hyderabad, Mumbai) with user authentication, admin dashboard, and job management.

## Features

- User registration and login
- Admin dashboard with charts and user management
- Job fetching from Adzuna API for selected companies and cities
- Job filtering by company, category, and location
- Responsive Bootstrap UI

## Setup

1. **Clone the repository:**
https://github.com/ashmithhmaddala/job-board-app.git
cd job-board-app

2. **Install dependencies:**
pip install -r requirements.txt

3. **Set environment variables (optional for local dev):**
export FLASK_APP=app.py
export FLASK_ENV=production
export SECRET_KEY=your-secret-key
export ADZUNA_APP_ID=your-adzuna-app-id
export ADZUNA_APP_KEY=your-adzuna-app-key

4. **Run the app locally:**
The app will be available at `http://localhost:5000`

## Deploy

### Deploy to Render.com

1. Push your code to GitHub.
2. Create a `Procfile` with:
web: gunicorn app:app

3. Go to [Render.com](https://render.com/), create a new Web Service, and connect your GitHub repo.
4. Set build command: `pip install -r requirements.txt`
5. Set start command: `gunicorn app:app`
6. Add environment variables for `SECRET_KEY`, `ADZUNA_APP_ID`, and `ADZUNA_APP_KEY`.

### Deploy to Railway

1. Push your code to GitHub.
2. Go to [Railway.app](https://railway.app/), create a new project from your repo.
3. Set environment variables as above.

## License

MIT

---

**Happy job tracking!**

