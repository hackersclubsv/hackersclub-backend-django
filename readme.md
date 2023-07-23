# Project Setup Guide

This document provides instructions to set up the Django project on your local machine.

## Prerequisites

- Python 3.11.4
- pip (Python package installer)
- PostgreSQL

## Instructions

### 1. Clone the GitHub repository

Clone the repository by running the following command in your terminal:

```bash
git clone https://github.com/hackersclubsv/hackersclub-backend-django.git
cd hackersclub-backend-django
```

### 2. Setting up a virtual environment

Create a new Python virtual environment and activate it using the following commands:

```bash
# Create a virtual environment
python -m venv myenv

# Activate the environment
# On macOS and Linux:
source myenv/bin/activate

# On Windows:
.\myenv\Scripts\activate
```

### 3. Installing requirements

Navigate to the project directory (where `requirements.txt` is located) and install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

### 4. Setting up PostgreSQL

#### On MacOS:

Install PostgreSQL, create a new user, and create a new database:

```bash
brew install postgresql
brew services start postgresql
createuser --interactive --pwprompt
createdb -O your-username coengagedb
```

#### On Windows:

First, download and install PostgreSQL from the [official site](https://rajs.dev). After installation, open the SQL Shell (psql) app and login as the superuser. Then run the following SQL commands:

```
CREATE USER your-username WITH ENCRYPTED PASSWORD 'your-password';
ALTER USER your-username CREATEDB;
CREATE DATABASE coengagedb OWNER your-username;
```

### 5. Setting up environment variables

Create a new file named `.env` inside the `hackersclub_backend/hackersclub_backend directory` (on the same level as `settings.py`) and add the following content:

```bash
DJANGO_SECRET_KEY=your-secret-key
DEBUG=True or False
ALLOWED_HOSTS=.localhost,127.0.0.1
DATABASE_URL=postgres://your-username:your-password@localhost:5432/coengagedb
```

Replace your-username, your-password, and your-secret-key with your actual PostgreSQL username, password, and Django secret key.

### 6. Django Commands

Once the database is set up, run the following commands:

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

You should now be able to navigate to http://localhost:8000 in your web browser and see your running application.
