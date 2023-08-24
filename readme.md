# Project Setup Guide

This document provides instructions to set up the Django project on your local machine.

## Prerequisites

- Python 3.11.4
- pip (Python package installer)
- PostgreSQL
- AWS Account (request access from admin)
- Environment Variables

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
brew install postgresql@15
brew services start postgresql@15
createuser --interactive --pwprompt
createdb -O your-username coengagedb
```

#### On Windows:

Download and install PostgreSQL from the [official site](https://rajs.dev). After installation, open the SQL Shell (psql) app and login as the superuser. Then run the following SQL commands:

```
CREATE USER your-username WITH ENCRYPTED PASSWORD 'your-password';
ALTER USER your-username CREATEDB;
CREATE DATABASE coengagedb OWNER your-username;
```

### 5. Setting up environment variables

Create a new file named `.env` inside the `hackersclub_backend/hackersclub_backend` directory (on the same level as `settings.py`) and add the following content:

```bash
DJANGO_SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
DATABASE_URL=postgres://your-username:your-password@localhost:5432/coengagedb
AWS_ACCESS_KEY_ID=your-aws-access-key
AWS_SECRET_ACCESS_KEY=your-aws-secret-key
AWS_SES_REGION_NAME=your-aws-ses-region-name
AWS_SES_REGION_ENDPOINT=your-aws-ses-region-endpoint
AWS_SES_EMAIL_SOURCE=your-aws-ses-email-source
AWS_STORAGE_BUCKET_NAME=your-aws-storage-bucket-name
AWS_S3_REGION_NAME=your-aws-s3-region-name


```

Replace placeholders (your-...) with actual values.

### 6. Django Commands

Once the database is set up, run the following commands:

```bash
python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser
```

#### Run the Development Server
```bash
python manage.py runserver
```

You should now be able to navigate to http://localhost:8000 in your web browser and see your running application.
