# app.py

import os
import imaplib
import email
import tempfile
import json
import csv
from io import StringIO, BytesIO
from functools import wraps
from datetime import timedelta
import base64
import threading  # For background tasks
import time        # For sleep functionality

from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    login_required,
    logout_user,
    current_user,
    UserMixin,
)
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import (
    StringField,
    PasswordField,
    BooleanField,
    SubmitField,
    IntegerField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Email, Length, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail,
    Attachment,
    FileContent,
    FileName,
    FileType,
    Disposition,
)

import openai
import pytesseract
from pdf2image import convert_from_path

import logging

# -------------------------------------------------
# Initialize Flask app
# -------------------------------------------------
app = Flask(__name__)

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv()

# Configuration
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max file size
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 1800,  # Recycle connections after 1800 seconds (30 minutes)
    # You can add other options like 'pool_size', 'max_overflow' if needed
}



# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
csrf = CSRFProtect(app)

# Initialize Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]",
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ],
)
logger = logging.getLogger(__name__)  # Initialize a logger for this module

# Initialize OpenAI
openai.api_key = os.getenv("OPENAI_API_KEY")

# -------------------------------------------------
# Define Models
# -------------------------------------------------


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)  # Using scrypt
    is_admin = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        # Using 'scrypt' for password hashing
        self.password_hash = generate_password_hash(password, method="scrypt")
        logger.info(f"[INFO] Password hash set for user '{self.username}'.")

    def check_password(self, password):
        result = check_password_hash(self.password_hash, password)
        logger.debug(f"[DEBUG] Password check for user '{self.username}': {result}")
        return result

    def __repr__(self):
        return f"<User {self.username} - Admin: {self.is_admin}>"


class Referral(db.Model):
    __tablename__ = "referrals"
    id = db.Column(db.Integer, primary_key=True)
    record_type = db.Column(db.String(100), nullable=False, default="Referral")
    patient_details = db.Column(db.Text, nullable=True)  # JSON string
    record_details = db.Column(db.Text, nullable=True)  # JSON string

    def __repr__(self):
        return f"<Referral {self.id} - Type: {self.record_type}>"


class Setting(db.Model):
    __tablename__ = "settings"
    id = db.Column(db.Integer, primary_key=True)
    field_name = db.Column(db.String(255), nullable=False, unique=True)
    field_config = db.Column(db.Text, nullable=False)  # Stored as JSON string

    def __repr__(self):
        return f"<Setting {self.field_name}>"

# -------------------------------------------------
# User Loader for Flask-Login
# -------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    logger.debug(f"[DEBUG] Loading user with ID: {user_id}")
    return User.query.get(int(user_id))


# -------------------------------------------------
# Define Forms using Flask-WTF
# -------------------------------------------------
class LoginForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=3, max=150)]
    )
    password = PasswordField("Password", validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


class SettingsForm(FlaskForm):
    SENDGRID_FROM_EMAIL = StringField(
        "SendGrid From Email", validators=[DataRequired(), Email()]
    )
    SENDGRID_TO_EMAIL = StringField(
        "SendGrid To Email", validators=[DataRequired(), Email()]
    )
    EMAIL_HOST = StringField("Email Host", validators=[DataRequired()])
    EMAIL_PORT = IntegerField(
        "Email Port", validators=[DataRequired(), NumberRange(min=1, max=65535)]
    )
    EMAIL_USERNAME = StringField("Email Username", validators=[DataRequired()])
    ENABLE_EMAIL_CSV = BooleanField("Enable Emailing CSV")
    CSV_EMAIL_RECIPIENT = StringField(
        "CSV Email Recipient", validators=[Email(), Length(max=150)]
    )
    CSV_EMAIL_SUBJECT = StringField(
        "CSV Email Subject", validators=[DataRequired(), Length(max=255)]
    )
    CSV_EMAIL_BODY = TextAreaField(
        "CSV Email Body", validators=[DataRequired(), Length(max=2000)]
    )
    # Adding patient_details and record_details
    PATIENT_DETAILS = TextAreaField(
        "Patient Details (comma-separated)", validators=[DataRequired()]
    )
    RECORD_DETAILS = TextAreaField(
        "Record Details (comma-separated)", validators=[DataRequired()]
    )
    submit = SubmitField("Save Settings")


# -------------------------------------------------
# Utility Functions
# -------------------------------------------------
def get_setting(field_name, default=None):
    setting = Setting.query.filter_by(field_name=field_name).first()
    if setting:
        try:
            config = json.loads(setting.field_config)
            logger.debug(f"[DEBUG] Retrieved setting '{field_name}': {config}")
            return config
        except json.JSONDecodeError:
            logger.error(
                f"[ERROR] Invalid JSON for setting '{field_name}'. Using default."
            )
            return default
    logger.warning(f"[WARNING] Setting '{field_name}' not found. Using default.")
    return default


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            logger.warning(
                f"[WARNING] Unauthorized access attempt by user '{current_user.username}'."
            )
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


def initialize_database():
    with app.app_context():
        db.create_all()


        # Ensure an admin user exists
        admin_username = os.getenv('ADMIN_USERNAME', 'admin')
        admin_password = os.getenv('ADMIN_PASSWORD', 'Password123')  # Change this in production
        if not User.query.filter_by(username=admin_username).first():
            admin_user = User(username=admin_username, is_admin=True)
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            logger.info(f"[INFO] Admin user '{admin_username}' created with password '{admin_password}'.")


def send_csv_email(forwarding_email, patient_data, record_data):
    try:
        # Fetch SendGrid settings from the database
        sendgrid_from_email = get_setting("SENDGRID_FROM_EMAIL")
        sendgrid_to_email = get_setting("SENDGRID_TO_EMAIL")
        enable_email_csv = get_setting("ENABLE_EMAIL_CSV", False)
        csv_email_recipient = get_setting("CSV_EMAIL_RECIPIENT", sendgrid_to_email)
        csv_email_subject = get_setting("CSV_EMAIL_SUBJECT", "New Referral Processed")
        csv_email_body = get_setting("CSV_EMAIL_BODY", "<p>Attached is the processed referral data in CSV format.</p>")

        if not enable_email_csv:
            logger.info("[INFO] Emailing CSV is disabled in settings.")
            return

        # Create CSV content with Patient Details and Record Details
        csv_content = StringIO()
        writer = csv.writer(csv_content)

        # Write Patient Details
        writer.writerow(["Patient Details"])
        writer.writerow(["Field", "Value"])
        for key, value in patient_data.items():
            writer.writerow([key, value])
        writer.writerow([])  # Empty row for separation

        # Write Record Details
        writer.writerow(["Record Details"])
        writer.writerow(["Field", "Value"])
        for key, value in record_data.items():
            writer.writerow([key, value])

        # Encode CSV to base64 for attachment
        encoded_csv = base64.b64encode(csv_content.getvalue().encode('utf-8')).decode('utf-8')

        # Prepare email
        message = Mail(
            from_email=sendgrid_from_email,
            to_emails=csv_email_recipient,
            subject=csv_email_subject,
            html_content=csv_email_body
        )
        attachment = Attachment()
        attachment.file_content = FileContent(encoded_csv)
        attachment.file_type = FileType("text/csv")
        attachment.file_name = FileName("referral.csv")
        attachment.disposition = Disposition("attachment")
        message.attachment = attachment

        # Send email via SendGrid
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sg.send(message)
        logger.info(f"[INFO] Email sent successfully with status code: {response.status_code}")
    except Exception as e:
        logger.error(f"[ERROR] Failed to send email: {e}")


def generate_individual_csv(referral):
    """
    Generates a CSV file from a single Referral object.
    """
    output = StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['ID', 'Record Type'])

    # Write basic details
    writer.writerow([referral.id, referral.record_type])

    # Deserialize JSON fields
    try:
        patient_details = json.loads(referral.patient_details) if referral.patient_details else {}
    except json.JSONDecodeError:
        patient_details = {}
        logger.error(f"[ERROR] Failed to decode patient_details for Referral ID {referral.id}")

    try:
        record_details = json.loads(referral.record_details) if referral.record_details else {}
    except json.JSONDecodeError:
        record_details = {}
        logger.error(f"[ERROR] Failed to decode record_details for Referral ID {referral.id}")

    # Write Patient Details
    writer.writerow([])
    writer.writerow(["Patient Details"])
    writer.writerow(["Field", "Value"])
    for key, value in patient_details.items():
        writer.writerow([key, value])

    # Write Record Details
    writer.writerow([])
    writer.writerow(["Record Details"])
    writer.writerow(["Field", "Value"])
    for key, value in record_details.items():
        writer.writerow([key, value])

    output.seek(0)
    return output


def generate_csv(referrals):
    """
    Generates a CSV file from a list of Referral objects.
    """
    output = StringIO()
    writer = csv.writer(output)

    # Collect all possible patient and record fields
    patient_fields = set()
    record_fields = set()
    for referral in referrals:
        try:
            patient = json.loads(referral.patient_details) if referral.patient_details else {}
            patient_fields.update(patient.keys())
        except json.JSONDecodeError:
            logger.error(f"[ERROR] Failed to decode patient_details for Referral ID {referral.id}")
        try:
            record = json.loads(referral.record_details) if referral.record_details else {}
            record_fields.update(record.keys())
        except json.JSONDecodeError:
            logger.error(f"[ERROR] Failed to decode record_details for Referral ID {referral.id}")

    patient_fields = sorted(patient_fields)
    record_fields = sorted(record_fields)

    # Write header
    writer.writerow(['ID', 'Record Type'] + patient_fields + record_fields)

    # Write data rows
    for referral in referrals:
        row = [referral.id, referral.record_type]
        try:
            patient = json.loads(referral.patient_details) if referral.patient_details else {}
        except json.JSONDecodeError:
            patient = {}
            logger.error(f"[ERROR] Failed to decode patient_details for Referral ID {referral.id}")
        try:
            record = json.loads(referral.record_details) if referral.record_details else {}
        except json.JSONDecodeError:
            record = {}
            logger.error(f"[ERROR] Failed to decode record_details for Referral ID {referral.id}")

        # Add patient fields
        for field in patient_fields:
            row.append(patient.get(field, ""))
        # Add record fields
        for field in record_fields:
            row.append(record.get(field, ""))

        writer.writerow(row)

    output.seek(0)
    return output


def fetch_and_process_emails():
    with app.app_context():
        try:
            # Fetch email settings
            email_host = get_setting("EMAIL_HOST", "imap.gmail.com")
            email_port = get_setting("EMAIL_PORT", 993)
            email_username = get_setting("EMAIL_USERNAME")
            email_password = os.getenv("EMAIL_PASSWORD")

            if not all([email_host, email_port, email_username, email_password]):
                logger.error("[ERROR] Email settings are not properly configured.")
                return

            # Connect to the IMAP server
            mail = imaplib.IMAP4_SSL(email_host, email_port)
            mail.login(email_username, email_password)
            mail.select("inbox")

            # Search for unseen emails
            status, messages = mail.search(None, 'UNSEEN')
            email_ids = messages[0].split()

            for num in email_ids:
                status, data = mail.fetch(num, '(RFC822)')
                for response_part in data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        subject = msg['subject']
                        from_email = msg['from']
                        logger.info(f"[INFO] Processing email from {from_email} with subject '{subject}'.")

                        for part in msg.walk():
                            if part.get_content_type() == "application/pdf":
                                pdf_data = part.get_payload(decode=True)
                                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_pdf:
                                    temp_pdf.write(pdf_data)
                                    pdf_path = temp_pdf.name
                                logger.info(f"[INFO] PDF saved to temporary path: {pdf_path}")

                                # Process PDF
                                raw_text = process_pdf(pdf_path)
                                if raw_text:
                                    # Fetch settings for OpenAI prompt
                                    patient_setting = get_setting("patient_details", "")
                                    record_setting = get_setting("record_details", "")
                                    patient_fields = [field.strip() for field in patient_setting.split(',') if field.strip()]
                                    record_fields = [field.strip() for field in record_setting.split(',') if field.strip()]

                                    if not patient_fields and not record_fields:
                                        logger.warning("[WARNING] No fields defined for extraction.")
                                        continue

                                    # Generate OpenAI prompt
                                    prompt = generate_openai_prompt(raw_text, patient_fields, record_fields)

                                    # Call OpenAI API using ChatCompletion
                                    try:
                                        response = openai.ChatCompletion.create(
                                            model="gpt-4",
                                            messages=[
                                                {"role": "system", "content": "You are an assistant that extracts specific information from text."},
                                                {"role": "user", "content": prompt}
                                            ],
                                            temperature=0,
                                            max_tokens=500
                                        )
                                        extracted_data = response.choices[0].message['content'].strip()
                                        data_json = json.loads(extracted_data)
                                        logger.info(f"[INFO] OpenAI extracted data: {data_json}")

                                        # Normalize and save data
                                        referral = Referral(
                                            record_type=data_json.get("record_type", "Unknown"),
                                            patient_details=json.dumps(data_json.get("patient_details", {})),
                                            record_details=json.dumps(data_json.get("record_details", {}))
                                        )
                                        db.session.add(referral)
                                        db.session.commit()
                                        logger.info(f"[INFO] Referral saved with ID {referral.id}.")

                                        # Send CSV email with both Patient Details and Record Details
                                        forwarding_email = get_setting("SENDGRID_TO_EMAIL", "chris@goldiehealth.com")
                                        send_csv_email(forwarding_email, data_json.get("patient_details", {}), data_json.get("record_details", {}))

                                    except Exception as e:
                                        logger.error(f"[ERROR] Failed to process email with OpenAI: {e}")
            # Mark emails as seen
            for num in email_ids:
                mail.store(num, '+FLAGS', '\\Seen')

            mail.logout()
        except Exception as e:
            logger.error(f"[ERROR] Failed to fetch and process emails: {e}")


def process_pdf(pdf_path, dpi=200):
    try:
        images = convert_from_path(pdf_path, dpi=dpi)
        extracted_text = ""
        for image in images:
            text = pytesseract.image_to_string(image)
            extracted_text += text + "\n"
        logger.info(f"[INFO] Extracted text from PDF: {len(extracted_text)} characters.")
        return extracted_text
    except Exception as e:
        logger.error(f"[ERROR] Error processing PDF: {e}")
        return None


def generate_openai_prompt(text, patient_fields, record_fields):
    patient_prompts = ', '.join(patient_fields)
    record_prompts = ', '.join(record_fields)

    prompt = f"""
Extract the following patient details from the text: {patient_prompts}.
Extract the following record details: {record_prompts}.

Text:
{text}

Format the output as JSON:
{{
    "record_type": "Referral",
    "patient_details": {{
        {', '.join([f'"{field}": ""' for field in patient_fields])}
    }},
    "record_details": {{
        {', '.join([f'"{field}": ""' for field in record_fields])}
    }}
}}
"""
    return prompt


def email_scheduler(interval=300):
    while True:
        logger.info("[INFO] Starting email fetch and processing cycle.")
        fetch_and_process_emails()
        logger.info(f"[INFO] Email fetch and processing cycle completed. Sleeping for {interval} seconds.")
        time.sleep(interval)  # Wait for the specified interval before fetching again


# -------------------------------------------------
# Routes
# -------------------------------------------------

@app.route('/')
def home():
    return redirect(url_for('dashboard'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        logger.info("User already authenticated. Redirecting to dashboard.")
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        logger.info(f"Login form submitted with username: '{form.username.data}'")
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            logger.info(f"User '{user.username}' found in the database.")
            if user.check_password(form.password.data):
                login_user(user, remember=form.remember.data)
                logger.info(f"User '{user.username}' logged in successfully.")
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                logger.warning(f"Incorrect password for user '{user.username}'.")
        else:
            logger.warning(f"User '{form.username.data}' not found in the database.")
        flash("Invalid username or password.", "danger")
    else:
        if request.method == 'POST':
            logger.warning(f"Login form validation failed with errors: {form.errors}")
    return render_template('login.html', form=form)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logger.info(f"[INFO] User '{current_user.username}' is logging out.")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10  # Number of referrals per page
    search_query = request.args.get('search', '', type=str)

    if search_query:
        referrals_paginated = Referral.query.filter(
            Referral.record_type.ilike(f'%{search_query}%') |
            Referral.patient_details.ilike(f'%{search_query}%') |
            Referral.record_details.ilike(f'%{search_query}%')
        ).order_by(Referral.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
        logger.info(f"[INFO] Dashboard accessed with search query: '{search_query}'")
    else:
        referrals_paginated = Referral.query.order_by(Referral.id.desc()).paginate(page=page, per_page=per_page, error_out=False)
        logger.info("[INFO] Dashboard accessed without search query.")

    # Deserialize JSON fields for display
    referrals = []
    for referral in referrals_paginated.items:
        try:
            patient_details = json.loads(referral.patient_details) if referral.patient_details else {}
        except json.JSONDecodeError:
            patient_details = {}
            logger.error(f"[ERROR] Failed to decode patient_details for Referral ID {referral.id}")

        try:
            record_details = json.loads(referral.record_details) if referral.record_details else {}
        except json.JSONDecodeError:
            record_details = {}
            logger.error(f"[ERROR] Failed to decode record_details for Referral ID {referral.id}")

        referrals.append({
            "id": referral.id,
            "record_type": referral.record_type,
            "patient_details": patient_details,
            "record_details": record_details,
        })

    return render_template('dashboard.html', referrals=referrals, pagination=referrals_paginated, search_query=search_query)


# -------------------------------------------------
# New Route: Manage Settings
# -------------------------------------------------
@app.route('/settings', methods=['GET', 'POST'], endpoint='settings_route')
@login_required
@admin_required
def settings_route():
    form = SettingsForm()
    if form.validate_on_submit():
        # Retrieve form data
        settings_data = {
            "SENDGRID_FROM_EMAIL": form.SENDGRID_FROM_EMAIL.data,
            "SENDGRID_TO_EMAIL": form.SENDGRID_TO_EMAIL.data,
            "EMAIL_HOST": form.EMAIL_HOST.data,
            "EMAIL_PORT": form.EMAIL_PORT.data,
            "EMAIL_USERNAME": form.EMAIL_USERNAME.data,
            "ENABLE_EMAIL_CSV": form.ENABLE_EMAIL_CSV.data,
            "CSV_EMAIL_RECIPIENT": form.CSV_EMAIL_RECIPIENT.data,
            "CSV_EMAIL_SUBJECT": form.CSV_EMAIL_SUBJECT.data,
            "CSV_EMAIL_BODY": form.CSV_EMAIL_BODY.data,
            "patient_details": form.PATIENT_DETAILS.data,
            "record_details": form.RECORD_DETAILS.data
        }

        # Update or create settings in the database
        for field_name, field_value in settings_data.items():
            setting = Setting.query.filter_by(field_name=field_name).first()
            if setting:
                # For patient_details and record_details, ensure they are stored as comma-separated strings
                if field_name in ["patient_details", "record_details"]:
                    if not isinstance(field_value, str):
                        logger.error(f"[ERROR] '{field_name}' should be a comma-separated string.")
                        continue
                    field_config = json.dumps(field_value)
                elif isinstance(field_value, bool):
                    field_config = json.dumps(field_value)
                elif isinstance(field_value, int):
                    field_config = json.dumps(field_value)
                else:
                    field_config = json.dumps(field_value)
                setting.field_config = field_config
                logger.info(f"[INFO] Updated setting '{field_name}'.")
            else:
                # Create new settings if they don't exist
                new_setting = Setting(field_name=field_name, field_config=json.dumps(field_value))
                db.session.add(new_setting)
                logger.info(f"[INFO] Created new setting '{field_name}'.")
        try:
            db.session.commit()
            flash("Settings updated successfully!", "success")
            logger.info("[INFO] Settings updated successfully by admin.")
            return redirect(url_for('settings_route'))
        except Exception as e:
            db.session.rollback()
            flash("Failed to update settings.", "danger")
            logger.error(f"[ERROR] Failed to update settings: {e}")

    # Pre-populate form with existing settings on GET request
    if request.method == 'GET':
        settings = Setting.query.all()
        settings_dict = {}
        for s in settings:
            try:
                settings_dict[s.field_name] = json.loads(s.field_config)
            except json.JSONDecodeError:
                logger.error(f"[ERROR] Invalid JSON for setting '{s.field_name}'. Setting to empty string.")
                settings_dict[s.field_name] = ""
        form.SENDGRID_FROM_EMAIL.data = settings_dict.get("SENDGRID_FROM_EMAIL", "")
        form.SENDGRID_TO_EMAIL.data = settings_dict.get("SENDGRID_TO_EMAIL", "")
        form.EMAIL_HOST.data = settings_dict.get("EMAIL_HOST", "")
        form.EMAIL_PORT.data = settings_dict.get("EMAIL_PORT", 993)
        form.EMAIL_USERNAME.data = settings_dict.get("EMAIL_USERNAME", "")
        form.ENABLE_EMAIL_CSV.data = settings_dict.get("ENABLE_EMAIL_CSV", False)
        form.CSV_EMAIL_RECIPIENT.data = settings_dict.get("CSV_EMAIL_RECIPIENT", "")
        form.CSV_EMAIL_SUBJECT.data = settings_dict.get("CSV_EMAIL_SUBJECT", "New Referral Processed")
        form.CSV_EMAIL_BODY.data = settings_dict.get("CSV_EMAIL_BODY", "<p>Attached is the processed referral data in CSV format.</p>")
        form.PATIENT_DETAILS.data = settings_dict.get("patient_details", "")
        form.RECORD_DETAILS.data = settings_dict.get("record_details", "")
        logger.info("[INFO] Settings form pre-populated with existing settings.")

    return render_template('settings.html', form=form)


# -------------------------------------------------
# New Route: Delete a Referral
# -------------------------------------------------
@app.route('/referral/delete/<int:referral_id>', methods=['POST'], endpoint='delete_referral')
@login_required
@admin_required
def delete_referral(referral_id):
    referral = Referral.query.get_or_404(referral_id)
    try:
        db.session.delete(referral)
        db.session.commit()
        flash(f"Referral ID {referral_id} has been deleted.", "success")
        logger.info(f"[INFO] Referral ID {referral_id} deleted by user '{current_user.username}'.")
    except Exception as e:
        db.session.rollback()
        flash("Failed to delete the referral.", "danger")
        logger.error(f"[ERROR] Failed to delete Referral ID {referral_id}: {e}")
    return redirect(url_for('dashboard'))


# -------------------------------------------------
# New Route: Download Individual CSV
# -------------------------------------------------
@app.route('/download_csv/<int:referral_id>', methods=['GET'], endpoint='download_individual_csv')
@login_required
def download_individual_csv(referral_id):
    referral = Referral.query.get_or_404(referral_id)
    try:
        # Generate CSV for the individual referral
        csv_file = generate_individual_csv(referral)

        # Create a BytesIO object from the CSV string
        mem = BytesIO()
        mem.write(csv_file.getvalue().encode('utf-8'))
        mem.seek(0)

        filename = f"referral_{referral.id}.csv"
        return send_file(
            mem,
            mimetype='text/csv',
            download_name=filename,
            as_attachment=True
        )
    except Exception as e:
        flash("Failed to generate CSV.", "danger")
        logger.error(f"[ERROR] Failed to generate CSV for Referral ID {referral_id}: {e}")
        return redirect(url_for('dashboard'))


# -------------------------------------------------
# Scheduler to periodically fetch emails
# -------------------------------------------------
def email_scheduler(interval=300):
    while True:
        logger.info("[INFO] Starting email fetch and processing cycle.")
        fetch_and_process_emails()
        logger.info(f"[INFO] Email fetch and processing cycle completed. Sleeping for {interval} seconds.")
        time.sleep(interval)  # Wait for the specified interval before fetching again


# Start the email scheduler in a separate thread
email_thread = threading.Thread(target=email_scheduler, args=(300,), daemon=True)
email_thread.start()

# -------------------------------------------------
# Initialize Database and Seed Data
# -------------------------------------------------
with app.app_context():
    initialize_database()

# -------------------------------------------------
# Run the Flask app
# -------------------------------------------------
if __name__ == '__main__':
    # Run the Flask app without the reloader to prevent duplicate threads
    app.run(debug=True)

