import os
import json
import base64
import csv
import tempfile
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from pdf2image import convert_from_path
import pytesseract
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition
from io import StringIO  # Ensure StringIO is imported
import openai

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Validate required environment variables
required_env_vars = ["OPENAI_API_KEY", "SENDGRID_TO_EMAIL", "SENDGRID_FROM_EMAIL", "SENDGRID_API_KEY"]
for var in required_env_vars:
    if not os.getenv(var):
        raise RuntimeError(f"Environment variable {var} is missing.")

# OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///default.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(255), nullable=False)
    dob = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(50), nullable=False)
    insurance_name = db.Column(db.String(255), nullable=False)
    fax_receive_date = db.Column(db.String(50), nullable=True)
    referring_doctor_name = db.Column(db.String(255), nullable=True)
    referring_clinic_name = db.Column(db.String(255), nullable=True)
    referring_phone_number = db.Column(db.String(50), nullable=True)
    referring_fax_number = db.Column(db.String(50), nullable=True)

# Initialize database tables
def initialize_database():
    with app.app_context():
        db.create_all()

# Root route to redirect to dashboard
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

# Function to process PDF and extract text
def process_pdf(pdf_path):
    try:
        images = convert_from_path(pdf_path)
        extracted_text = ""
        for image in images:
            text = pytesseract.image_to_string(image)
            extracted_text += text + "\n"
        return extracted_text
    except Exception as e:
        return {"error": str(e)}

# Function to process text with OpenAI
def process_text_with_openai(text):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "Extract structured referral data in JSON format for patient_name, dob, phone_number, insurance_name, fax_receive_date, referring_doctor_name, referring_clinic_name, referring_phone_number, and referring_fax_number."},
                {"role": "user", "content": text}
            ],
            temperature=0,
            max_tokens=1000
        )
        content = response['choices'][0]['message']['content']
        return json.loads(content)
    except (json.JSONDecodeError, Exception) as e:
        print("Error decoding JSON or OpenAI API issue:", e)
        return {"error": "The response from OpenAI could not be parsed."}

# Function to format phone numbers
def format_phone_number(phone):
    phone = ''.join(filter(str.isdigit, phone))  # Keep only digits
    if len(phone) == 10:
        return f"{phone[:3]}-{phone[3:6]}-{phone[6:]}"
    return phone

# Function to capitalize all fields
def capitalize_fields(data):
    return {key: (value.upper() if isinstance(value, str) else value) for key, value in data.items()}

# API endpoint to process a PDF
@app.route('/process', methods=['POST'])
def process_referral():
    try:
        if 'file' not in request.files:
            return {"error": "No file part in the request"}, 400
        file = request.files['file']
        if not file.filename.lower().endswith('.pdf'):
            return {"error": "Invalid file type. Only PDF files are allowed."}, 400

        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = os.path.join(temp_dir, file.filename)
            file.save(pdf_path)

            raw_text = process_pdf(pdf_path)
            if isinstance(raw_text, dict) and "error" in raw_text:
                return raw_text, 500

        referral_data = process_text_with_openai(raw_text)
        if isinstance(referral_data, dict) and "error" in referral_data:
            return referral_data, 500

        normalized_data = {
            "patient_name": referral_data.get("Patient Name") or referral_data.get("patient_name", "Unknown"),
            "dob": referral_data.get("DOB") or referral_data.get("dob", "Unknown"),
            "phone_number": referral_data.get("Phone Number") or referral_data.get("phone_number", "Unknown"),
            "insurance_name": referral_data.get("Insurance Name") or referral_data.get("insurance_name", "Unknown"),
            "fax_receive_date": referral_data.get("Fax Receive Date") or referral_data.get("fax_receive_date", "Unknown"),
            "referring_doctor_name": referral_data.get("Referring Doctor Name") or referral_data.get("referring_doctor_name", "Unknown"),
            "referring_clinic_name": referral_data.get("Referring Clinic Name") or referral_data.get("referring_clinic_name", "Unknown"),
            "referring_phone_number": referral_data.get("Referring Phone Number") or referral_data.get("referring_phone_number", "Unknown"),
            "referring_fax_number": referral_data.get("Referring Fax Number") or referral_data.get("referring_fax_number", "Unknown"),
        }

        # Capitalize all string fields and format phone numbers
        normalized_data = capitalize_fields(normalized_data)
        normalized_data['phone_number'] = format_phone_number(normalized_data['phone_number'])
        normalized_data['referring_phone_number'] = format_phone_number(normalized_data['referring_phone_number'])
        normalized_data['referring_fax_number'] = format_phone_number(normalized_data['referring_fax_number'])

        referral = Referral(**normalized_data)
        db.session.add(referral)
        db.session.commit()

        # Log email sending process
        try:
            # Check if email settings are configured
            to_email = os.getenv('SENDGRID_TO_EMAIL')
            from_email = os.getenv('SENDGRID_FROM_EMAIL')
            sendgrid_api_key = os.getenv('SENDGRID_API_KEY')

            if to_email and from_email and sendgrid_api_key:
                csv_buffer = StringIO()
                csv_writer = csv.writer(csv_buffer)
                csv_writer.writerow(["Patient Name", "DOB", "Phone Number", "Insurance Name", "Fax Receive Date", "Referring Doctor Name", "Referring Clinic Name", "Referring Phone Number", "Referring Fax Number"])
                csv_writer.writerow([
                    normalized_data["patient_name"],
                    normalized_data["dob"],
                    normalized_data["phone_number"],
                    normalized_data["insurance_name"],
                    normalized_data["fax_receive_date"],
                    normalized_data["referring_doctor_name"],
                    normalized_data["referring_clinic_name"],
                    normalized_data["referring_phone_number"],
                    normalized_data["referring_fax_number"],
                ])
                csv_buffer.seek(0)

                message = Mail(
                    from_email=from_email.strip(),
                    to_emails=to_email.strip(),
                    subject="Referral Processed",
                    html_content="<p>The referral has been processed successfully. See the attached CSV file for details.</p>"
                )
                message.attachment = Attachment(
                    FileContent(base64.b64encode(csv_buffer.getvalue().encode()).decode()),
                    FileName("referral.csv"),
                    FileType("text/csv"),
                    Disposition("attachment")
                )

                sg = SendGridAPIClient(sendgrid_api_key.strip())
                response = sg.send(message)
                print(f"Email sent! Status code: {response.status_code}")
            else:
                print("Missing email configuration.")
        except Exception as email_error:
            print(f"Failed to send email: {email_error}")

        return {"message": "Referral processed successfully."}, 200
    except Exception as e:
        return {"error": str(e)}, 500

# API endpoint to view dashboard
@app.route('/dashboard', methods=['GET'])
def dashboard():
    referrals = Referral.query.all()
    return render_template("dashboard.html", referrals=referrals)

# API endpoint to delete a referral
@app.route('/delete/<int:referral_id>', methods=['POST'])
def delete_referral(referral_id):
    try:
        referral = Referral.query.get(referral_id)
        if not referral:
            return {"error": "Referral not found"}, 404

        db.session.delete(referral)
        db.session.commit()
        return redirect(url_for('dashboard'))
    except Exception as e:
        return {"error": str(e)}, 500

if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, host="0.0.0.0", port=8000)

