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
import openai

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Validate required environment variables
required_env_vars = ["OPENAI_API_KEY", "SENDGRID_TO_EMAIL", "SENDGRID_FROM_EMAIL"]
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
                {"role": "system", "content": "Extract structured referral data in JSON format for patient_name, dob, phone_number, and insurance_name."},
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
        }

        referral = Referral(**normalized_data)
        db.session.add(referral)
        db.session.commit()

        return {"message": "Referral processed successfully."}, 200
    except Exception as e:
        return {"error": str(e)}, 500

# API endpoint to view dashboard
@app.route('/dashboard', methods=['GET'])
def dashboard():
    referrals = Referral.query.all()
    return render_template("dashboard.html", referrals=referrals)

if __name__ == "__main__":
    initialize_database()
    app.run(debug=True, host="0.0.0.0", port=8000)

