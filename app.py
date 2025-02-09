from flask import Flask, request, render_template, jsonify, redirect, url_for, send_file
import dkim
import spf
import dns.resolver
from email.parser import Parser
import re
from datetime import datetime
import uuid
import json
from werkzeug.exceptions import HTTPException
import logging
from logging.handlers import RotatingFileHandler
import os
from dashboard import create_dashboard
from models import db, User
import bcrypt
from validate_email import validate_email
import html


# Initialize Flask app first
app = Flask(__name__)

# Store results temporarily (in production, use a database)
analysis_results = {}

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

def setup_logging():
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Configure main application logger
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
    )
    
    # Application log
    app_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=1024 * 1024,  # 1MB
        backupCount=10
    )
    app_handler.setFormatter(formatter)
    app_handler.setLevel(logging.INFO)
    app.logger.addHandler(app_handler)
    app.logger.setLevel(logging.INFO)
    
    # Analysis log
    analysis_logger = logging.getLogger('analysis')
    analysis_handler = RotatingFileHandler(
        'logs/analysis.log',
        maxBytes=1024 * 1024,
        backupCount=10
    )
    analysis_handler.setFormatter(formatter)
    analysis_logger.addHandler(analysis_handler)
    analysis_logger.setLevel(logging.INFO)
    
    # Add initial log entries to verify logging is working
    app.logger.info("Application started - Logging system initialized")
    analysis_logger.info("Email analysis system ready")
    
    return analysis_logger

analysis_logger = setup_logging()

# Create the Dash app
dash_app = create_dashboard(app)

# Ensure the assets directory is properly registered
app.static_folder = 'assets'

@app.route("/")
def home():
    app.logger.info("Home page accessed")
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze_email():
    try:
        # Get headers from either JSON or form data
        if request.is_json:
            if not request.data:
                return jsonify({"error": "Empty JSON request"}), 400
            headers = request.json.get("headers")
        else:
            headers = request.form.get("headers")

        if not headers:
            return jsonify({"error": "No email headers provided"}), 400
        if not isinstance(headers, str):
            return jsonify({"error": "Headers must be a string"}), 400

        try:
            # Parse email headers
            parsed_headers = Parser().parsestr(headers)
            
            # Extract basic email information
            email_info = {
                "from": mask_email_address(parsed_headers.get('from', 'Unknown')),
                "subject": parsed_headers.get('subject', 'No Subject'),
                "date": parsed_headers.get('date', 'Unknown'),
                "has_attachments": 'multipart/mixed' in parsed_headers.get('content-type', '').lower()
            }
            
            # Extract key headers for logging (being mindful of privacy)
            subject = parsed_headers.get('subject', 'No Subject')
            from_addr = parsed_headers.get('from', 'Unknown')
            message_id = parsed_headers.get('message-id', 'No Message ID')
            
            # Mask email addresses for privacy in logs
            from_addr = mask_email_address(from_addr)
            
        except Exception as e:
            app.logger.error(f"Header parsing error: {str(e)}")
            return jsonify({"error": "Invalid email header format"}), 400

        # Extract Authentication-Results header
        auth_results = parsed_headers.get("Authentication-Results", "").lower()
        
        if not auth_results:
            analysis_logger.warning(
                f"No Authentication-Results header found. Subject: {subject}, "
                f"From: {from_addr}, Message-ID: {message_id}"
            )
            return jsonify({
                "warning": "No Authentication-Results header found",
                "results": {
                    "SPF": "neutral",
                    "DKIM": "neutral",
                    "DMARC": "neutral"
                }
            }), 200

        try:
            # More detailed analysis
            spf_result = "fail"
            dkim_result = "fail"
            dmarc_result = "fail"

            # Check SPF
            if "spf=pass" in auth_results:
                spf_result = "pass"
            
            # Check DKIM
            if "dkim=pass" in auth_results:
                dkim_result = "pass"
            
            # Check DMARC
            if "dmarc=pass" in auth_results:
                dmarc_result = "pass"

            # Generate unique ID for this analysis
            analysis_id = str(uuid.uuid4())
            
            # Log the analysis results
            analysis_logger.info(
                f"Analysis completed - ID: {analysis_id}, "
                f"Subject: {subject}, From: {from_addr}, "
                f"Message-ID: {message_id}, "
                f"Results: SPF={spf_result}, DKIM={dkim_result}, DMARC={dmarc_result}"
            )

            # Store results with detailed information
            analysis_results[analysis_id] = {
                "results": {
                    "SPF": spf_result,
                    "DKIM": dkim_result,
                    "DMARC": dmarc_result,
                },
                "email_info": email_info,
                "raw_headers": headers,  # Add raw headers
                "details": {
                    "spf": get_spf_details(spf_result, auth_results),
                    "dkim": get_dkim_details(dkim_result, auth_results),
                    "dmarc": get_dmarc_details(dmarc_result, auth_results)
                },
                "recommendations": {
                    "spf": get_spf_recommendations(spf_result),
                    "dkim": get_dkim_recommendations(dkim_result),
                    "dmarc": get_dmarc_recommendations(dmarc_result)
                },
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            return jsonify({"analysis_id": analysis_id})

        except Exception as e:
            analysis_logger.error(
                f"Analysis failed - Subject: {subject}, "
                f"From: {from_addr}, Message-ID: {message_id}, "
                f"Error: {str(e)}"
            )
            return jsonify({"error": "Error analyzing email headers"}), 500

    except Exception as e:
        app.logger.error(f"Error in analyze_email: {str(e)}")
        return jsonify({"error": "An unexpected error occurred processing the request"}), 500

def get_spf_details(status, auth_results):
    if status == "pass":
        return "SPF authentication passed. The sending server is authorized."
    return "SPF authentication failed. The sending server may not be authorized."

def get_dkim_details(status, auth_results):
    if status == "pass":
        return "DKIM signature is valid and matches the sending domain."
    return "DKIM signature validation failed or was not present."

def get_dmarc_details(status, auth_results):
    if status == "pass":
        return "DMARC check passed. Email complies with domain's policy."
    return "DMARC check failed. Email may not comply with domain's policy."

def get_spf_recommendations(status):
    if status.lower() == "pass":
        return [
            "✓ SPF record is properly configured",
            "→ Monitor for any changes in sending infrastructure",
            "→ Regularly audit authorized sending IPs",
            "→ Consider implementing DMARC if not already in place"
        ]
    return [
        "⚠ Implement SPF record for your domain",
        "→ Include all legitimate sending servers in SPF record",
        "→ Use SPF record validator to ensure correct syntax",
        "→ Consider starting with ~all before moving to -all",
        "→ Document all email sending sources"
    ]

def get_dkim_recommendations(status):
    if status.lower() == "pass":
        return [
            "✓ DKIM is properly configured",
            "→ Maintain regular key rotation schedule",
            "→ Monitor for any signing issues",
            "→ Keep private keys secure"
        ]
    return [
        "⚠ Set up DKIM signing for your domain",
        "→ Generate 2048-bit DKIM keys",
        "→ Implement automated key rotation",
        "→ Verify DKIM configuration with testing tools",
        "→ Configure proper key storage security"
    ]

def get_dmarc_recommendations(status):
    if status.lower() == "pass":
        return [
            "✓ DMARC is properly configured",
            "→ Review DMARC reports regularly",
            "→ Consider increasing policy strictness",
            "→ Monitor for unauthorized sending activities"
        ]
    return [
        "⚠ Create DMARC record for your domain",
        "→ Start with p=none to monitor results",
        "→ Gradually increase enforcement level",
        "→ Set up DMARC report analysis",
        "→ Configure aggregate and forensic reporting"
    ]

@app.route("/results/<analysis_id>")
def show_results(analysis_id):
    if analysis_id not in analysis_results:
        return redirect(url_for('home'))
    
    analysis = analysis_results[analysis_id]
    
    return render_template(
        "results.html",
        results={
            "SPF": analysis["results"]["SPF"],
            "DKIM": analysis["results"]["DKIM"],
            "DMARC": analysis["results"]["DMARC"],
            "email_info": analysis["email_info"],
            "raw_headers": analysis["raw_headers"]
        },
        spf_recommendations=analysis["recommendations"]["spf"],
        dkim_recommendations=analysis["recommendations"]["dkim"],
        dmarc_recommendations=analysis["recommendations"]["dmarc"],
        timestamp=analysis["timestamp"]
    )

@app.route("/chat", methods=["POST"])
def chat():
    try:
        if not request.is_json:
            return jsonify({"error": "Request must be JSON"}), 400

        data = request.get_json()
        if data is None:
            return jsonify({"error": "Invalid JSON data"}), 400

        user_message = data.get("message", "").strip()
        
        if not user_message:
            return jsonify({"error": "Message cannot be empty"}), 400
        
        if len(user_message) > 500:  # Add reasonable limit
            return jsonify({"error": "Message too long. Maximum 500 characters allowed"}), 400

        # Convert to lower case for processing
        user_message_lower = user_message.lower()
        
        # Enhanced chatbot responses
        if "spf" in user_message_lower:
            response = "SPF (Sender Policy Framework) helps prevent email spoofing by specifying which servers are authorized to send emails for your domain. Would you like to know more about implementing SPF?"
        elif "dkim" in user_message_lower:
            response = "DKIM (DomainKeys Identified Mail) adds a digital signature to emails, allowing recipients to verify the email's authenticity and integrity. Need help with DKIM setup?"
        elif "dmarc" in user_message_lower:
            response = "DMARC builds on SPF and DKIM to help email domain owners protect their domain from unauthorized use. It provides clear policies for handling authentication failures. Want to learn more?"
        elif any(word in user_message_lower for word in ["hello", "hi", "hey"]):
            response = "Hello! I'm your email security assistant. How can I help you understand email authentication better?"
        elif "help" in user_message_lower:
            response = "I can help you understand SPF, DKIM, and DMARC. What specific aspect of email security would you like to learn about?"
        else:
            response = "I'm here to help with email security questions. You can ask about SPF, DKIM, DMARC, or general email security best practices."
        
        return jsonify({
            "response": response,
            "timestamp": datetime.now().isoformat()
        })
    
    except Exception as e:
        app.logger.error(f"Error in chat endpoint: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500

def calculate_risk_score(spf_result, dkim_result, dmarc_result):
    """Calculate risk score based on authentication results"""
    base_score = 0
    
    # SPF Check (30 points)
    if spf_result.lower() == "fail":
        base_score += 30
    
    # DKIM Check (30 points)
    if dkim_result.lower() == "fail":
        base_score += 30
    
    # DMARC Check (40 points)
    if dmarc_result.lower() == "fail":
        base_score += 40
    
    return base_score

def get_risk_level(score):
    """Determine risk level based on score"""
    if score <= 30:
        return {
            "level": "Low Risk",
            "explanation": "This email passes most security checks and appears to be legitimate. The sending domain has properly implemented email authentication measures.",
            "color": "#10b981"  # success-color
        }
    elif score <= 60:
        return {
            "level": "Medium Risk",
            "explanation": "Some security checks have failed. This could indicate a misconfiguration or potential security concern. Verify the sender's authenticity before taking any action.",
            "color": "#f59e0b"  # warning-color
        }
    else:
        return {
            "level": "High Risk",
            "explanation": "Multiple security checks have failed. This email shows strong indicators of potential spoofing or unauthorized sending. Exercise extreme caution.",
            "color": "#ef4444"  # error-color
        }

@app.route("/risk-assessment/<analysis_id>")
def risk_assessment(analysis_id):
    if analysis_id not in analysis_results:
        return redirect(url_for('home'))
    
    analysis = analysis_results[analysis_id]
    results = analysis["results"]
    
    risk_score = calculate_risk_score(
        results["SPF"],
        results["DKIM"],
        results["DMARC"]
    )
    
    risk_info = get_risk_level(risk_score)
    
    return render_template(
        'risk_report.html',
        analysis_id=analysis_id,
        risk_score=risk_score,
        risk_level=risk_info["level"],
        explanation=risk_info["explanation"],
        spf_status=results["SPF"],
        dkim_status=results["DKIM"],
        dmarc_status=results["DMARC"],
        timestamp=analysis["timestamp"]
    )

@app.route("/logs/<log_type>")
def view_logs(log_type):
    """View logs in the browser - In production, secure this with authentication!"""
    if log_type not in ['app', 'analysis']:
        app.logger.warning(f"Invalid log type requested: {log_type}")
        return jsonify({"error": "Invalid log type"}), 400
        
    try:
        log_file = f'logs/{log_type}.log'
        if not os.path.exists(log_file):
            app.logger.error(f"Log file not found: {log_file}")
            return render_template(
                'logs.html',
                log_type=log_type,
                log_entries=["No logs found. The log file has not been created yet."],
                error=True
            )
            
        # Read the last 100 lines
        with open(log_file, 'r') as f:
            lines = f.readlines()[-100:]
            
        if not lines:
            lines = ["No log entries yet."]
            
        return render_template(
            'logs.html',
            log_type=log_type,
            log_entries=lines
        )
    except Exception as e:
        app.logger.error(f"Error reading log file: {str(e)}")
        return render_template(
            'logs.html',
            log_type=log_type,
            log_entries=[f"Error reading log file: {str(e)}"],
            error=True
        )

@app.route("/download-logs/<log_type>")
def download_logs(log_type):
    """Download log file"""
    if log_type not in ['app', 'analysis']:
        return jsonify({"error": "Invalid log type"}), 400
        
    try:
        log_file = f'logs/{log_type}.log'
        if not os.path.exists(log_file):
            return jsonify({"error": "Log file not found"}), 404
            
        return send_file(
            log_file,
            mimetype='text/plain',
            as_attachment=True,
            download_name=f'{log_type}.log'
        )
    except Exception as e:
        app.logger.error(f"Error downloading log file: {str(e)}")
        return jsonify({"error": "Error downloading log file"}), 500

@app.errorhandler(404)
def not_found_error(error):
    if request.accept_mimetypes.accept_json and \
       not request.accept_mimetypes.accept_html:
        return jsonify({"error": "Resource not found"}), 404
    return render_template('error.html', 
                         error_code=404,
                         message="The requested resource was not found"), 404

@app.errorhandler(500)
def internal_error(error):
    if request.accept_mimetypes.accept_json and \
       not request.accept_mimetypes.accept_html:
        return jsonify({"error": "Internal server error"}), 500
    return render_template('error.html',
                         error_code=500,
                         message="An internal server error occurred"), 500

@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return e

    # Log the error for debugging
    app.logger.error(f"Unhandled exception: {str(e)}")
    
    if request.accept_mimetypes.accept_json and \
       not request.accept_mimetypes.accept_html:
        return jsonify({"error": "An unexpected error occurred"}), 500
    return render_template('error.html',
                         error_code=500,
                         message="An unexpected error occurred"), 500

def mask_email_address(email):
    """Mask email address for privacy in logs."""
    try:
        if '<' in email and '>' in email:
            # Handle "Display Name <email@domain.com>" format
            display_part = email.split('<')[0].strip()
            email_part = email.split('<')[1].split('>')[0]
        else:
            display_part = ""
            email_part = email.strip()

        if '@' in email_part:
            username, domain = email_part.split('@')
            if len(username) > 3:
                masked_username = username[:3] + '*' * (len(username) - 3)
            else:
                masked_username = username[0] + '*' * (len(username) - 1)
            
            masked_email = f"{masked_username}@{domain}"
            
            if display_part:
                return f"{display_part} <{masked_email}>"
            return masked_email
        return email
    except Exception:
        return "Invalid Email Format"

if __name__ == "__main__":
    # Run the Flask app
    app.run(debug=True, port=5000)

