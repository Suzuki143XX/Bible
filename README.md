# 📖 Bible AI

A beautiful, AI-powered Bible verse application with user authentication, real-time verse generation, and a comprehensive admin panel.

![Bible AI](https://img.shields.io/badge/Bible-AI-blue)
![Flask](https://img.shields.io/badge/Flask-3.0.0-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

### User Features
- 🔐 **Google OAuth Login** - Secure authentication
- 📜 **Auto-Generated Verses** - New verses every minute
- ❤️ **Like & Save** - Build your personal collection
- 💬 **Comments** - Discuss verses with the community
- 🎯 **AI Recommendations** - Smart verse suggestions
- 🌓 **Dark/Light Mode** - Theme toggle
- 📱 **Responsive Design** - Works on all devices

### Admin Features
- 📊 **Admin Dashboard** - Statistics and overview
- 👥 **User Management** - Ban/unban, role changes
- 📋 **Audit Logs** - Track all admin actions
- ⚙️ **System Settings** - Configure verse intervals

## 🚀 Quick Deploy to Render

### Option 1: One-Click Deploy (Blueprint)

1. **Fork this repository** to your GitHub account
2. **Create a Blueprint on Render:**
   - Go to [Render Dashboard](https://dashboard.render.com/)
   - Click "Blueprints"
   - Connect your GitHub repo
   - Click "New Blueprint Instance"
   - Select this repository

3. **Set Environment Variables:**
   After the blueprint deploys, add these in Render Dashboard:
   
   | Variable | Description | How to Get |
   |----------|-------------|------------|
   | `GOOGLE_CLIENT_ID` | Google OAuth Client ID | [Google Cloud Console](https://console.cloud.google.com/) |
   | `GOOGLE_CLIENT_SECRET` | Google OAuth Secret | [Google Cloud Console](https://console.cloud.google.com/) |
   | `ADMIN_CODE` | Code to unlock admin panel | Create your own secret code |
   | `ADMIN_PASSWORD` | Master admin password | Create a strong password |

### Option 2: Manual Deploy

1. **Push to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/bible-ai.git
   git push -u origin main
   ```

2. **Create Web Service on Render:**
   - Go to [Render Dashboard](https://dashboard.render.com/)
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Configure:
     - **Name:** `bible-ai`
     - **Runtime:** `Python 3`
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `gunicorn app:app`

3. **Create PostgreSQL Database:**
   - Click "New +" → "PostgreSQL"
   - Name it `bible-ai-db`
   - Copy the "Internal Database URL"

4. **Add Environment Variables:**
   In your Web Service settings, add:
   - `DATABASE_URL` = (paste the database URL)
   - `SECRET_KEY` = (generate a random string)
   - `GOOGLE_CLIENT_ID` = (from Google Cloud)
   - `GOOGLE_CLIENT_SECRET` = (from Google Cloud)
   - `ADMIN_CODE` = (your admin unlock code)
   - `ADMIN_PASSWORD` = (your master password)

## 🔧 Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the **Google+ API**
4. Go to **Credentials** → **Create Credentials** → **OAuth client ID**
5. Configure OAuth consent screen
6. Add authorized redirect URIs:
   - `https://your-app-name.onrender.com/callback`
   - `http://localhost:5000/callback` (for local testing)
7. Copy the Client ID and Client Secret

## 🏠 Local Development

### Prerequisites
- Python 3.11+
- pip

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/bible-ai.git
   cd bible-ai
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   
   # Windows
   venv\Scripts\activate
   
   # macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables:**
   Create a `.env` file:
   ```
   SECRET_KEY=your-secret-key-here
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   ADMIN_CODE=your-admin-code
   ADMIN_PASSWORD=your-admin-password
   ```

5. **Run the application:**
   ```bash
   python app.py
   ```

6. **Access the app:**
   Open http://localhost:5000 in your browser

## 📁 Project Structure

```
bible-ai/
├── app.py                 # Main Flask application
├── admin.py              # Admin panel blueprint
├── requirements.txt      # Python dependencies
├── render.yaml          # Render blueprint config
├── README.md            # This file
├── .gitignore           # Git ignore rules
├── static/              # Static assets
│   ├── manifest.json
│   └── audio/           # Audio files
└── templates/           # HTML templates
    ├── login.html       # User login page
    ├── web.html         # Main application
    ├── admin_login.html # Admin login
    ├── admin_dashboard.html
    ├── admin_users.html
    ├── admin_user_detail.html
    ├── admin_audits.html
    ├── admin_settings.html
    └── admin_base.html
```

## 👑 Admin Access

### Becoming an Admin

1. **Login** with your Google account
2. **Go to Settings** (⚙️ icon)
3. **Click "Unlock Admin Panel"**
4. **Enter the admin code** (set in `ADMIN_CODE` env var)
5. You're now an admin!

### Admin Panel URL
Once you're an admin, access the admin panel at:
```
https://your-app-name.onrender.com/admin
```

### Admin Roles
- **User** - Regular user
- **Host** - Can unlock admin panel
- **Admin** - Full admin access
- **Super Admin** - Complete control

## 🔒 Security

- All passwords and codes are stored as environment variables
- Admin actions are logged to the audit log
- User bans can be temporary or permanent
- CSRF protection on all forms
- Session management with secure cookies

## 📝 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask secret key for sessions |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `GOOGLE_CLIENT_ID` | Yes | Google OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | Yes | Google OAuth Client Secret |
| `ADMIN_CODE` | Yes | Code to unlock admin privileges |
| `ADMIN_PASSWORD` | No | Master admin password |
| `RENDER_EXTERNAL_URL` | Auto | Set automatically by Render |
| `PORT` | Auto | Set automatically by Render |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🙏 Credits

- Bible verses provided by [Bible-API.com](https://bible-api.com/)
- Icons and emojis from various open sources

---

Made with ❤️ and faith
