# Flask User Authentication System

A complete Flask web application that includes:
- User registration with email verification
- JWT-based login
- Protected profile view
- Resend code functionality with cooldown
- Simple HTML frontend
- Styled with CSS and Flask templates

## 🔧 Features
- **Register:** User provides name, email, and password
- **Verify:** Email code verification after registration
- **Login:** Authenticates only if verified
- **Profile:** JWT-protected route displays user info
- **Resend Code:** Resend verification code every 30s max

## 📦 Tech Stack
- Python + Flask
- SQLite with SQLAlchemy
- Flask-Mail for sending emails
- JWT for authentication
- HTML/CSS frontend (no JS frameworks)

## ▶️ Getting Started

### 1. Clone the Repo
```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo
```

### 2. Setup Virtual Environment
```bash
python -m venv .venv
.venv\Scripts\activate   # Windows
# OR
source .venv/bin/activate  # macOS/Linux
```

### 3. Install Requirements
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create a `.env` file or set them in `config.py`:
```
SECRET_KEY=your_secret
JWT_SECRET_KEY=your_jwt_secret
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
```

### 5. Run the App
```bash
python app.py
```
Go to `http://127.0.0.1:5000`

## 📁 Project Structure
```
/your-project
├── app.py
├── config.py
├── static/
│   └── style.css
├── templates/
│   ├── register.html
│   ├── login.html
│   ├── verify.html
│   └── profile.html
├── requirements.txt
└── README.md
```


## 📬 Contact
For issues or suggestions, contact [sabahsaleh101@gmail.com].
