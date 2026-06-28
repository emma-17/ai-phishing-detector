# 🛡️ AI-Based Phishing Detection System

> Detect phishing URLs, scam emails, and SMS attacks in real time using AI — with plain-English explanations.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.35+-red)
![AI](https://img.shields.io/badge/AI-Claude%20%7C%20GPT--4o%20%7C%20Gemini-purple)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 Project Description

People fall victim to phishing attacks every day through fake emails, malicious URLs, and scam SMS messages. This application leverages state-of-the-art Large Language Models (LLMs) to analyze user-submitted content and determine whether it is **Safe**, **Suspicious**, or **Phishing** — and explains *why* in beginner-friendly language.

Built for college innovation competitions, hackathons, and cybersecurity awareness demonstrations.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 URL Detection | Analyzes domain names, paths, HTTPS usage, and brand spoofing |
| 📧 Email Analysis | Detects urgency tactics, impersonation, and suspicious links |
| 📱 SMS Scanning | Identifies OTP harvesting, fake bank alerts, and phishing links |
| 🤖 AI Explanation | Plain-English breakdown of exactly why content is dangerous |
| 📊 Confidence Score | Percentage confidence with an animated threat meter |
| 📄 PDF Report | Downloadable analysis report for documentation |
| 🕐 History | Session-level analysis history with timestamps |
| 🛡️ Safety Tips | Built-in cybersecurity education panel |
| 🌗 Dark Theme | Professional cybersecurity-styled UI |

---

## 🏗️ Project Structure

```
phishing_detector/
├── app.py              # Main Streamlit application
├── utils.py            # AI API calls, validation, PDF generation
├── prompts.py          # LLM system prompt and user prompt builder
├── requirements.txt    # Python dependencies
├── .env.example        # Environment variable template
└── README.md           # This file
```

---

## 🚀 Installation & Setup

### 1. Clone / Download the project

```bash
git clone https://github.com/your-username/phishing-detector.git
cd phishing-detector
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔑 Obtaining an API Key

The app supports **three AI providers**. You only need one.

### Option A — Anthropic Claude (Recommended)
1. Go to [https://console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
2. Sign up or log in
3. Click **Create Key** and copy the key (starts with `sk-ant-…`)

### Option B — OpenAI GPT-4o
1. Go to [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
2. Sign in and click **Create new secret key**
3. Copy the key (starts with `sk-…`)
4. Ensure your account has GPT-4o access

### Option C — Google Gemini (Free tier available)
1. Go to [https://aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
2. Sign in with your Google account
3. Click **Create API Key**
4. Copy the key

---

## ⚙️ Environment Variable Setup

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your chosen key
nano .env     # or use any text editor
```

Your `.env` file should look like:
```env
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxxxxxx
```

> **Tip:** You can also paste the API key directly in the sidebar of the running app — no `.env` required.

---

## ▶️ Running the Application

```bash
streamlit run app.py
```

The app will open automatically at `http://localhost:8501`

---

## 🧪 Sample Test Cases

### ✅ Safe URL
```
https://www.google.com
```

### 🚨 Phishing URL
```
http://paypa1-login-security.xyz/account/verify
```

### 📧 Phishing Email
```
Subject: URGENT — Your Amazon Account Has Been Suspended

Dear Customer,
We detected suspicious activity on your account. Click below immediately to verify or your account will be permanently deleted.

http://amaz0n-accounts-secure.xyz

Amazon Security Team
```

### 📱 SMS Scam
```
Your SBI account is BLOCKED! Verify now at https://sbi-secure-login.xyz/verify or lose access permanently.
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `requests` | HTTP calls to AI APIs |
| `validators` | URL format validation |
| `python-dotenv` | Load `.env` file |
| `reportlab` | PDF report generation |

---

## 🏆 Competition Notes

- Fully functional with real AI APIs (no mock data)
- Professional dark cybersecurity UI
- Supports multiple AI providers (easy to switch)
- Beginner-friendly output language
- Extensible architecture (modular files)

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👨‍💻 Author

Built for the College Innovation Competition.  
Powered by Anthropic Claude / OpenAI GPT-4o / Google Gemini.
