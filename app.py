"""
app.py — AI-Based Phishing Detection System
Main Streamlit application entry point.

Run with:  streamlit run app.py
"""

import os
import json
import streamlit as st
from dotenv import load_dotenv

from prompt import SYSTEM_PROMPT, build_analysis_prompt
from utils import (
    validate_url,
    analyze_with_claude,
    analyze_with_openai,
    analyze_with_gemini,
    validate_result,
    get_risk_config,
    get_reason_icon,
    add_to_history,
    generate_pdf_report,
)

# ── Load .env (optional — users can also paste key in sidebar) ──
load_dotenv()

# ────────────────────────────────────────────
#  Page config  (must be first Streamlit call)
# ────────────────────────────────────────────
st.set_page_config(
    page_title="AI Phishing Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ────────────────────────────────────────────
#  Global CSS
# ────────────────────────────────────────────
st.markdown("""
<style>
/* ── Base ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;900&family=JetBrains+Mono:wght@400;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: #050d1a;
    color: #e2e8f0;
}

/* ── Hide default Streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding-top: 2rem; max-width: 1100px; }

/* ── Animated grid background ── */
.stApp::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background-image:
        linear-gradient(rgba(30,64,175,0.06) 1px, transparent 1px),
        linear-gradient(90deg, rgba(30,64,175,0.06) 1px, transparent 1px);
    background-size: 40px 40px;
    z-index: 0;
    pointer-events: none;
}

/* ── Hero header ── */
.hero {
    text-align: center;
    padding: 2.5rem 1rem 2rem;
    position: relative;
    z-index: 1;
}

.hero-badge {
    display: inline-block;
    background: rgba(30,64,175,0.25);
    border: 1px solid rgba(96,165,250,0.4);
    color: #60a5fa;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    padding: 0.35rem 1rem;
    border-radius: 100px;
    margin-bottom: 1.2rem;
}

.hero-title {
    font-size: clamp(2rem, 5vw, 3.2rem);
    font-weight: 900;
    line-height: 1.1;
    margin: 0 0 0.8rem;
    background: linear-gradient(135deg, #e2e8f0 0%, #60a5fa 50%, #818cf8 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.hero-sub {
    color: #94a3b8;
    font-size: 1.05rem;
    max-width: 560px;
    margin: 0 auto;
    line-height: 1.6;
}

/* ── Cards ── */
.card {
    background: rgba(15,23,42,0.85);
    border: 1px solid rgba(51,65,85,0.8);
    border-radius: 16px;
    padding: 1.6rem;
    margin-bottom: 1rem;
    backdrop-filter: blur(8px);
    position: relative;
    z-index: 1;
}

.card-title {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: #64748b;
    margin: 0 0 0.8rem;
}

/* ── Risk banner ── */
.risk-banner {
    border-radius: 16px;
    padding: 1.8rem 2rem;
    display: flex;
    align-items: center;
    gap: 1.5rem;
    margin-bottom: 1.2rem;
    position: relative;
    overflow: hidden;
    z-index: 1;
}

.risk-icon {
    font-size: 3rem;
    line-height: 1;
    flex-shrink: 0;
}

.risk-label {
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    opacity: 0.75;
}

.risk-title {
    font-size: 2rem;
    font-weight: 900;
    line-height: 1.1;
    margin: 0.2rem 0;
}

.risk-summary {
    font-size: 0.95rem;
    opacity: 0.85;
    line-height: 1.5;
    margin: 0;
}

/* ── Confidence meter ── */
.conf-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.conf-label { font-size: 0.8rem; color: #94a3b8; font-weight: 500; }
.conf-value { font-size: 1.2rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; }

.meter-track {
    height: 10px;
    background: rgba(51,65,85,0.6);
    border-radius: 100px;
    overflow: hidden;
}

.meter-fill {
    height: 100%;
    border-radius: 100px;
    transition: width 0.8s cubic-bezier(.4,0,.2,1);
}

/* ── Reason chips ── */
.reason-chip {
    display: flex;
    align-items: flex-start;
    gap: 0.7rem;
    padding: 0.85rem 1.1rem;
    background: rgba(15,23,42,0.6);
    border: 1px solid rgba(51,65,85,0.5);
    border-radius: 10px;
    margin-bottom: 0.5rem;
    font-size: 0.9rem;
    line-height: 1.5;
    color: #cbd5e1;
}

.reason-icon { font-size: 1rem; flex-shrink: 0; margin-top: 1px; }
.reason-text { flex: 1; }

/* ── Recommendation box ── */
.rec-box {
    background: rgba(30,64,175,0.12);
    border: 1px solid rgba(96,165,250,0.25);
    border-left: 4px solid #60a5fa;
    border-radius: 0 12px 12px 0;
    padding: 1rem 1.2rem;
    color: #bfdbfe;
    font-size: 0.95rem;
    line-height: 1.6;
}

/* ── Sample buttons ── */
.stButton > button {
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.85rem !important;
    transition: all 0.15s ease !important;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #080f1e !important;
    border-right: 1px solid rgba(51,65,85,0.6) !important;
}

section[data-testid="stSidebar"] .stMarkdown { color: #94a3b8; }

/* ── History row ── */
.hist-row {
    display: flex;
    align-items: center;
    gap: 0.8rem;
    padding: 0.75rem 1rem;
    background: rgba(15,23,42,0.7);
    border: 1px solid rgba(51,65,85,0.4);
    border-radius: 10px;
    margin-bottom: 0.5rem;
    font-size: 0.83rem;
    color: #94a3b8;
}

.hist-badge {
    font-size: 0.7rem;
    font-weight: 700;
    padding: 0.2rem 0.55rem;
    border-radius: 100px;
    white-space: nowrap;
}

/* ── Tip cards ── */
.tip-card {
    background: rgba(15,23,42,0.7);
    border: 1px solid rgba(51,65,85,0.4);
    border-radius: 12px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.7rem;
    display: flex;
    gap: 0.8rem;
    align-items: flex-start;
    font-size: 0.88rem;
    color: #cbd5e1;
    line-height: 1.5;
}

.tip-icon { font-size: 1.2rem; flex-shrink: 0; }

/* ── Scan input area ── */
.stTextArea > div > div > textarea {
    background: rgba(15,23,42,0.9) !important;
    border: 1px solid rgba(51,65,85,0.8) !important;
    border-radius: 12px !important;
    color: #e2e8f0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.9rem !important;
}

.stTextArea > div > div > textarea:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 3px rgba(59,130,246,0.15) !important;
}

.stSelectbox > div > div {
    background: rgba(15,23,42,0.9) !important;
    border: 1px solid rgba(51,65,85,0.8) !important;
    color: #e2e8f0 !important;
    border-radius: 10px !important;
}

/* ── Primary analyze button ── */
div[data-testid="stButton"] > button[kind="primary"] {
    background: linear-gradient(135deg, #1e40af 0%, #3b82f6 100%) !important;
    border: none !important;
    color: white !important;
    padding: 0.7rem 2.5rem !important;
    font-size: 1rem !important;
    font-weight: 700 !important;
    border-radius: 10px !important;
    letter-spacing: 0.03em !important;
    box-shadow: 0 4px 20px rgba(59,130,246,0.3) !important;
}

div[data-testid="stButton"] > button[kind="primary"]:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 28px rgba(59,130,246,0.45) !important;
}
</style>
""", unsafe_allow_html=True)


# ────────────────────────────────────────────
#  Session state initialisation
# ────────────────────────────────────────────
if "history" not in st.session_state:
    st.session_state.history = []
if "last_result" not in st.session_state:
    st.session_state.last_result = None
if "last_input" not in st.session_state:
    st.session_state.last_input = ""
if "last_type" not in st.session_state:
    st.session_state.last_type = "URL"
if "input_text" not in st.session_state:
    st.session_state.input_text = ""


# ────────────────────────────────────────────
#  Sidebar
# ────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 0.5rem 0 1.5rem;">
        <div style="font-size:2.5rem;">🛡️</div>
        <div style="font-size:1.1rem; font-weight:800; color:#e2e8f0;">PhishGuard AI</div>
        <div style="font-size:0.75rem; color:#64748b; margin-top:0.25rem;">Powered by AI</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("#### ⚙️ AI Provider")
    ai_provider = st.selectbox(
        "Select AI Provider",
        ["Claude (Anthropic)", "OpenAI GPT-4o", "Google Gemini"],
        label_visibility="collapsed",
    )

    st.markdown("#### 🔑 API Key")
    env_key_map = {
        "Claude (Anthropic)": "ANTHROPIC_API_KEY",
        "OpenAI GPT-4o": "OPENAI_API_KEY",
        "Google Gemini": "GEMINI_API_KEY",
    }
    env_key = os.getenv(env_key_map[ai_provider], "")
    api_key_input = st.text_input(
        "API Key",
        value=env_key,
        type="password",
        placeholder="Paste your API key here…",
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("""
    <div style="color:#64748b; font-size:0.82rem; line-height:1.7;">
        <div style="color:#94a3b8; font-weight:700; margin-bottom:0.5rem;">✨ Features</div>
        ✅ URL phishing detection<br>
        ✅ Email analysis<br>
        ✅ SMS scam detection<br>
        ✅ AI explanation<br>
        ✅ Confidence scoring<br>
        ✅ PDF report export<br>
        ✅ Analysis history<br>
        ✅ Cyber safety tips
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style="color:#64748b; font-size:0.8rem; line-height:1.7;">
        <div style="color:#94a3b8; font-weight:700; margin-bottom:0.5rem;">ℹ️ About</div>
        This application uses Large Language Models to analyze suspicious content 
        and explain phishing indicators in plain English — built for educational 
        and awareness purposes.
    </div>
    """, unsafe_allow_html=True)


# ────────────────────────────────────────────
#  Hero
# ────────────────────────────────────────────
st.markdown("""
<div class="hero">
    <div class="hero-badge">🔐 AI-Powered Cyber Defense</div>
    <h1 class="hero-title">AI-Based Phishing Detection System</h1>
    <p class="hero-sub">
        Protect yourself against phishing emails, fake websites, and scam SMS 
        using Artificial Intelligence — get instant, plain-English explanations.
    </p>
</div>
""", unsafe_allow_html=True)


# ────────────────────────────────────────────
#  Stats bar
# ────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
stats = [
    ("🌐", "URL Detection", "Real-time"),
    ("📧", "Email Analysis", "Deep scan"),
    ("📱", "SMS Scanning", "Scam alerts"),
    ("🤖", "AI Explainer", "Plain English"),
]
for col, (icon, label, val) in zip([c1, c2, c3, c4], stats):
    col.markdown(f"""
    <div class="card" style="text-align:center; padding:1.1rem;">
        <div style="font-size:1.6rem;">{icon}</div>
        <div style="font-weight:700; font-size:0.9rem; color:#e2e8f0; margin:0.3rem 0 0.1rem;">{label}</div>
        <div style="font-size:0.75rem; color:#64748b;">{val}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)


# ────────────────────────────────────────────
#  Main input section
# ────────────────────────────────────────────
col_main, col_side = st.columns([3, 2], gap="large")

with col_main:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">🔍 Scan Input</div>', unsafe_allow_html=True)

    input_type = st.selectbox(
        "Input Type",
        ["URL", "Email", "SMS Message"],
        index=["URL", "Email", "SMS Message"].index(st.session_state.last_type),
        label_visibility="collapsed",
    )
    st.session_state.last_type = input_type

    placeholder_map = {
        "URL": "https://paypa1-login-security.xyz/account/verify",
        "Email": "Subject: URGENT — Account Suspended\n\nDear Customer,\nYour account has been locked due to suspicious activity. Click below to verify immediately:\nhttp://amaz0n-security.xyz",
        "SMS Message": "Your SBI account has been blocked. Verify now at https://sbibank-security.xyz or your account will be permanently closed.",
    }

    user_input = st.text_area(
        "Content to analyze",
        value=st.session_state.input_text,
        height=160,
        placeholder=placeholder_map[input_type],
        label_visibility="collapsed",
    )

    # ── Sample buttons ──
    st.markdown('<div style="margin-top:0.5rem;">', unsafe_allow_html=True)
    sb1, sb2, sb3, sb4 = st.columns(4)

    examples = {
        "✅ Safe URL": ("URL", "https://www.google.com"),
        "🚨 Phishing URL": ("URL", "http://paypa1-login-security.xyz/account/verify"),
        "📧 Scam Email": ("Email", "URGENT! Your Amazon account has been suspended.\n\nDear Customer,\nWe detected suspicious activity on your account. You must verify your identity immediately or your account will be permanently closed.\n\nClick here: http://amaz0n-accounts-verify.xyz\n\nAmazon Security Team"),
        "📱 Scam SMS": ("SMS Message", "Your SBI Bank account is BLOCKED! Verify now: https://sbi-secure-login.xyz/verify or lose access permanently. OTP: 847293"),
    }

    for col_btn, (label, (ex_type, ex_val)) in zip([sb1, sb2, sb3, sb4], examples.items()):
        if col_btn.button(label, use_container_width=True):
            st.session_state.input_text = ex_val
            st.session_state.last_type = ex_type
            st.rerun()

    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Analyze button ──
    analyze_clicked = st.button(
        "🔍  Analyze with AI",
        type="primary",
        use_container_width=True,
    )

    st.markdown('</div>', unsafe_allow_html=True)  # close .card


with col_side:
    # ── Cyber Safety Tips ──
    st.markdown("""
    <div class="card">
        <div class="card-title">🛡️ Cyber Safety Tips</div>
    """, unsafe_allow_html=True)

    tips = [
        ("🔍", "Always check the URL domain before entering credentials."),
        ("🔒", "Look for HTTPS and a padlock icon in your browser."),
        ("⚡", "Be wary of messages creating extreme urgency or fear."),
        ("🏦", "Banks never ask for OTPs or passwords via SMS or email."),
        ("🔗", "Hover over links to preview the destination URL first."),
        ("📞", "Call the company directly using their official number to verify."),
    ]
    for icon, tip in tips:
        st.markdown(f'<div class="tip-card"><span class="tip-icon">{icon}</span><span>{tip}</span></div>', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


# ────────────────────────────────────────────
#  Analysis logic
# ────────────────────────────────────────────
if analyze_clicked:
    raw_input = user_input.strip()

    # ── Validation ──
    if not raw_input:
        st.error("⚠️ Please enter some content to analyze.")
        st.stop()

    if not api_key_input.strip():
        st.error("🔑 Please enter your API key in the sidebar to continue.")
        st.stop()

    if input_type == "URL":
        is_valid, msg = validate_url(raw_input)
        if not is_valid:
            st.error(f"❌ Invalid URL: {msg}")
            st.stop()

    # ── Call AI ──
    with st.spinner("🤖 Analyzing using AI…  This takes a few seconds."):
        try:
            system_p = SYSTEM_PROMPT
            user_p = build_analysis_prompt(input_type, raw_input)

            if ai_provider == "Claude (Anthropic)":
                result = analyze_with_claude(system_p, user_p, api_key_input.strip())
            elif ai_provider == "OpenAI GPT-4o":
                result = analyze_with_openai(system_p, user_p, api_key_input.strip())
            else:
                result = analyze_with_gemini(system_p, user_p, api_key_input.strip())

            result = validate_result(result)
            st.session_state.last_result = result
            st.session_state.last_input = raw_input
            st.session_state.last_type = input_type
            add_to_history(st.session_state, input_type, raw_input, result)

        except json.JSONDecodeError:
            st.error("❌ The AI returned an unexpected format. Please try again.")
            st.stop()
        except ValueError as e:
            st.error(f"❌ API Error: {e}")
            st.stop()
        except requests.exceptions.ConnectionError:
            st.error("❌ Network error: Could not reach the AI service. Check your internet connection.")
            st.stop()
        except requests.exceptions.Timeout:
            st.error("❌ Request timed out. The AI service is slow — please try again.")
            st.stop()
        except Exception as e:
            st.error(f"❌ Unexpected error: {e}")
            st.stop()


# ────────────────────────────────────────────
#  Results display
# ────────────────────────────────────────────
if st.session_state.last_result:
    result = st.session_state.last_result
    risk = result.get("risk", "Suspicious")
    cfg = get_risk_config(risk)
    confidence = result.get("confidence", 0)

    st.markdown("---")
    st.markdown("## 📊 Analysis Results")

    # ── Risk banner ──
    st.markdown(f"""
    <div class="risk-banner" style="background:{cfg['bg']}; border:2px solid {cfg['border']}40; border-left:5px solid {cfg['border']};">
        <div class="risk-icon">{cfg['icon']}</div>
        <div style="flex:1;">
            <div class="risk-label" style="color:{cfg['color']};">Risk Assessment</div>
            <div class="risk-title" style="color:{cfg['color']};">{risk}</div>
            <p class="risk-summary">{result.get('summary', '')}</p>
        </div>
        <div style="text-align:right; flex-shrink:0;">
            <div style="font-size:0.7rem; color:#64748b; text-transform:uppercase; letter-spacing:0.1em; margin-bottom:0.3rem;">Confidence</div>
            <div style="font-size:2.5rem; font-weight:900; font-family:'JetBrains Mono',monospace; color:{cfg['color']};">{confidence}%</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Threat meter ──
    st.markdown(f"""
    <div class="card">
        <div class="conf-row">
            <span class="conf-label">🎯 Threat Confidence Meter</span>
            <span class="conf-value" style="color:{cfg['color']};">{confidence}%</span>
        </div>
        <div class="meter-track">
            <div class="meter-fill" style="width:{confidence}%; background:linear-gradient(90deg, {cfg['color']}88, {cfg['color']});"></div>
        </div>
        <div style="display:flex; justify-content:space-between; margin-top:0.4rem; font-size:0.7rem; color:#475569;">
            <span>Low Risk</span><span>Medium</span><span>High Risk</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Two columns: reasons + recommendation ──
    rc1, rc2 = st.columns([3, 2], gap="large")

    with rc1:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">🔎 Detection Reasons</div>', unsafe_allow_html=True)
        for reason in result.get("reasons", []):
            icon = get_reason_icon(reason)
            st.markdown(f"""
            <div class="reason-chip">
                <span class="reason-icon">{icon}</span>
                <span class="reason-text">{reason}</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with rc2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">💡 Recommendation</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="rec-box">{result.get("recommendation", "")}</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Copy JSON ──
        result_json = json.dumps(result, indent=2)
        st.download_button(
            "📋 Copy Raw JSON",
            data=result_json,
            file_name="phishing_analysis.json",
            mime="application/json",
            use_container_width=True,
        )

        # ── PDF Download ──
        pdf_bytes = generate_pdf_report(
            st.session_state.last_type,
            st.session_state.last_input,
            result,
        )
        if pdf_bytes:
            st.download_button(
                "📄 Download PDF Report",
                data=pdf_bytes,
                file_name="phishing_report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        else:
            st.caption("Install `reportlab` to enable PDF export.")

        st.markdown('</div>', unsafe_allow_html=True)


# ────────────────────────────────────────────
#  Analysis History
# ────────────────────────────────────────────
if st.session_state.history:
    st.markdown("---")
    st.markdown("## 🕐 Analysis History")

    risk_badge_styles = {
        "Safe": "background:#0d2b1a; color:#00d084; border:1px solid #00d08440;",
        "Suspicious": "background:#2b1f06; color:#fbbf24; border:1px solid #fbbf2440;",
        "Phishing": "background:#2b0707; color:#ef4444; border:1px solid #ef444440;",
    }

    for entry in st.session_state.history:
        badge_style = risk_badge_styles.get(entry["risk"], "")
        st.markdown(f"""
        <div class="hist-row">
            <span style="color:#475569; font-family:'JetBrains Mono',monospace; font-size:0.75rem;">{entry['timestamp']}</span>
            <span style="background:rgba(30,64,175,0.2); color:#60a5fa; padding:0.15rem 0.5rem; border-radius:6px; font-size:0.72rem; font-weight:600;">{entry['input_type']}</span>
            <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">{entry['preview']}</span>
            <span class="hist-badge" style="{badge_style}">{entry['risk']}</span>
            <span style="font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:#64748b;">{entry['confidence']}%</span>
        </div>
        """, unsafe_allow_html=True)

    if st.button("🗑️ Clear History", type="secondary"):
        st.session_state.history = []
        st.rerun()
