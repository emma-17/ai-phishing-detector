"""
utils.py — Utility functions for the Phishing Detection System.
Handles API calls, URL validation, PDF generation, and result formatting.
"""

import json
import re
import os
import datetime
from typing import Optional

import requests
import validators


# ─────────────────────────────────────────────
#  URL Validation
# ─────────────────────────────────────────────

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate a URL string.

    Returns:
        (is_valid: bool, message: str)
    """
    url = url.strip()
    if not url:
        return False, "URL cannot be empty."

    # Add scheme if missing so validators can parse it
    if not url.startswith(("http://", "https://")):
        test_url = "https://" + url
    else:
        test_url = url

    if validators.url(test_url):
        return True, "Valid URL"
    return False, f"'{url}' does not appear to be a valid URL. Please check the format."


# ─────────────────────────────────────────────
#  AI Analysis via Claude API (Anthropic)
# ─────────────────────────────────────────────

def analyze_with_claude(system_prompt: str, user_prompt: str, api_key: str) -> dict:
    """
    Call the Anthropic Claude API to analyze phishing content.

    Args:
        system_prompt: The cybersecurity analyst system context
        user_prompt: The formatted analysis prompt with user input
        api_key: Anthropic API key

    Returns:
        Parsed JSON dict with risk, confidence, summary, reasons, recommendation
    """
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
    }

    payload = {
        "model": "claude-opus-4-6",
        "max_tokens": 1024,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_prompt}],
    }

    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        json=payload,
        timeout=30,
    )

    if response.status_code != 200:
        raise ValueError(
            f"API Error {response.status_code}: {response.json().get('error', {}).get('message', 'Unknown error')}"
        )

    data = response.json()
    raw_text = data["content"][0]["text"].strip()

    # Strip markdown fences if model wrapped in them
    raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
    raw_text = re.sub(r"\s*```$", "", raw_text)

    return json.loads(raw_text)


def analyze_with_openai(system_prompt: str, user_prompt: str, api_key: str) -> dict:
    """
    Call OpenAI GPT-4o to analyze phishing content.

    Args:
        system_prompt: The cybersecurity analyst system context
        user_prompt: The formatted analysis prompt with user input
        api_key: OpenAI API key

    Returns:
        Parsed JSON dict with risk, confidence, summary, reasons, recommendation
    """
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    payload = {
        "model": "gpt-4o",
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 1024,
    }

    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=30,
    )

    if response.status_code != 200:
        raise ValueError(
            f"API Error {response.status_code}: {response.json().get('error', {}).get('message', 'Unknown error')}"
        )

    data = response.json()
    raw_text = data["choices"][0]["message"]["content"].strip()
    return json.loads(raw_text)


def analyze_with_gemini(system_prompt: str, user_prompt: str, api_key: str) -> dict:
    """
    Call Google Gemini API to analyze phishing content.

    Args:
        system_prompt: The cybersecurity analyst system context
        user_prompt: The formatted analysis prompt with user input
        api_key: Google Gemini API key

    Returns:
        Parsed JSON dict with risk, confidence, summary, reasons, recommendation
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"

    full_prompt = f"{system_prompt}\n\n{user_prompt}"

    payload = {
        "contents": [{"parts": [{"text": full_prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 1024,
            "responseMimeType": "application/json",
        },
    }

    response = requests.post(url, json=payload, timeout=30)

    if response.status_code != 200:
        raise ValueError(
            f"Gemini API Error {response.status_code}: {response.text[:200]}"
        )

    data = response.json()
    raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()

    raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
    raw_text = re.sub(r"\s*```$", "", raw_text)

    return json.loads(raw_text)


# ─────────────────────────────────────────────
#  Result Validation
# ─────────────────────────────────────────────

def validate_result(result: dict) -> dict:
    """
    Ensure the AI response contains all required fields and sane values.
    Applies defaults for missing or malformed fields.
    """
    valid_risks = {"Safe", "Suspicious", "Phishing"}

    if result.get("risk") not in valid_risks:
        result["risk"] = "Suspicious"

    confidence = result.get("confidence", 50)
    try:
        result["confidence"] = max(0, min(100, int(confidence)))
    except (ValueError, TypeError):
        result["confidence"] = 50

    if not result.get("summary"):
        result["summary"] = "Analysis complete. Review the reasons below."

    if not isinstance(result.get("reasons"), list) or not result["reasons"]:
        result["reasons"] = ["No specific indicators were identified."]

    if not result.get("recommendation"):
        result["recommendation"] = "Exercise caution and verify before proceeding."

    return result


# ─────────────────────────────────────────────
#  Risk Styling Helpers
# ─────────────────────────────────────────────

RISK_CONFIG = {
    "Safe": {
        "color": "#00d084",
        "bg": "#0d2b1a",
        "border": "#00d084",
        "icon": "🛡️",
        "badge": "✅ SAFE",
        "text_color": "#00d084",
    },
    "Suspicious": {
        "color": "#fbbf24",
        "bg": "#2b1f06",
        "border": "#fbbf24",
        "icon": "⚠️",
        "badge": "⚠️ SUSPICIOUS",
        "text_color": "#fbbf24",
    },
    "Phishing": {
        "color": "#ef4444",
        "bg": "#2b0707",
        "border": "#ef4444",
        "icon": "🚨",
        "badge": "🚨 PHISHING",
        "text_color": "#ef4444",
    },
}


def get_risk_config(risk: str) -> dict:
    return RISK_CONFIG.get(risk, RISK_CONFIG["Suspicious"])


def get_reason_icon(reason: str) -> str:
    """Return an appropriate icon based on reason content."""
    reason_lower = reason.lower()
    if any(w in reason_lower for w in ["safe", "legitimate", "trusted", "valid", "https", "secure"]):
        return "✅"
    elif any(w in reason_lower for w in ["urgent", "immediate", "warning", "suspicious", "unusual"]):
        return "⚠️"
    elif any(w in reason_lower for w in ["fake", "phish", "malicious", "scam", "fraud", "spoof", "danger"]):
        return "🚨"
    else:
        return "🔍"


# ─────────────────────────────────────────────
#  Analysis History (session-level)
# ─────────────────────────────────────────────

def add_to_history(session_state, input_type: str, user_input: str, result: dict):
    """Append an analysis entry to the session history list."""
    if "history" not in session_state:
        session_state.history = []

    entry = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "input_type": input_type,
        "preview": user_input[:60] + ("..." if len(user_input) > 60 else ""),
        "risk": result.get("risk", "Unknown"),
        "confidence": result.get("confidence", 0),
        "summary": result.get("summary", ""),
        "reasons": result.get("reasons", []),
        "recommendation": result.get("recommendation", ""),
    }
    session_state.history.insert(0, entry)

    # Keep only last 10 entries
    session_state.history = session_state.history[:10]


# ─────────────────────────────────────────────
#  PDF Report Generation
# ─────────────────────────────────────────────

def generate_pdf_report(input_type: str, user_input: str, result: dict) -> Optional[bytes]:
    """
    Generate a PDF analysis report using only stdlib + reportlab.

    Returns:
        PDF bytes or None if reportlab is unavailable
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle("title", parent=styles["Title"],
                                     fontSize=20, spaceAfter=6,
                                     textColor=colors.HexColor("#1e40af"))
        story.append(Paragraph("AI-Based Phishing Detection Report", title_style))
        story.append(Paragraph(
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        ))
        story.append(Spacer(1, 0.4*cm))

        # Risk level
        risk = result.get("risk", "Unknown")
        risk_colors = {"Safe": "#16a34a", "Suspicious": "#d97706", "Phishing": "#dc2626"}
        risk_color = colors.HexColor(risk_colors.get(risk, "#6b7280"))

        risk_style = ParagraphStyle("risk", parent=styles["Heading1"],
                                    fontSize=16, textColor=risk_color)
        story.append(Paragraph(f"Risk Level: {risk}", risk_style))
        story.append(Paragraph(
            f"Confidence: {result.get('confidence', 0)}%", styles["Normal"]
        ))
        story.append(Spacer(1, 0.3*cm))

        # Input info
        story.append(Paragraph("Analyzed Content", styles["Heading2"]))
        story.append(Paragraph(f"<b>Type:</b> {input_type}", styles["Normal"]))
        preview = user_input[:300] + ("..." if len(user_input) > 300 else "")
        story.append(Paragraph(f"<b>Content:</b> {preview}", styles["Normal"]))
        story.append(Spacer(1, 0.3*cm))

        # Summary
        story.append(Paragraph("Summary", styles["Heading2"]))
        story.append(Paragraph(result.get("summary", ""), styles["Normal"]))
        story.append(Spacer(1, 0.3*cm))

        # Reasons
        story.append(Paragraph("Detection Reasons", styles["Heading2"]))
        for r in result.get("reasons", []):
            story.append(Paragraph(f"• {r}", styles["Normal"]))
        story.append(Spacer(1, 0.3*cm))

        # Recommendation
        story.append(Paragraph("Recommendation", styles["Heading2"]))
        story.append(Paragraph(result.get("recommendation", ""), styles["Normal"]))

        doc.build(story)
        return buffer.getvalue()

    except ImportError:
        return None
