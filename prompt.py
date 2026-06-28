"""
prompts.py — AI prompt templates for the Phishing Detection System.
Each function returns a formatted prompt string ready to send to the LLM.
"""

SYSTEM_PROMPT = """You are an elite cybersecurity analyst with 15+ years of experience 
in phishing detection, threat intelligence, and digital forensics. You specialize in 
identifying social engineering attacks, malicious URLs, fraudulent emails, and SMS scams.

Your job is to analyze user-submitted content (URLs, emails, or SMS messages) and 
determine whether it is Safe, Suspicious, or Phishing.

CRITICAL: You must ALWAYS respond with ONLY a valid JSON object — no markdown, no 
code fences, no explanations outside the JSON. The JSON must follow this exact schema:

{
    "risk": "Safe" | "Suspicious" | "Phishing",
    "confidence": <integer 0-100>,
    "summary": "<one concise sentence describing the overall finding>",
    "reasons": [
        "<specific reason 1>",
        "<specific reason 2>",
        "<specific reason 3>",
        "<specific reason 4 if applicable>"
    ],
    "recommendation": "<clear, actionable advice for a non-technical user>"
}

ANALYSIS GUIDELINES:
- "Safe": Legitimate content, no red flags, trusted domain/source.
- "Suspicious": Contains some warning signs but not conclusively malicious.
- "Phishing": Strong indicators of malicious intent — spoofed brand, deceptive URL, 
  urgency tactics, credential harvesting, or known scam patterns.

Keep explanations beginner-friendly. Avoid jargon. Be direct and helpful.
"""


def build_analysis_prompt(input_type: str, user_input: str) -> str:
    """
    Build the user-facing prompt for phishing analysis.

    Args:
        input_type: One of 'URL', 'Email', or 'SMS Message'
        user_input: The raw text/URL submitted by the user

    Returns:
        A formatted prompt string
    """
    type_context = {
        "URL": (
            "a URL/web address submitted for safety analysis. "
            "Examine the domain name, TLD, path, subdomains, use of HTTPS, "
            "misspellings of known brands, suspicious keywords, and URL structure."
        ),
        "Email": (
            "an email message submitted for phishing analysis. "
            "Look for urgency language, spoofed sender addresses, suspicious links, "
            "requests for personal/financial information, grammar errors, and "
            "impersonation of trusted brands."
        ),
        "SMS Message": (
            "an SMS/text message submitted for scam analysis. "
            "Check for urgency tactics, suspicious URLs, requests to click links, "
            "impersonation of banks/government agencies, prize/lottery claims, and "
            "requests for OTPs or personal data."
        ),
    }

    context = type_context.get(input_type, "content submitted for security analysis.")

    prompt = f"""Analyze the following {input_type.lower()} for phishing indicators.

INPUT TYPE: {input_type}
CONTEXT: This is {context}

SUBMITTED CONTENT:
---
{user_input}
---

Provide your analysis as a JSON object only. No markdown, no extra text."""

    return prompt
