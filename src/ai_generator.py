"""
ai_generator.py

Generates professional cybersecurity incident reports
using Google's Gemini AI.
"""

import os
import time

from dotenv import load_dotenv
from google import genai

# ---------------- LOAD ENV ---------------- #

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError("GEMINI_API_KEY not found in .env")

# ---------------- CREATE CLIENT ---------------- #

client = genai.Client(api_key=API_KEY)

# ---------------- MODELS ---------------- #

MODELS = [

    "gemini-3.5-flash",

    "gemini-3.1-flash-lite",

    "gemini-2.0-flash"

]

# ---------------- PROMPT ---------------- #

def build_prompt(incident):

    return f"""
You are a Senior SOC Analyst.

Generate a professional Cybersecurity Incident Report.

Incident Details

Incident ID:
{incident["incident_id"]}

Title:
{incident["title"]}

Severity:
{incident["severity"]}

Timestamp:
{incident["timestamp"]}

Source IP:
{incident["source_ip"]}

Destination IP:
{incident["destination_ip"]}

Affected Host:
{incident["affected_host"]}

Attack Type:
{incident["attack_type"]}

Status:
{incident["status"]}

Evidence:
{incident["evidence"]}

Generate a professional report with the following sections.

1. Executive Summary

2. Incident Timeline

3. Root Cause Analysis

4. Evidence Collected

5. Business Impact

6. MITRE ATT&CK Mapping

7. Recommendations

8. Conclusion

Write the report professionally.

Use headings.

Do not use markdown tables.

Keep the report detailed but easy to understand.
"""


# ---------------- GENERATE REPORT ---------------- #

def generate_ai_report(incident):

    prompt = build_prompt(incident)

    last_error = None

    for model in MODELS:

        for attempt in range(3):

            try:

                print(f"Trying {model} (Attempt {attempt+1}/3)...")

                response = client.models.generate_content(

                    model=model,

                    contents=prompt

                )

                if response.text:

                    return response.text

            except Exception as e:

                last_error = str(e)

                print(last_error)

                time.sleep(2)

                continue

    return f"""
Unable to generate AI report.

Reason:

{last_error}

Possible Causes

• Gemini API quota exceeded

• Temporary server issue

• Internet connection problem

• Invalid API Key

Please try again later.
"""