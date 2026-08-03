# AI Incident Report Generator

## Overview

The AI Incident Report Generator is a cybersecurity application that automatically generates professional incident reports from structured JSON data using Google's Gemini AI.

## Features

- Upload Incident JSON
- AI Generated Report
- MITRE ATT&CK Mapping
- Threat Score
- TXT Export
- PDF Export
- Streamlit Dashboard

## Technology Stack

- Python
- Streamlit
- Google Gemini API
- ReportLab
- JSON

## Project Structure

```
ai-incident-report/
│
├── streamlit_app.py
├── src/
├── data/
├── output/
├── screenshots/
├── tests/
├── requirements.txt
└── README.md
```

## Installation

```bash
pip install -r requirements.txt
```

## Run Streamlit

```bash
streamlit run streamlit_app.py
```

## Run Terminal Version

```bash
python src/app.py
```

## Sample Input

Use:

```
data/sample_incident.json
```

## Output

- AI Generated Report
- PDF Report
- TXT Report

## Developed By

Yuvanth
for
CyberCodeEduLabs Internship