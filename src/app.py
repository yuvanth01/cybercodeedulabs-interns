"""
app.py

Command Line version of the AI Incident Report Generator.
Useful for testing without Streamlit.
"""

import os

from parser import load_incident, validate_incident
from ai_generator import generate_ai_report
from report_writer import save_report
from pdf_generator import create_pdf


def main():

    print("=" * 60)
    print("AI INCIDENT REPORT GENERATOR")
    print("=" * 60)

    # Project root directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Sample JSON path
    json_path = os.path.join(
        base_dir,
        "data",
        "sample_incident.json"
    )

    # Check if JSON exists
    if not os.path.exists(json_path):
        print("Error: sample_incident.json not found.")
        return

    # Load Incident
    print("\nLoading Incident JSON...")

    incident = load_incident(json_path)

    # Validate
    try:
        validate_incident(incident)
        print("Incident JSON is valid.")
    except Exception as e:
        print(f"Validation Error: {e}")
        return

    print("\nGenerating AI Report...\n")

    # Generate Report
    report = generate_ai_report(incident)

    print(report)

    # Save TXT
    txt_path = save_report(report)

    # Save PDF
    pdf_path = create_pdf(report)

    print("\n" + "=" * 60)
    print("REPORT GENERATED SUCCESSFULLY")
    print("=" * 60)

    print(f"\nTXT Report : {txt_path}")
    print(f"PDF Report : {pdf_path}")

    print("\nDone.")


if __name__ == "__main__":
    main()