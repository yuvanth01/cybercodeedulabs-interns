"""
pdf_generator.py

Creates a professional PDF report from the AI-generated incident report.
"""

import os
from datetime import datetime

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)


OUTPUT_FOLDER = "output"


def create_pdf(report_text):
    """
    Creates a PDF report and returns its path.
    """

    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    pdf_path = os.path.join(
        OUTPUT_FOLDER,
        "incident_report.pdf"
    )

    doc = SimpleDocTemplate(pdf_path)

    styles = getSampleStyleSheet()

    story = []

    # ---------------- TITLE ---------------- #

    title = Paragraph(
        "<b><font size=20>AI Incident Report</font></b>",
        styles["Title"]
    )

    story.append(title)

    story.append(Spacer(1, 20))

    # ---------------- DATE ---------------- #

    date = Paragraph(
        f"<b>Generated:</b> {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}",
        styles["Normal"]
    )

    story.append(date)

    story.append(Spacer(1, 20))

    # ---------------- REPORT ---------------- #

    for line in report_text.split("\n"):

        if line.strip() == "":
            story.append(Spacer(1, 8))
            continue

        paragraph = Paragraph(
            line.replace("    ", "&nbsp;&nbsp;&nbsp;&nbsp;"),
            styles["BodyText"]
        )

        story.append(paragraph)

    # ---------------- FOOTER ---------------- #

    story.append(Spacer(1, 20))


    doc.build(story)

    return pdf_path