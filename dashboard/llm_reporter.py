import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def generate_report(threat_type, anomaly_score, e8_control, risk_level, top_features):
    prompt = f"""You are a cybersecurity analyst. Write a 3-4 sentence plain English report for the following threat alert.

Threat Type: {threat_type}
Anomaly Score: {anomaly_score:.2f}
Essential Eight Control Violated: {e8_control}
Risk Level: {risk_level}
Top Indicators: {', '.join(top_features)}

Write clearly for a non-technical manager. Be direct and specific."""

    response = client.chat.completions.create(
        model="llama-3.1-8b-instant",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=300
    )

    return response.choices[0].message.content

if __name__ == "__main__":
    report = generate_report(
        threat_type="Brute Force",
        anomaly_score=0.89,
        e8_control="#7 — Multi-Factor Authentication",
        risk_level="High",
        top_features=["failed_login_ratio", "sttl", "ct_state_ttl"]
    )
    print(report)