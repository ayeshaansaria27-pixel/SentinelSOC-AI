
import os
import json
import re
import gradio as gr
from groq import Groq


# ==========================================
# CONFIGURATION
# ==========================================

MODEL = "openai/gpt-oss-120b"

# Get API key
try:
    from google.colab import userdata
    GROQ_API_KEY = userdata.get("GROQ_API_KEY")
except Exception:
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY")

if not GROQ_API_KEY:
    raise ValueError("GROQ_API_KEY was not found.")

client = Groq(api_key=GROQ_API_KEY)


# ==========================================
# AI FUNCTION
# ==========================================

def ask_ai(prompt):

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are SentinelSOC AI, a professional "
                    "cybersecurity SOC assistant."
                )
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.2
    )

    return response.choices[0].message.content


# ==========================================
# THREAT ANALYSIS AGENT
# ==========================================

def threat_analysis_agent(alert):

    prompt = f"""
Analyze this cybersecurity alert or suspicious activity.

Alert:
{alert}

Identify:
- Threat type
- Attack technique
- Indicators of compromise
- Evidence
- Confidence
- Possible impact

Return the result in JSON format.
"""

    return ask_ai(prompt)


# ==========================================
# RISK ASSESSMENT AGENT
# ==========================================

def risk_assessment_agent(threat_analysis):

    prompt = f"""
You are the Risk Assessment Agent.

Analyze this threat analysis:

{threat_analysis}

Determine:
- Risk level: Low, Medium, High, or Critical
- Risk score from 0 to 100
- Severity
- Urgency
- Reason for the risk level

Return the result in JSON format.
"""

    return ask_ai(prompt)


# ==========================================
# RESPONSE AGENT
# ==========================================

def response_agent(threat_analysis, risk_assessment):

    prompt = f"""
You are the Response Agent of SentinelSOC AI.

Threat Analysis:
{threat_analysis}

Risk Assessment:
{risk_assessment}

Provide:
- Immediate defensive actions
- Investigation steps
- Recommended response
- Prevention recommendations

Keep the response practical for a SOC analyst.

Return the result in JSON format.
"""

    return ask_ai(prompt)


# ==========================================
# SENTINELSOC WORKFLOW
# ==========================================

def sentinel_soc(alert):

    threat = threat_analysis_agent(alert)

    risk = risk_assessment_agent(threat)

    response = response_agent(
        threat,
        risk
    )

    return {
        "threat_analysis": threat,
        "risk_assessment": risk,
        "response": response
    }


# ==========================================
# JSON PARSER
# ==========================================

def parse_json(text):

    try:
        return json.loads(text)

    except Exception:

        match = re.search(
            r"\{.*\}",
            text,
            re.DOTALL
        )

        if match:

            try:
                return json.loads(match.group())

            except Exception:
                pass

    return {}


# ==========================================
# DASHBOARD DATA
# ==========================================

def prepare_dashboard_data(result):

    threat = parse_json(
        result["threat_analysis"]
    )

    risk = parse_json(
        result["risk_assessment"]
    )

    response = parse_json(
        result["response"]
    )

    return threat, risk, response


# ==========================================
# DASHBOARD BUILDER
# ==========================================

def build_dashboard(result):

    threat, risk, response = prepare_dashboard_data(result)

    threat_type = threat.get(
        "threat_type",
        "Unknown"
    )

    technique = threat.get(
        "attack_technique",
        "Unknown"
    )

    confidence = threat.get(
        "confidence",
        "Unknown"
    )

    risk_level = risk.get(
        "risk_level",
        "Unknown"
    )

    risk_score = risk.get(
        "risk_score",
        "N/A"
    )

    severity = risk.get(
        "severity",
        "Unknown"
    )

    urgency = risk.get(
        "urgency",
        "Unknown"
    )

    indicators = threat.get(
        "indicators_of_compromise",
        "No indicators identified"
    )

    evidence = threat.get(
        "evidence",
        "No evidence provided"
    )

    impact = threat.get(
        "possible_impact",
        "Unknown"
    )

    immediate_actions = response.get(
        "immediate_defensive_actions",
        "No actions provided"
    )

    investigation = response.get(
        "investigation_steps",
        "No investigation steps provided"
    )

    recommendations = response.get(
        "recommended_response",
        "No recommendations provided"
    )

    prevention = response.get(
        "prevention_recommendations",
        "No prevention recommendations provided"
    )

    return f"""
<div class="dashboard">

<h1>🛡️ SentinelSOC AI</h1>

<p class="subtitle">
AI-Powered Security Operations Center Assistant
</p>

<div class="cards">

<div class="card">
<h3>🚨 Threat</h3>
<p>{threat_type}</p>
</div>

<div class="card">
<h3>🎯 Technique</h3>
<p>{technique}</p>
</div>

<div class="card">
<h3>⚠️ Risk</h3>
<p>{risk_level}</p>
</div>

<div class="card">
<h3>📊 Risk Score</h3>
<p>{risk_score}/100</p>
</div>

<div class="card">
<h3>🔎 Confidence</h3>
<p>{confidence}</p>
</div>

<div class="card">
<h3>🔥 Severity</h3>
<p>{severity}</p>
</div>

</div>

<div class="section">
<h2>🔎 Indicators of Compromise</h2>
<p>{indicators}</p>
</div>

<div class="section">
<h2>📌 Evidence</h2>
<p>{evidence}</p>
</div>

<div class="section">
<h2>💥 Possible Impact</h2>
<p>{impact}</p>
</div>

<div class="section">
<h2>🚀 Immediate Actions</h2>
<p>{immediate_actions}</p>
</div>

<div class="section">
<h2>🕵️ Investigation</h2>
<p>{investigation}</p>
</div>

<div class="section">
<h2>🛠️ Recommended Response</h2>
<p>{recommendations}</p>
</div>

<div class="section">
<h2>🛡️ Prevention</h2>
<p>{prevention}</p>
</div>

</div>
"""


# ==========================================
# ANALYSIS FUNCTION
# ==========================================

def run_analysis(alert):

    if not alert or not alert.strip():

        return (
            "<div style='padding:20px;'>"
            "⚠️ Please enter a security alert "
            "or suspicious activity."
            "</div>"
        )

    try:

        result = sentinel_soc(alert)

        return build_dashboard(result)

    except Exception as e:

        return f"""
        <div style="padding:20px;">
        ❌ Error: {str(e)}
        </div>
        """


# ==========================================
# DASHBOARD CSS
# ==========================================

dashboard_css = """

.dashboard {
    padding: 20px;
}

.dashboard h1 {
    font-size: 32px;
    margin-bottom: 5px;
}

.subtitle {
    opacity: 0.7;
    margin-bottom: 25px;
}

.cards {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 15px;
    margin: 20px 0;
}

.card {
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #333;
}

.card h3 {
    margin-bottom: 8px;
}

.section {
    padding: 18px;
    margin-top: 15px;
    border-radius: 12px;
    border: 1px solid #333;
}

.section h2 {
    margin-bottom: 10px;
}

"""


# ==========================================
# GRADIO APP
# ==========================================

with gr.Blocks(
    title="SentinelSOC AI"
) as app:

    gr.Markdown(
        """
# 🛡️ SentinelSOC AI

### AI-Powered Security Operations Center Assistant

Analyze suspicious security alerts and receive AI-powered
threat analysis, risk assessment, and defensive response.
"""
    )

    alert_input = gr.Textbox(
        label="Security Alert / Suspicious Activity",
        placeholder=(
            "Paste a security alert, log, suspicious "
            "message, or activity here..."
        ),
        lines=8
    )

    analyze_button = gr.Button(
        "🔍 Analyze Threat",
        variant="primary"
    )

    output = gr.HTML()

    analyze_button.click(
        fn=run_analysis,
        inputs=alert_input,
        outputs=output
    )


# ==========================================
# RAILWAY START
# ==========================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            7860
        )
    )

    app.launch(
        server_name="0.0.0.0",
        server_port=port,
        css=dashboard_css
    )
