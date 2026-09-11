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


    # Convert lists into attractive dashboard items

    if isinstance(indicators, list):
        indicator_html = "".join(
            f'<span class="indicator">⚠️ {item}</span>'
            for item in indicators
        )
    else:
        indicator_html = (
            f'<span class="indicator">⚠️ {indicators}</span>'
        )


    if isinstance(immediate_actions, list):
        immediate_html = "".join(
            f'<div class="action">🛡️ {item}</div>'
            for item in immediate_actions
        )
    else:
        immediate_html = (
            f'<div class="action">🛡️ {immediate_actions}</div>'
        )


    if isinstance(investigation, list):
        investigation_html = "".join(
            f'<div class="action">🔍 {item}</div>'
            for item in investigation
        )
    else:
        investigation_html = (
            f'<div class="action">🔍 {investigation}</div>'
        )


    if isinstance(recommendations, list):
        recommendation_html = "".join(
            f'<div class="action">🚀 {item}</div>'
            for item in recommendations
        )
    else:
        recommendation_html = (
            f'<div class="action">🚀 {recommendations}</div>'
        )


    if isinstance(prevention, list):
        prevention_html = "".join(
            f'<div class="action">🛡️ {item}</div>'
            for item in prevention
        )
    else:
        prevention_html = (
            f'<div class="action">🛡️ {prevention}</div>'
        )


    return f"""

<div class="dashboard">

    <!-- HEADER -->

    <div class="dashboard-header">

        <div class="brand">
            🛡️
            <span>SENTINELSOC AI</span>
        </div>

        <div class="subtitle">
            AI-POWERED SECURITY OPERATIONS CENTER
        </div>

        <div class="status">

            <span class="online-dot"></span>
            SYSTEM ONLINE

            <span class="separator">•</span>

            🤖 3 AGENTS ACTIVE

            <span class="separator">•</span>

            🔐 SECURE ANALYSIS

        </div>

    </div>


    <!-- TOP CARDS -->

    <div class="top-grid">

        <div class="soc-card">

            <div class="card-title">
                🔍 THREAT DETECTED
            </div>

            <div class="big-value">
                {threat_type}
            </div>

            <div class="small-text">
                🎯 {technique}
            </div>

        </div>


        <div class="soc-card">

            <div class="card-title">
                ⚠️ RISK LEVEL
            </div>

            <div class="risk-value">
                {risk_level}
            </div>

            <div class="score">
                {risk_score}/100
            </div>

        </div>


        <div class="soc-card">

            <div class="card-title">
                🤖 AI CONFIDENCE
            </div>

            <div class="confidence">
                {confidence}%
            </div>

            <div class="small-text">
                Analysis confidence
            </div>

        </div>

    </div>


    <!-- INDICATORS -->

    <div class="soc-card">

        <div class="card-title">
            📌 INDICATORS
        </div>

        <div class="indicators">
            {indicator_html}
        </div>

    </div>


    <!-- EVIDENCE + IMPACT -->

    <div class="middle-grid">

        <div class="soc-card">

            <div class="card-title">
                🧠 EVIDENCE
            </div>

            <div class="content">
                {evidence}
            </div>

        </div>


        <div class="soc-card">

            <div class="card-title">
                💥 IMPACT
            </div>

            <div class="content">
                {impact}
            </div>

            <div class="small-text">
                ⏱️ {urgency}
            </div>

        </div>

    </div>


    <!-- IMMEDIATE ACTIONS -->

    <div class="soc-card">

        <div class="card-title">
            🛡️ RECOMMENDED ACTIONS
        </div>

        {immediate_html}

    </div>


    <!-- INVESTIGATION -->

    <div class="soc-card">

        <div class="card-title">
            🔍 INVESTIGATION
        </div>

        {investigation_html}

    </div>


    <!-- RECOMMENDED RESPONSE -->

    <div class="soc-card">

        <div class="card-title">
            🚀 RECOMMENDED RESPONSE
        </div>

        {recommendation_html}

    </div>


    <!-- PREVENTION -->

    <div class="soc-card">

        <div class="card-title">
            🛡️ PREVENTION
        </div>

        {prevention_html}

    </div>

</div>

"""


# ==========================================
# ANALYSIS FUNCTION
# ==========================================

def run_analysis(alert):

    if not alert or not alert.strip():

        return """
        <div class="error-box">
            🚨 Please enter a security alert
            or suspicious activity.
        </div>
        """

    try:

        result = sentinel_soc(alert)

        return build_dashboard(result)

    except Exception as e:

        return f"""
        <div class="error-box">
            ❌ Error: {str(e)}
        </div>
        """


# ==========================================
# PROFESSIONAL DASHBOARD CSS
# ==========================================

dashboard_css = """

/* ==========================================
   MAIN APPLICATION
   ========================================== */

body {
    background: #070711 !important;
}

.gradio-container {
    max-width: 1400px !important;
    margin: auto !important;
    background: #070711 !important;
}


/* ==========================================
   DASHBOARD
   ========================================== */

.dashboard {

    font-family: Arial, sans-serif;

    padding: 10px;

    color: #eeeeF5;

}


/* ==========================================
   HEADER
   ========================================== */

.dashboard-header {

    padding: 10px 0 20px 0;

}


.brand {

    display: flex;

    align-items: center;

    gap: 14px;

    font-size: 42px;

    font-weight: 800;

    letter-spacing: 2px;

    color: #f5f5fa;

}


.brand:first-letter {

    font-size: 45px;

}


.subtitle {

    margin-top: 10px;

    font-size: 16px;

    font-weight: 700;

    color: #ffffff;

    letter-spacing: 0.5px;

}


.status {

    margin-top: 28px;

    font-size: 14px;

    color: #eeeeF5;

}


.online-dot {

    display: inline-block;

    width: 16px;

    height: 16px;

    background: #35e88a;

    border-radius: 50%;

    margin-right: 7px;

    box-shadow: 0 0 12px rgba(53,232,138,0.7);

}


.separator {

    margin: 0 12px;

    color: #ffffff;

}


/* ==========================================
   TOP CARDS
   ========================================== */

.top-grid {

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 16px;

    margin-top: 18px;

    margin-bottom: 16px;

}


/* ==========================================
   SOC CARD
   ========================================== */

.soc-card {

    background:
        linear-gradient(
            145deg,
            #111122,
            #0a0a16
        );

    border: 1px solid #29294a;

    border-radius: 18px;

    padding: 22px;

    margin-bottom: 16px;

    box-shadow:
        0 8px 30px
        rgba(0,0,0,0.35);

    transition: 0.2s;

}


.soc-card:hover {

    border-color: #6c5ce7;

    box-shadow:
        0 0 22px
        rgba(108,92,231,0.25);

}


/* ==========================================
   CARD TITLES
   ========================================== */

.card-title {

    font-size: 13px;

    font-weight: 700;

    letter-spacing: 1.5px;

    color: #aaaac5;

    margin-bottom: 12px;

}


/* ==========================================
   CARD VALUES
   ========================================== */

.big-value {

    font-size: 28px;

    font-weight: 800;

    color: #ffffff;

}


.risk-value {

    font-size: 30px;

    font-weight: 800;

    color: #ff4d6d;

}


.score {

    font-size: 20px;

    font-weight: 700;

    margin-top: 6px;

    color: #b8a7ff;

}


.confidence {

    font-size: 28px;

    font-weight: 800;

    color: #b8a7ff;

}


.small-text {

    color: #9696ad;

    margin-top: 8px;

    font-size: 14px;

}


/* ==========================================
   INDICATORS
   ========================================== */

.indicators {

    display: flex;

    flex-wrap: wrap;

    gap: 8px;

}


.indicator {

    background: #19192c;

    border: 1px solid #343452;

    border-radius: 10px;

    padding: 8px 12px;

    color: #d8d8ea;

    font-size: 13px;

}


/* ==========================================
   MIDDLE SECTION
   ========================================== */

.middle-grid {

    display: grid;

    grid-template-columns:
        2fr 1fr;

    gap: 16px;

}


/* ==========================================
   CONTENT
   ========================================== */

.content {

    color: #eeeeF5;

    font-size: 15px;

    line-height: 1.6;

}


/* ==========================================
   ACTIONS
   ========================================== */

.action {

    background: #151527;

    border-left: 3px solid #6c5ce7;

    border-radius: 8px;

    padding: 10px 12px;

    margin-top: 8px;

    color: #eeeeF5;

    font-size: 14px;

}


/* ==========================================
   ERROR
   ========================================== */

.error-box {

    background: #111122;

    border: 1px solid #ff4d6d;

    border-radius: 14px;

    padding: 20px;

    color: #ffffff;

}


/* ==========================================
   RESPONSIVE
   ========================================== */

@media (max-width: 900px) {

    .top-grid {

        grid-template-columns: 1fr;

    }

    .middle-grid {

        grid-template-columns: 1fr;

    }

    .brand {

        font-size: 32px;

    }

}

"""


# ==========================================
# GRADIO APP
# ==========================================

with gr.Blocks(
    title="SentinelSOC AI",
    css=dashboard_css
) as app:


    # ======================================
    # APPLICATION HEADER
    # ======================================

    gr.Markdown(
        """
# 🛡️ SENTINELSOC AI

**AI-POWERED SECURITY OPERATIONS CENTER**

🟢 SYSTEM ONLINE &nbsp;&nbsp; • &nbsp;&nbsp;
🤖 3 AGENTS ACTIVE &nbsp;&nbsp; • &nbsp;&nbsp;
🔐 SECURE ANALYSIS
"""
    )


    # ======================================
    # SECURITY ALERT INPUT
    # ======================================

    gr.Markdown(
        "## 🚨 NEW SECURITY ALERT"
    )


    alert_input = gr.Textbox(

        placeholder=(
            "Paste suspicious activity, "
            "security alert, or log here..."
        ),

        lines=7,

        show_label=False

    )


    # ======================================
    # ANALYZE BUTTON
    # ======================================

    analyze_button = gr.Button(

        "🔍 ANALYZE THREAT",

        variant="primary"

    )


    # ======================================
    # OUTPUT
    # ======================================

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

        server_port=port

    )

