import os
import json
import re
import gradio as gr
from groq import Groq


# ==========================================
# CONFIGURATION
# ==========================================

MODEL = "openai/gpt-oss-120b"


# ==========================================
# GET API KEY
# ==========================================

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

Create a SHORT SOC response.

IMPORTANT:
- Do NOT write explanations or paragraphs.
- Do NOT use sub-bullets.
- Do NOT use numbering.
- Each item must be ONE short sentence.
- Keep every item concise and practical.

Return ONLY these JSON fields:

"immediate_defensive_actions":
Exactly 4 short items.
Each item should be one short sentence.

"investigation_steps":
Exactly 3 short items.
Each item should be one short sentence.

"prevention_recommendations":
Exactly 4 short items.
Each item should be one short sentence.

Do NOT include "recommended_response".

Return valid JSON only.
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
# SHORT RESPONSE ITEMS
# ==========================================

def clean_short_item(item):

    item = str(item)

    # Remove markdown
    item = re.sub(r"\*\*(.*?)\*\*", r"\1", item)
    item = re.sub(r"__(.*?)__", r"\1", item)
    item = re.sub(r"`(.*?)`", r"\1", item)

    # Remove numbering
    item = re.sub(
        r"^\s*\d+[\.\)\-:]\s*",
        "",
        item
    )

    # Remove bullets
    item = re.sub(
        r"^\s*[-*•]\s*",
        "",
        item
    )

    # Remove unnecessary spaces
    item = re.sub(
        r"\s+",
        " ",
        item
    ).strip()

    return item


def get_short_items(value, limit):

    if isinstance(value, list):

        items = value

    else:

        text = str(value)

        # If AI returns multiple lines in one string
        items = re.split(
            r"\n+",
            text
        )

    cleaned = []

    for item in items:

        item = clean_short_item(item)

        if item:
            cleaned.append(item)

    return cleaned[:limit]


# ==========================================
# DASHBOARD BUILDER
# ==========================================

def build_dashboard(result):

    threat, risk, response = prepare_dashboard_data(result)


    # ======================================
    # THREAT INFORMATION
    # KEEPING EXISTING INFORMATION
    # ======================================

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


    # ======================================
    # KEEP INDICATORS EXACTLY AS BEFORE
    # ======================================

    indicators = threat.get(
        "indicators_of_compromise",
        "No indicators identified"
    )


    # ======================================
    # KEEP EVIDENCE EXACTLY AS BEFORE
    # ======================================

    evidence = threat.get(
        "evidence",
        "No evidence provided"
    )


    # ======================================
    # KEEP IMPACT EXACTLY AS BEFORE
    # ======================================

    impact = threat.get(
        "possible_impact",
        "Unknown"
    )


    # ======================================
    # RESPONSE DATA
    # SHORTENED
    # ======================================

    immediate_actions = response.get(
        "immediate_defensive_actions",
        "No actions provided"
    )

    investigation = response.get(
        "investigation_steps",
        "No investigation steps provided"
    )

    prevention = response.get(
        "prevention_recommendations",
        "No prevention recommendations provided"
    )


    # ======================================
    # INDICATORS
    # EXISTING STYLE - UNCHANGED
    # ======================================

    if isinstance(indicators, list):

        indicator_html = "".join(
            f'<span class="indicator">⚠️ {item}</span>'
            for item in indicators
        )

    else:

        indicator_html = (
            f'<span class="indicator">⚠️ {indicators}</span>'
        )


    # ======================================
    # RECOMMENDED ACTIONS
    # EXACTLY 4
    # ======================================

    action_items = get_short_items(
        immediate_actions,
        4
    )

    immediate_html = "".join(
        f'<div class="action">🛡️ {item}</div>'
        for item in action_items
    )


    # ======================================
    # INVESTIGATION
    # EXACTLY 3
    # ======================================

    investigation_items = get_short_items(
        investigation,
        3
    )

    investigation_html = "".join(
        f'<div class="action">🔍 {item}</div>'
        for item in investigation_items
    )


    # ======================================
    # PREVENTION
    # EXACTLY 4
    # ======================================

    prevention_items = get_short_items(
        prevention,
        4
    )

    prevention_html = "".join(
        f'<div class="action">🛡️ {item}</div>'
        for item in prevention_items
    )


    # ======================================
    # DASHBOARD
    # ======================================

    return f"""

<div class="dashboard">

    <!-- ==================================
         HEADER
         ================================== -->

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


    <!-- ==================================
         TOP CARDS
         ================================== -->

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


    <!-- ==================================
         INDICATORS
         ================================== -->

    <div class="soc-card">

        <div class="card-title">
            📌 INDICATORS
        </div>

        <div class="indicators">

            {indicator_html}

        </div>

    </div>


    <!-- ==================================
         EVIDENCE + IMPACT
         ================================== -->

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


    <!-- ==================================
         RECOMMENDED ACTIONS
         4 SHORT LINES
         ================================== -->

    <div class="soc-card">

        <div class="card-title">
            🛡️ RECOMMENDED ACTIONS
        </div>

        {immediate_html}

    </div>


    <!-- ==================================
         INVESTIGATION
         3 SHORT LINES
         ================================== -->

    <div class="soc-card">

        <div class="card-title">
            🔍 INVESTIGATION
        </div>

        {investigation_html}

    </div>


    <!-- ==================================
         PREVENTION
         4 SHORT LINES
         ================================== -->

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

    padding: 8px;

    color: #eeeeF5;
}


/* ==========================================
   HEADER
   ========================================== */

.dashboard-header {

    padding: 6px 0 14px 0;
}


.brand {

    display: flex;

    align-items: center;

    gap: 12px;

    font-size: 36px;

    font-weight: 800;

    letter-spacing: 2px;

    color: #f5f5fa;
}


.brand:first-letter {
    font-size: 40px;
}


.subtitle {

    margin-top: 7px;

    font-size: 14px;

    font-weight: 700;

    color: #ffffff;

    letter-spacing: 0.5px;
}


.status {

    margin-top: 16px;

    font-size: 13px;

    color: #eeeeF5;
}


.online-dot {

    display: inline-block;

    width: 12px;

    height: 12px;

    background: #35e88a;

    border-radius: 50%;

    margin-right: 6px;

    box-shadow:
        0 0 10px
        rgba(53,232,138,0.7);
}


.separator {

    margin: 0 9px;

    color: #ffffff;
}


/* ==========================================
   TOP CARDS
   ========================================== */

.top-grid {

    display: grid;

    grid-template-columns:
        repeat(3, 1fr);

    gap: 12px;

    margin-top: 12px;

    margin-bottom: 12px;
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

    border-radius: 16px;

    padding: 17px;

    margin-bottom: 12px;

    box-shadow:
        0 7px 25px
        rgba(0,0,0,0.35);

    transition: 0.2s;
}


.soc-card:hover {

    border-color: #6c5ce7;

    box-shadow:
        0 0 20px
        rgba(108,92,231,0.25);
}


/* ==========================================
   CARD TITLES
   ========================================== */

.card-title {

    font-size: 12px;

    font-weight: 700;

    letter-spacing: 1.5px;

    color: #aaaac5;

    margin-bottom: 9px;
}


/* ==========================================
   CARD VALUES
   ========================================== */

.big-value {

    font-size: 26px;

    font-weight: 800;

    color: #ffffff;
}


.risk-value {

    font-size: 28px;

    font-weight: 800;

    color: #ff4d6d;
}


.score {

    font-size: 18px;

    font-weight: 700;

    margin-top: 5px;

    color: #b8a7ff;
}


.confidence {

    font-size: 26px;

    font-weight: 800;

    color: #b8a7ff;
}


.small-text {

    color: #9696ad;

    margin-top: 6px;

    font-size: 13px;
}


/* ==========================================
   INDICATORS
   ========================================== */

.indicators {

    display: flex;

    flex-wrap: wrap;

    gap: 7px;
}


.indicator {

    background: #19192c;

    border: 1px solid #343452;

    border-radius: 9px;

    padding: 7px 10px;

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

    gap: 12px;
}


/* ==========================================
   CONTENT
   ========================================== */

.content {

    color: #eeeeF5;

    font-size: 14px;

    line-height: 1.5;
}


/* ==========================================
   ACTIONS
   ========================================== */

.action {

    background: #151527;

    border-left: 3px solid #6c5ce7;

    border-radius: 7px;

    padding: 8px 10px;

    margin-top: 6px;

    color: #eeeeF5;

    font-size: 13px;

    line-height: 1.35;
}


/* ==========================================
   ERROR
   ========================================== */

.error-box {

    background: #111122;

    border: 1px solid #ff4d6d;

    border-radius: 12px;

    padding: 18px;

    color: #ffffff;
}


/* ==========================================
   INPUT AREA
   ========================================== */

textarea {

    background: #0d0d1b !important;

    border-color: #29294a !important;

    color: #eeeeF5 !important;
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

        font-size: 30px;
    }

}

"""


# ==========================================
# GRADIO APP
# ==========================================
# IMPORTANT:
# CSS is NOT passed here.
# It is passed only to app.launch()
# to avoid the Gradio 6.0 warning.
# ==========================================

with gr.Blocks(
    title="SentinelSOC AI"
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

        lines=5,

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

        server_port=port,

        css=dashboard_css
    )
