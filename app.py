import ast
import base64
import io
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Project 4.2 | Entropy & Security Analyzer", page_icon="🔐", layout="wide")

# ----------------------------- Analysis engines -----------------------------
SENSITIVE_PATTERNS = [
    ("Email address", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "Medium"),
    ("Phone-like number", re.compile(r"(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)"), "Medium"),
    ("Aadhaar-like 12-digit number", re.compile(r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)"), "High"),
    ("Password/secret assignment", re.compile(r"(?i)\b(password|passwd|pwd|secret|client_secret)\b\s*[:=]\s*['\"]?[^\s'\"]{4,}"), "High"),
    ("API/access token assignment", re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{8,}"), "High"),
    ("Private-key header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Critical"),
]


def entropy_of(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def analyze_text(text):
    counts = Counter(text)
    n = len(text)
    chars = list(counts)
    probs = np.array([counts[c] / n for c in chars], dtype=float)
    contributions = -probs * np.log2(probs)
    eps = 1e-7
    lo = np.maximum(probs - eps, 1e-12)
    hi = np.minimum(probs + eps, 1.0 - 1e-12)
    gradient = (-(hi * np.log2(hi)) - (-(lo * np.log2(lo)))) / (hi - lo)
    order = np.argsort(probs)
    sorted_p, sorted_c = probs[order], contributions[order]
    area = float(np.sum((sorted_c[:-1] + sorted_c[1:]) * 0.5 * np.diff(sorted_p))) if len(sorted_p) > 1 else 0.0
    rows = []
    for ch, count, p, contribution, grad in zip(chars, [counts[c] for c in chars], probs, contributions, gradient):
        shown = {" ": "[space]", "\n": "[newline]", "\t": "[tab]", "\r": "[CR]"}.get(ch, ch)
        rows.append({"Character": shown, "Frequency": count, "Probability": p,
                     "Entropy contribution": contribution, "Numerical gradient": grad})
    table = pd.DataFrame(rows).sort_values("Frequency", ascending=False)
    H = entropy_of(text)
    if H < 3:
        label, meaning = "Low entropy", "Character distribution is concentrated or repetitive. This can be normal for structured logs and source code."
    elif H < 5:
        label, meaning = "Moderate entropy", "The input has a moderate variety of characters. Interpret this with the content and file type."
    else:
        label, meaning = "High entropy", "The input has a broad character distribution. Encoded, compressed, encrypted, hashed, or ordinary mixed content can all produce this result."
    return {"length": n, "unique": len(chars), "word_count": len(re.findall(r"\b\w+\b", text)),
            "entropy": H, "label": label, "interpretation": meaning, "table": table,
            "sorted_p": sorted_p, "sorted_contrib": sorted_c, "area": area,
            "gradient_mean": float(np.mean(gradient)), "gradient_min": float(np.min(gradient)),
            "gradient_max": float(np.max(gradient))}


def security_scan(text):
    findings = []
    for name, pattern, severity in SENSITIVE_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(0)
            # Avoid displaying the matched secret/identifier in the report.
            preview = raw[:3] + "…" if len(raw) > 3 else "[redacted]"
            findings.append({"Finding": name, "Severity": severity, "Location": f"characters {match.start()}–{match.end()}", "Masked example": preview})
    # Long hexadecimal/base64-like runs are indicators only, not proof of obfuscation.
    candidates = re.finditer(r"(?<![A-Za-z0-9])[A-Fa-f0-9]{32,}(?![A-Za-z0-9])|(?<![A-Za-z0-9])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9])", text)
    for m in candidates:
        token = m.group(0)
        kind = "Long hexadecimal string" if re.fullmatch(r"[A-Fa-f0-9]+", token) else "Base64-like string"
        findings.append({"Finding": kind, "Severity": "Review", "Location": f"characters {m.start()}–{m.end()}", "Masked example": token[:5] + "…"})
    # Stable, transparent heuristic score; it is a triage score, not a certified security rating.
    weights = {"Medium": 10, "High": 20, "Critical": 35, "Review": 8}
    score = min(100, sum(weights.get(x["Severity"], 0) for x in findings))
    if score >= 60: risk = "High – investigate"
    elif score >= 25: risk = "Moderate – review findings"
    elif score > 0: risk = "Low – review flagged items"
    else: risk = "No pattern detected"
    return pd.DataFrame(findings, columns=["Finding", "Severity", "Location", "Masked example"]), score, risk


def code_metrics(text, filename):
    lines = text.splitlines()
    nonblank = [line for line in lines if line.strip()]
    comment_lines = sum(1 for line in lines if line.strip().startswith(("#", "//", "/*", "*", "<!--")))
    ext = Path(filename).suffix.lower()
    functions = 0
    decisions = 0
    method = "Heuristic source scan"
    if ext == ".py":
        try:
            tree = ast.parse(text)
            functions = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree))
            decisions = sum(isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.comprehension)) for n in ast.walk(tree))
            decisions += sum(isinstance(n, ast.BoolOp) and len(n.values) > 1 for n in ast.walk(tree))
            method = "Python AST analysis"
        except SyntaxError:
            functions = len(re.findall(r"(?m)^\s*def\s+\w+\s*\(", text))
            decisions = len(re.findall(r"\b(if|elif|for|while|except|and|or)\b", text))
            method = "Regex fallback (Python syntax could not be parsed)"
    else:
        functions = len(re.findall(r"(?m)^\s*(?:[\w:<>,*&]+\s+)+\w+\s*\([^;{}]*\)\s*(?:\{|$)", text))
        decisions = len(re.findall(r"\b(if|else\s+if|for|while|case|catch|&&|\|\|)\b", text))
    cyclomatic = decisions + 1 if nonblank else 0
    return {"Total lines": len(lines), "Non-empty lines": len(nonblank), "Comment lines (approx.)": comment_lines,
            "Function/method count (approx.)": functions, "Decision points (approx.)": decisions,
            "Cyclomatic complexity estimate": cyclomatic, "Analysis method": method}


def make_report(filename, result, findings, score, risk, metrics):
    finding_text = findings.to_string(index=False) if not findings.empty else "No configured sensitive/obfuscation patterns detected."
    metrics_text = "\n".join(f"{k}: {v}" for k, v in metrics.items())
    return f"""PROJECT 4.2 – TEXT/CODE COMPLEXITY & SECURITY ANALYSIS
======================================================
Input: {filename}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SHANNON ENTROPY
---------------
Characters: {result['length']}
Unique characters: {result['unique']}
Approximate words: {result['word_count']}
Entropy: {result['entropy']:.5f} bits/character
Band: {result['label']}
Interpretation: {result['interpretation']}
Mean numerical gradient: {result['gradient_mean']:.6f}
Gradient range: {result['gradient_min']:.6f} to {result['gradient_max']:.6f}
Area under sorted probability-contribution curve: {result['area']:.8f}

SECURITY TRIAGE
---------------
Heuristic risk score: {score}/100
Classification: {risk}
Findings (examples are masked):
{finding_text}

CODE COMPLEXITY (ESTIMATES)
---------------------------
{metrics_text}

LIMITATIONS
-----------
Entropy is not proof of encryption, malware, or a vulnerability. Pattern matching can
produce false positives and cannot guarantee that secrets are absent. The risk score
is an educational triage heuristic, not a certified security rating. Generic-language
complexity metrics are approximate. Uploaded files are analysed as text and never executed.
"""

# --------------------------------- Interface ---------------------------------
st.markdown("""
<style>
:root {
    --ea-bg: #080d1a;
    --ea-panel: #11182a;
    --ea-panel-2: #161f35;
    --ea-border: #263450;
    --ea-text: #f4f7fb;
    --ea-muted: #9ba8bf;
    --ea-cyan: #38bdf8;
    --ea-purple: #8b7cf6;
    --ea-green: #34d399;
}
.stApp {
    background:
        radial-gradient(circle at 82% 0%, rgba(56, 189, 248, 0.07), transparent 22rem),
        linear-gradient(135deg, #080d1a 0%, #0b1020 100%);
    color: var(--ea-text);
}
.block-container {
    max-width: 1320px;
    padding: 1.2rem 2rem 3rem;
}
header[data-testid="stHeader"] {
    background: rgba(8, 13, 26, 0.92);
}
[data-testid="stSidebar"] {
    background: #0d1424;
    border-right: 1px solid var(--ea-border);
}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
    color: var(--ea-muted);
}
h1, h2, h3, h4, [data-testid="stHeading"] {
    color: var(--ea-text) !important;
}
.stCaption, [data-testid="stCaptionContainer"] {
    color: var(--ea-muted) !important;
}
div[data-testid="stMetric"] {
    background: var(--ea-panel);
    border: 1px solid var(--ea-border);
    border-radius: 14px;
    padding: 1.1rem 1.2rem;
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.16);
}
div[data-testid="stMetricLabel"] p,
div[data-testid="stMetricLabel"] {
    color: var(--ea-muted) !important;
    font-size: 0.82rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}
div[data-testid="stMetricValue"] {
    color: var(--ea-text) !important;
}
.ea-card-grid {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1rem;
    margin: 0.25rem 0 1rem;
}
.ea-card-grid.three {
    grid-template-columns: repeat(3, minmax(0, 1fr));
}
.ea-card {
    min-height: 112px;
    padding: 1.1rem 1.2rem;
    background: linear-gradient(145deg, var(--ea-panel-2), var(--ea-panel));
    border: 1px solid var(--ea-border);
    border-radius: 14px;
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.18);
}
.ea-card-label {
    color: var(--ea-muted);
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 0.055em;
    text-transform: uppercase;
    margin-bottom: 0.55rem;
}
.ea-card-value {
    color: var(--ea-text);
    font-size: 1.65rem;
    font-weight: 750;
    line-height: 1.15;
    overflow-wrap: anywhere;
}
.ea-card.accent-cyan { border-top: 3px solid var(--ea-cyan); }
.ea-card.accent-purple { border-top: 3px solid var(--ea-purple); }
.ea-card.accent-green { border-top: 3px solid var(--ea-green); }
.ea-card.accent-amber { border-top: 3px solid #fbbf24; }
.ea-summary {
    margin: 0.35rem 0 1rem;
    padding: 0.9rem 1rem;
    background: rgba(17, 24, 42, 0.82);
    border: 1px solid var(--ea-border);
    border-left: 3px solid var(--ea-cyan);
    border-radius: 10px;
    color: var(--ea-text);
}
.ea-summary.security {
    border-left-color: var(--ea-green);
}
.ea-summary strong {
    color: var(--ea-cyan);
}
.ea-summary.security strong {
    color: var(--ea-green);
}
.stTabs [data-baseweb="tab-list"] {
    gap: 0.45rem;
    background: transparent;
}
.stTabs [data-baseweb="tab"] {
    height: auto;
    padding: 0.72rem 1rem;
    color: var(--ea-muted);
    background: var(--ea-panel);
    border: 1px solid var(--ea-border);
    border-radius: 10px;
}
.stTabs [aria-selected="true"] {
    color: var(--ea-text) !important;
    background: linear-gradient(135deg, rgba(56,189,248,.18), rgba(139,124,246,.12));
    border-color: rgba(56,189,248,.7);
}
.stTextArea textarea,
.stTextInput input,
.stSelectbox [data-baseweb="select"] > div,
.stDataFrame {
    background: #11182a !important;
    color: var(--ea-text) !important;
    border-color: var(--ea-border) !important;
}
.stButton > button,
.stDownloadButton > button {
    border-radius: 10px;
    border: 1px solid var(--ea-border);
    background: var(--ea-panel);
    color: var(--ea-text);
}
.stButton > button[kind="primary"] {
    border: none;
    background: linear-gradient(135deg, #0ea5e9, #7c3aed);
    color: white;
    font-weight: 750;
}
.stAlert {
    border-radius: 10px;
}
hr {
    border-color: var(--ea-border);
}
@media (max-width: 900px) {
    .ea-card-grid, .ea-card-grid.three {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
@media (max-width: 600px) {
    .block-container { padding: 1rem; }
    .ea-card-grid, .ea-card-grid.three {
        grid-template-columns: 1fr;
    }
}
</style>
""", unsafe_allow_html=True)
st.title("🔐 Text/Code Complexity & Security Vulnerability Analyzer")
st.caption("Project 4.2 • Shannon entropy • Security indicators • Source-code complexity")

with st.sidebar:
    st.header("Project information")
    st.write("Analyse e-governance logs, plain text and source-code files using character entropy and rule-based security checks.")
    st.info("All analysis runs locally in this Streamlit session. Uploaded files are not executed or sent to an external analysis service by this app.")
    st.markdown("**Supported:** TXT, LOG, PY, C, H, CPP, JAVA, JS, TS, CSV, HTML, JSON")
    st.caption("Educational prototype – findings require human verification.")

input_tab, file_tab, demo_tab = st.tabs(["✍️ Paste text", "📁 Upload file", "🧪 Sample demonstrations"])
text_input, source_name = "", "Pasted text"
with input_tab:
    text_input = st.text_area("Enter e-governance log, text or source code", height=230,
                              placeholder="Example: LOGIN SUCCESS user=admin time=10:30")
with file_tab:
    upload = st.file_uploader("Choose a text/source-code file", type=["txt", "log", "py", "c", "h", "cpp", "java", "js", "ts", "csv", "html", "json"])
    if upload is not None:
        try:
            text_input = upload.getvalue().decode("utf-8-sig")
            source_name = upload.name
            st.success(f"Loaded {upload.name} • {len(text_input):,} characters")
        except UnicodeDecodeError:
            st.error("Could not decode this file as UTF-8. Save it as UTF-8 text and try again.")
with demo_tab:
    samples = {
        "Repeated characters": ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "sample.txt"),
        "E-governance log with review items": ("LOGIN SUCCESS user=admin time=10:30\nemail=admin@example.com\npassword=admin123\n", "sample.log"),
        "Python source code": ("def calculate_total(items):\n    total = 0\n    for item in items:\n        if item > 0:\n            total += item\n    return total\n", "sample_code.py"),
        "Random-looking string": ("a8X#9pQ!2zL@7mK$4vT%6wR&", "sample.txt"),
    }
    choice = st.selectbox("Select a demonstration", list(samples))
    if st.button("Load demonstration"):
        st.session_state["demo_input"] = samples[choice][0]
        st.session_state["demo_filename"] = samples[choice][1]
    if "demo_input" in st.session_state:
        st.code(st.session_state["demo_input"])
        if not text_input:
            text_input, source_name = st.session_state["demo_input"], st.session_state["demo_filename"]

if st.button("🔍 Analyse input", type="primary", use_container_width=True):
    if not text_input.strip():
        st.warning("Please enter text, upload a file or load a demonstration first.")
    else:
        st.session_state["project42_result"] = {
            "entropy": analyze_text(text_input),
            "security": security_scan(text_input),
            "complexity": code_metrics(text_input, source_name),
            "name": source_name,
        }

bundle = st.session_state.get("project42_result")
if bundle:
    r = bundle["entropy"]
    findings, risk_score, risk_label = bundle["security"]
    metrics = bundle["complexity"]
    st.divider()
    st.subheader("Analysis dashboard")
    st.markdown(f"""
    <div class="ea-card-grid">
      <div class="ea-card accent-cyan"><div class="ea-card-label">Shannon entropy</div><div class="ea-card-value">{r['entropy']:.3f}</div></div>
      <div class="ea-card accent-purple"><div class="ea-card-label">Characters</div><div class="ea-card-value">{r['length']:,}</div></div>
      <div class="ea-card accent-green"><div class="ea-card-label">Unique characters</div><div class="ea-card-value">{r['unique']:,}</div></div>
      <div class="ea-card accent-amber"><div class="ea-card-label">Heuristic risk score</div><div class="ea-card-value">{risk_score}/100</div></div>
    </div>
    <div class="ea-summary"><strong>Entropy interpretation:</strong> {r['label']} — {r['interpretation']}</div>
    <div class="ea-summary security"><strong>Security triage:</strong> {risk_label}</div>
    """, unsafe_allow_html=True)

    entropy_tab, security_tab, complexity_tab, report_tab = st.tabs(["📊 Entropy analysis", "🛡️ Security analysis", "🧩 Code complexity", "📄 Audit report"])
    with entropy_tab:
        left, right = st.columns(2)
        with left:
            st.markdown("#### Character frequency (top 20)")
            freq = r["table"].head(20)
            fig, ax = plt.subplots(figsize=(8, 4), facecolor="#11182a")
            ax.set_facecolor("#11182a")
            ax.bar(freq["Character"].astype(str), freq["Frequency"], color="#38bdf8")
            ax.set_xlabel("Character", color="#9ba8bf"); ax.set_ylabel("Frequency", color="#9ba8bf")
            ax.tick_params(axis="x", rotation=55, colors="#9ba8bf"); ax.tick_params(axis="y", colors="#9ba8bf")
            ax.spines["bottom"].set_color("#263450"); ax.spines["left"].set_color("#263450")
            ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
            ax.grid(axis="y", alpha=.12, color="#9ba8bf")
            fig.tight_layout(); st.pyplot(fig); plt.close(fig)
        with right:
            st.markdown("#### Probability vs entropy contribution")
            fig, ax = plt.subplots(figsize=(8, 4), facecolor="#11182a")
            ax.set_facecolor("#11182a")
            ax.plot(r["sorted_p"], r["sorted_contrib"], marker="o", color="#8b7cf6", linewidth=2)
            ax.set_xlabel("Character probability P(x)", color="#9ba8bf")
            ax.set_ylabel("−P(x) log₂ P(x)", color="#9ba8bf")
            ax.tick_params(colors="#9ba8bf")
            ax.spines["bottom"].set_color("#263450"); ax.spines["left"].set_color("#263450")
            ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
            ax.grid(True, alpha=.12, color="#9ba8bf")
            fig.tight_layout(); st.pyplot(fig); plt.close(fig)
        st.markdown("#### Character probability distribution")
        st.dataframe(r["table"], use_container_width=True, hide_index=True)
        g1, g2, g3 = st.columns(3)
        g1.metric("Mean numerical gradient", f"{r['gradient_mean']:.5f}")
        g2.metric("Gradient range", f"{r['gradient_min']:.4f} to {r['gradient_max']:.4f}")
        g3.metric("Area under curve", f"{r['area']:.7f}")
        st.caption("Gradient is estimated numerically for h(p) = −p log₂(p). Area is the trapezoidal area under the sorted probability-contribution curve; both are descriptive mathematical outputs, not security scores.")
    with security_tab:
        st.subheader("Sensitive information & obfuscation indicators")
        st.metric("Heuristic risk score", f"{risk_score}/100", help="Rule-based triage score. It is not a certified security rating.")
        st.write(f"**Classification:** {risk_label}")
        if findings.empty:
            st.success("No configured patterns were detected. This does not guarantee that the input contains no sensitive information.")
        else:
            st.warning("Review the following indicators. Some may be false positives.")
            st.dataframe(findings, use_container_width=True, hide_index=True)
        st.caption("Secret-like values are masked in the results. Entropy and encoded-string patterns are clues only; they do not prove malicious activity or encryption.")
    with complexity_tab:
        st.subheader("Source-code complexity estimates")
        metric_items = list(metrics.items())
        card_grid = "".join(
            f'<div class="ea-card accent-cyan"><div class="ea-card-label">{key}</div>'
            f'<div class="ea-card-value">{value}</div></div>'
            for key, value in metric_items
        )
        st.markdown(f'<div class="ea-card-grid three">{card_grid}</div>', unsafe_allow_html=True)
        st.info("Cyclomatic complexity is estimated as decision points + 1. Python uses its AST parser; other languages use simple pattern matching. For non-code text, these counts are not meaningful.")
    with report_tab:
        report = make_report(bundle["name"], r, findings, risk_score, risk_label, metrics)
        st.text_area("Report preview", report, height=380)
        st.download_button("⬇️ Download full audit report (.txt)", report, file_name="project_4_2_audit_report.txt", mime="text/plain")
        st.download_button("⬇️ Download character analysis (.csv)", r["table"].to_csv(index=False).encode("utf-8"), file_name="character_probability_analysis.csv", mime="text/csv")
        st.download_button("⬇️ Download security findings (.csv)", findings.to_csv(index=False).encode("utf-8"), file_name="security_findings.csv", mime="text/csv")

st.divider()
st.caption("Project 4.2 | Python • Streamlit • NumPy • Pandas • Matplotlib | Educational use")
