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
    area = float(np.trapz(sorted_c, sorted_p)) if len(sorted_p) > 1 else 0.0
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
st.markdown("<style>.main .block-container{padding-top:1.5rem} div[data-testid='stMetric']{background:#f4f6fb;padding:12px;border-radius:10px}</style>", unsafe_allow_html=True)
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
    a, b, c, d = st.columns(4)
    a.metric("Shannon entropy", f"{r['entropy']:.3f} bits/char")
    b.metric("Characters", f"{r['length']:,}")
    c.metric("Unique characters", r["unique"])
    d.metric("Heuristic risk score", f"{risk_score}/100")
    st.markdown(f"**Entropy interpretation:** {r['label']} — {r['interpretation']}")
    st.markdown(f"**Security triage:** {risk_label}")

    entropy_tab, security_tab, complexity_tab, report_tab = st.tabs(["📊 Entropy analysis", "🛡️ Security analysis", "🧩 Code complexity", "📄 Audit report"])
    with entropy_tab:
        left, right = st.columns(2)
        with left:
            st.markdown("#### Character frequency (top 20)")
            freq = r["table"].head(20)
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.bar(freq["Character"].astype(str), freq["Frequency"])
            ax.set_xlabel("Character"); ax.set_ylabel("Frequency"); ax.tick_params(axis="x", rotation=55)
            fig.tight_layout(); st.pyplot(fig); plt.close(fig)
        with right:
            st.markdown("#### Probability vs entropy contribution")
            fig, ax = plt.subplots(figsize=(8, 4))
            ax.plot(r["sorted_p"], r["sorted_contrib"], marker="o")
            ax.set_xlabel("Character probability P(x)"); ax.set_ylabel("−P(x) log₂ P(x)"); ax.grid(True, alpha=.3)
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
        cols = st.columns(3)
        for i, (key, value) in enumerate(metrics.items()):
            cols[i % 3].metric(key, value)
        st.info("Cyclomatic complexity is estimated as decision points + 1. Python uses its AST parser; other languages use simple pattern matching. For non-code text, these counts are not meaningful.")
    with report_tab:
        report = make_report(bundle["name"], r, findings, risk_score, risk_label, metrics)
        st.text_area("Report preview", report, height=380)
        st.download_button("⬇️ Download full audit report (.txt)", report, file_name="project_4_2_audit_report.txt", mime="text/plain")
        st.download_button("⬇️ Download character analysis (.csv)", r["table"].to_csv(index=False).encode("utf-8"), file_name="character_probability_analysis.csv", mime="text/csv")
        st.download_button("⬇️ Download security findings (.csv)", findings.to_csv(index=False).encode("utf-8"), file_name="security_findings.csv", mime="text/csv")

st.divider()
st.caption("Project 4.2 | Python • Streamlit • NumPy • Pandas • Matplotlib | Educational use")
