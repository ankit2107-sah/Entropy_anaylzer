# Project 4.2 – Text/Code Complexity & Security Vulnerability Analyzer Using Shannon Entropy

A Streamlit educational prototype for analysing e-governance logs, plain text and source-code files.

## Features
- Paste text or upload TXT, LOG, PY, C, H, CPP, JAVA, JS, TS, CSV, HTML and JSON files.
- Character frequency, probability distribution and Shannon entropy (bits per character).
- Numerical central-difference estimate for the contribution function `h(p) = -p log2(p)`.
- Trapezoidal area under the sorted probability-contribution curve.
- Character-frequency and entropy-contribution graphs.
- Rule-based indicators for email addresses, phone-like numbers, Aadhaar-like number patterns, password/secret assignments, API/access tokens, private-key headers and long encoded-looking strings.
- A transparent heuristic triage score (not a certified security score).
- Basic source-code metrics: lines, comments, functions, decision points and cyclomatic-complexity estimate. Python uses AST; other languages use approximate pattern matching.
- Downloadable TXT audit report and CSV data.

## Run on Windows
1. Extract the ZIP file.
2. Open the extracted `Project_4_2` folder in VS Code.
3. Open Terminal and optionally create a virtual environment:
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   ```
4. Install packages:
   ```powershell
   pip install -r requirements.txt
   ```
5. Start the app:
   ```powershell
   streamlit run app.py
   ```
6. Open the local URL printed in the terminal (usually `http://localhost:8501`).

## Suggested demonstration
1. Load **E-governance log with review items** to show password/email pattern detection.
2. Load **Repeated characters** and note its low entropy.
3. Load **Random-looking string** and compare its entropy. Explain that high entropy is not proof of encryption or malware.
4. Upload a Python source file to demonstrate the code metrics.
5. Download the audit report and CSV outputs.

## Method and limitations
Shannon entropy is `H = -sum(p_i * log2(p_i))`. It describes character distribution, not whether data is safe or malicious. Pattern matching can produce false positives and cannot guarantee that no secret is present. Aadhaar-like matches are only number-pattern indicators and are not verified Aadhaar numbers. The risk score is a simple, documented educational triage heuristic, not a formal security rating. Python complexity uses AST; complexity for other languages is approximate. Files are read as text and never executed. Do not upload real credentials, personal data or confidential production logs for demonstrations.

## College specification mapping
- Ingest raw e-governance text/source code: paste box and file uploader.
- Extract character probability distribution: frequency/probability table.
- Compute entropy, numerical gradient and area: entropy analysis tab.
- Identify possible plain-text leaks and obfuscation indicators: security analysis tab.
- Generate audit report: downloadable TXT and CSV reports.
- Complexity analysis: source-code metrics tab.

## Dependencies
Python 3.10+ recommended. Streamlit, NumPy, Pandas and Matplotlib.
