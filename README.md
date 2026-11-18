# Entropy Analyzer

A browser-based dashboard for character-level Shannon entropy, heuristic sensitive-pattern scanning, and approximate source-code metrics. The web version runs entirely on the user's device: pasted text and uploaded files are not sent to an analysis server, and files are never executed.

## Run locally

### Browser dashboard

Open `public/index.html` in a browser, or serve the project folder with any static file server. No build step or JavaScript packages are required.

### Streamlit app

The original Python app is also available:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open <http://localhost:8501>. On macOS or Linux, replace `py` with `python3` and use `.venv/bin/python`.

## Deploy to Vercel

The browser dashboard is a static site, which Vercel can host directly. The included `vercel.json` sets `public` as the output directory.

1. Import this GitHub repository in the Vercel dashboard.
2. Select **Other** as the framework preset if Vercel asks.
3. Keep the build command empty; no build step or environment variables are needed.
4. Deploy. Vercel will publish the contents of `public/` and redeploy on pushes to the connected branch.

The Streamlit `app.py` remains for local use; Vercel serves the static browser dashboard instead.

## Dashboard features

- Character counts, Shannon entropy, unique-character count, and entropy interpretation.
- Character-frequency and probability/contribution charts with a detailed character table.
- Rule-based indicators for email addresses, phone-like and Aadhaar-like numbers, password/token assignments, private-key headers, and long encoded-looking strings. Examples are masked.
- Approximate line, comment, function, decision-point, and cyclomatic-complexity metrics.
- Downloadable text report and CSV exports.

## Limitations and safe use

- Entropy is not proof of encryption, compression, or malicious content.
- Pattern matching can produce false positives and cannot guarantee that secrets are absent.
- Security scores and complexity metrics are educational estimates, not certified ratings. The browser version uses heuristic source scanning; Python does not receive a full AST parse in the browser.
- For browser responsiveness, analysis is limited to 250,000 characters and uploaded files must be under 2 MB.
- Use synthetic or public data. Do not upload real credentials, private keys, or personal identifiers to any public service.
