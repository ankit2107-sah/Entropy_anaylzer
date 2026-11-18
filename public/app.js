"use strict";

const $ = (selector) => document.querySelector(selector);
const input = $("#text-input");
const fileInput = $("#file-input");
const inputMeta = $("#input-meta");
const errorMessage = $("#input-error");
const MAX_INPUT_CHARACTERS = 250000;
let sourceName = "Pasted text";
let currentResult = null;

const samples = {
  log: {
    name: "sample.log",
    text: "LOGIN SUCCESS user=student time=10:30\nemail=student@example.com\npassword=example123\n",
  },
  code: {
    name: "sample_code.py",
    text: "def calculate_total(items):\n    total = 0\n    for item in items:\n        if item > 0:\n            total += item\n    return total\n",
  },
  random: {
    name: "sample.txt",
    text: "a8X#9pQ!2zL@7mK$4vT%6wR&",
  },
};

function entropy(probabilities) {
  return probabilities.reduce((total, probability) => (
    total - probability * Math.log2(probability)
  ), 0);
}
function displayCharacter(character) {
  return ({ " ": "[space]", "\n": "[newline]", "\t": "[tab]", "\r": "[CR]" })[character] || character;
}

function analyzeText(text, filename) {
  const characters = Array.from(text);
  const counts = new Map();
  for (const character of characters) {
    counts.set(character, (counts.get(character) || 0) + 1);
  }
  const length = characters.length;
  const rows = [...counts.entries()].map(([character, frequency]) => {
    const probability = frequency / length;
    const contribution = -probability * Math.log2(probability);
    const epsilon = 1e-7;
    const low = Math.max(probability - epsilon, 1e-12);
    const high = Math.min(probability + epsilon, 1 - 1e-12);
    const gradient = (-(high * Math.log2(high)) + low * Math.log2(low)) / (high - low);
    return { character: displayCharacter(character), frequency, probability, contribution, gradient };
  }).sort((a, b) => b.frequency - a.frequency);
  const probabilities = [...counts.values()].map((count) => count / length);
  const entropyValue = entropy(probabilities);
  let label;
  let meaning;
  if (entropyValue < 3) {
    label = "Low entropy";
    meaning = "Character distribution is concentrated or repetitive. This can be normal for structured logs and source code.";
  } else if (entropyValue < 5) {
    label = "Moderate entropy";
    meaning = "The input has a moderate variety of characters. Interpret this with the content and file type.";
  } else {
    label = "High entropy";
    meaning = "The input has a broad character distribution. Encoded, compressed, encrypted, hashed, or ordinary mixed content can all produce this result.";
  }
  const sorted = [...rows].sort((a, b) => a.probability - b.probability);
  const area = sorted.slice(1).reduce((sum, point, index) => {
    const previous = sorted[index];
    return sum + ((previous.contribution + point.contribution) / 2)
      * (point.probability - previous.probability);
  }, 0);
  const gradientSummary = rows.reduce((summary, row) => ({
    sum: summary.sum + row.gradient,
    min: Math.min(summary.min, row.gradient),
    max: Math.max(summary.max, row.gradient),
  }), { sum: 0, min: Infinity, max: -Infinity });
  const findings = scanSecurity(text);
  return {
    name: filename,
    text,
    length,
    unique: counts.size,
    words: (text.match(/\b\w+\b/g) || []).length,
    entropy: entropyValue,
    label,
    meaning,
    rows,
    sorted,
    area,
    gradientMean: gradientSummary.sum / rows.length,
    gradientMin: gradientSummary.min,
    gradientMax: gradientSummary.max,
    findings,
    riskScore: Math.min(100, findings.reduce((sum, finding) => sum + ({
      Medium: 10, High: 20, Critical: 35, Review: 8,
    })[finding.severity], 0)),
    metrics: codeMetrics(text, filename),
  };
}

function scanSecurity(text) {
  const findings = [];
  const patterns = [
    ["Email address", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "Medium"],
    ["Phone-like number", /(?<!\d)(?:\+?91[-\s]?)?[6-9]\d{9}(?!\d)/g, "Medium"],
    ["Aadhaar-like 12-digit number", /(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)/g, "High"],
    ["Password/secret assignment", /\b(password|passwd|pwd|secret|client_secret)\b\s*[:=]\s*['"]?[^\s'"]{4,}/gi, "High"],
    ["API/access token assignment", /\b(api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"]?[A-Za-z0-9_./+=-]{8,}/gi, "High"],
    ["Private-key header", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, "Critical"],
  ];
  for (const [name, pattern, severity] of patterns) {
    for (const match of text.matchAll(pattern)) {
      const raw = match[0];
      findings.push({
        name,
        severity,
        location: `characters ${match.index}-${match.index + raw.length}`,
        masked: raw.length > 3 ? `${raw.slice(0, 3)}…` : "[redacted]",
      });
    }
  }
  const candidates = /(?<![A-Za-z0-9])[A-Fa-f0-9]{32,}(?![A-Za-z0-9])|(?<![A-Za-z0-9])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9])/g;
  for (const match of text.matchAll(candidates)) {
    const raw = match[0];
    findings.push({
      name: /^[A-Fa-f0-9]+$/.test(raw) ? "Long hexadecimal string" : "Base64-like string",
      severity: "Review",
      location: `characters ${match.index}-${match.index + raw.length}`,
      masked: `${raw.slice(0, 5)}…`,
    });
  }
  return findings.sort((a, b) => a.location.localeCompare(b.location, undefined, { numeric: true }));
}

function codeMetrics(text, filename) {
  const lines = text.split(/\r\n|\r|\n/);
  const nonblank = lines.filter((line) => line.trim());
  const commentLines = lines.filter((line) => /^\s*(#|\/\/|\/\*|\*|<!--)/.test(line)).length;
  const isPython = /\.py$/i.test(filename);
  const functions = isPython
    ? (text.match(/^\s*(?:async\s+)?def\s+\w+\s*\(/gm) || []).length
    : (text.match(/^\s*(?:[\w:<>,*&]+\s+)+\w+\s*\([^;{}]*\)\s*(?:\{|$)/gm) || []).length;
  const decisions = isPython
    ? (text.match(/\b(?:if|for|while|except)\b/g) || []).length
      + (text.match(/\band\b|\bor\b/g) || []).length
    : (text.match(/\b(?:if|else\s+if|for|while|case|catch)\b|&&|\|\|/g) || []).length;
  return [
    ["Total lines", lines.length],
    ["Non-empty lines", nonblank.length],
    ["Comment lines (approx.)", commentLines],
    ["Function/method count (approx.)", functions],
    ["Decision points (approx.)", decisions],
    ["Cyclomatic complexity estimate", nonblank.length ? decisions + 1 : 0],
    ["Analysis method", isPython ? "Python pattern scan (approx.)" : "Heuristic source scan"],
  ];
}

function riskLabel(score) {
  if (score >= 60) return "High – investigate";
  if (score >= 25) return "Moderate – review findings";
  if (score > 0) return "Low – review flagged items";
  return "No pattern detected";
}

function addMetric(container, label, value, accent = "cyan") {
  const card = document.createElement("article");
  card.className = `metric-card ${accent}`;
  const title = document.createElement("div");
  title.className = "metric-label";
  title.textContent = label;
  const content = document.createElement("div");
  content.className = "metric-value";
  content.textContent = value;
  card.append(title, content);
  container.append(card);
}

function renderTable(result) {
  const body = $("#frequency-rows");
  body.replaceChildren();
  for (const row of result.rows) {
    const tr = document.createElement("tr");
    const values = [
      row.character,
      row.frequency.toLocaleString(),
      row.probability.toFixed(5),
      row.contribution.toFixed(5),
      row.gradient.toFixed(5),
    ];
    for (const value of values) {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    }
    body.append(tr);
  }
}

function chartContext(canvas) {
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(rect.width * ratio));
  canvas.height = Math.max(1, Math.round(rect.height * ratio));
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  return { context, width: rect.width, height: rect.height };
}

function drawFrequencyChart(rows) {
  const { context: ctx, width, height } = chartContext($("#frequency-chart"));
  const values = rows.slice(0, 20);
  const padding = { top: 14, right: 12, bottom: 42, left: 36 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const max = Math.max(...values.map((row) => row.frequency), 1);
  ctx.font = "10px Segoe UI, sans-serif";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  for (let tick = 0; tick <= 4; tick += 1) {
    const value = max * tick / 4;
    const y = padding.top + plotHeight * (1 - tick / 4);
    ctx.strokeStyle = "rgba(132, 146, 172, .16)";
    ctx.beginPath(); ctx.moveTo(padding.left, y); ctx.lineTo(width - padding.right, y); ctx.stroke();
    ctx.fillStyle = "#8492ac";
    ctx.fillText(Math.round(value).toString(), padding.left - 7, y);
  }
  const slot = plotWidth / values.length;
  values.forEach((row, index) => {
    const barWidth = Math.max(2, slot * .58);
    const barHeight = plotHeight * row.frequency / max;
    const x = padding.left + index * slot + (slot - barWidth) / 2;
    const y = padding.top + plotHeight - barHeight;
    const gradient = ctx.createLinearGradient(0, y, 0, y + barHeight);
    gradient.addColorStop(0, "#38bdf8");
    gradient.addColorStop(1, "rgba(56, 189, 248, .28)");
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.roundRect(x, y, barWidth, barHeight, [3, 3, 0, 0]);
    ctx.fill();
    if (values.length <= 12 || index % 2 === 0) {
      ctx.save();
      ctx.translate(x + barWidth / 2, height - padding.bottom + 11);
      ctx.rotate(-Math.PI / 4);
      ctx.fillStyle = "#9ba8bf";
      ctx.textAlign = "right";
      ctx.fillText(row.character.slice(0, 8), 0, 0);
      ctx.restore();
    }
  });
}

function drawContributionChart(sorted) {
  const { context: ctx, width, height } = chartContext($("#contribution-chart"));
  const padding = { top: 17, right: 18, bottom: 37, left: 43 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const maxima = sorted.reduce((result, row) => ({
    x: Math.max(result.x, row.probability),
    y: Math.max(result.y, row.contribution),
  }), { x: 1e-6, y: 1e-6 });
  const maxX = maxima.x;
  const maxY = maxima.y;
  ctx.font = "10px Segoe UI, sans-serif";
  ctx.textAlign = "right";
  ctx.textBaseline = "middle";
  for (let tick = 0; tick <= 4; tick += 1) {
    const y = padding.top + plotHeight * (1 - tick / 4);
    ctx.strokeStyle = "rgba(132, 146, 172, .16)";
    ctx.beginPath(); ctx.moveTo(padding.left, y); ctx.lineTo(width - padding.right, y); ctx.stroke();
    ctx.fillStyle = "#8492ac";
    ctx.fillText((maxY * tick / 4).toFixed(2), padding.left - 7, y);
  }
  ctx.beginPath();
  sorted.forEach((row, index) => {
    const x = padding.left + row.probability / maxX * plotWidth;
    const y = padding.top + plotHeight - row.contribution / maxY * plotHeight;
    if (index === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#8b7cf6";
  ctx.lineWidth = 2;
  ctx.stroke();
  for (const row of sorted) {
    const x = padding.left + row.probability / maxX * plotWidth;
    const y = padding.top + plotHeight - row.contribution / maxY * plotHeight;
    ctx.beginPath(); ctx.arc(x, y, 2.5, 0, 2 * Math.PI);
    ctx.fillStyle = "#c4b5fd"; ctx.fill();
  }
  ctx.fillStyle = "#9ba8bf";
  ctx.textAlign = "center";
  ctx.textBaseline = "top";
  ctx.fillText("Character probability P(x)", padding.left + plotWidth / 2, height - 19);
}

function renderSecurity(result) {
  const container = $("#security-results");
  container.replaceChildren();
  $("#finding-count").textContent = `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}`;
  if (!result.findings.length) {
    const message = document.createElement("div");
    message.className = "empty-findings";
    message.textContent = "No configured patterns were detected. This does not guarantee that the input contains no sensitive information.";
    container.append(message);
    return;
  }
  const summary = document.createElement("p");
  summary.className = "finding-summary";
  summary.textContent = "Review these indicators. Some may be false positives; example values are masked.";
  const wrap = document.createElement("div");
  wrap.className = "table-wrap";
  const table = document.createElement("table");
  table.innerHTML = "<thead><tr><th>Finding</th><th>Severity</th><th>Location</th><th>Masked example</th></tr></thead>";
  const body = document.createElement("tbody");
  for (const finding of result.findings) {
    const tr = document.createElement("tr");
    for (const value of [finding.name, finding.severity, finding.location, finding.masked]) {
      const td = document.createElement("td");
      if (value === finding.severity) {
        const badge = document.createElement("span");
        badge.className = `severity severity-${finding.severity.toLowerCase()}`;
        badge.textContent = value;
        td.append(badge);
      } else {
        td.textContent = value;
      }
      tr.append(td);
    }
    body.append(tr);
  }
  table.append(body);
  wrap.append(table);
  container.append(summary, wrap);
}

function buildReport(result) {
  const lines = [
    "PROJECT 4.2 – TEXT/CODE COMPLEXITY & SECURITY ANALYSIS",
    "======================================================",
    `Input: ${result.name}`,
    `Generated: ${new Date().toLocaleString()}`,
    "",
    "SHANNON ENTROPY",
    "---------------",
    `Characters: ${result.length}`,
    `Unique characters: ${result.unique}`,
    `Approximate words: ${result.words}`,
    `Entropy: ${result.entropy.toFixed(5)} bits/character`,
    `Band: ${result.label}`,
    `Interpretation: ${result.meaning}`,
    `Mean numerical gradient: ${result.gradientMean.toFixed(6)}`,
    `Gradient range: ${result.gradientMin.toFixed(6)} to ${result.gradientMax.toFixed(6)}`,
    `Area under sorted probability-contribution curve: ${result.area.toFixed(8)}`,
    "",
    "SECURITY TRIAGE",
    "---------------",
    `Heuristic risk score: ${result.riskScore}/100`,
    `Classification: ${riskLabel(result.riskScore)}`,
    "Findings (examples are masked):",
    result.findings.length
      ? result.findings.map((item) => `${item.severity}: ${item.name} at ${item.location} (${item.masked})`).join("\n")
      : "No configured sensitive/obfuscation patterns detected.",
    "",
    "CODE COMPLEXITY (ESTIMATES)",
    "---------------------------",
    ...result.metrics.map(([key, value]) => `${key}: ${value}`),
    "",
    "LIMITATIONS",
    "-----------",
    "Entropy is not proof of encryption, malware, or a vulnerability. Pattern matching can",
    "produce false positives and cannot guarantee that secrets are absent. The risk score",
    "is an educational triage heuristic, not a certified security rating. Browser-side",
    "complexity metrics are approximate. Input is analysed locally and never executed.",
  ];
  return lines.join("\n");
}

function csvEscape(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

function download(filename, contents, type) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function renderDashboard(result) {
  currentResult = result;
  $("#empty-state").hidden = true;
  $("#dashboard").hidden = false;
  $("#analyzed-file").textContent = result.name;
  $("#summary-cards").replaceChildren();
  addMetric($("#summary-cards"), "Shannon entropy", `${result.entropy.toFixed(3)} bits/char`);
  addMetric($("#summary-cards"), "Characters", result.length.toLocaleString(), "purple");
  addMetric($("#summary-cards"), "Unique characters", result.unique.toLocaleString(), "green");
  addMetric($("#summary-cards"), "Heuristic risk score", `${result.riskScore}/100`, "amber");
  $("#entropy-label").textContent = result.label;
  $("#entropy-meaning").textContent = result.meaning;
  $("#risk-label").textContent = riskLabel(result.riskScore);
  $("#calculus-cards").replaceChildren();
  addMetric($("#calculus-cards"), "Mean numerical gradient", result.gradientMean.toFixed(5));
  addMetric($("#calculus-cards"), "Gradient range", `${result.gradientMin.toFixed(4)} to ${result.gradientMax.toFixed(4)}`, "purple");
  addMetric($("#calculus-cards"), "Area under curve", result.area.toFixed(7), "green");
  $("#complexity-cards").replaceChildren();
  result.metrics.forEach(([label, value], index) => {
    addMetric($("#complexity-cards"), label, value, ["cyan", "purple", "green"][index % 3]);
  });
  renderTable(result);
  renderSecurity(result);
  $("#report-preview").value = buildReport(result);
  requestAnimationFrame(() => {
    drawFrequencyChart(result.rows);
    drawContributionChart(result.sorted);
  });
}

function selectTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => {
    const selected = tab.dataset.tab === name;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-current", selected ? "page" : "false");
  });
  document.querySelectorAll(".tab-content").forEach((panel) => {
    panel.hidden = panel.id !== `tab-${name}`;
  });
  if (name === "entropy" && currentResult) {
    requestAnimationFrame(() => {
      drawFrequencyChart(currentResult.rows);
      drawContributionChart(currentResult.sorted);
    });
  }
}

function updateInputMeta() {
  inputMeta.textContent = input.value
    ? `${Array.from(input.value).length.toLocaleString()} characters`
    : "No input loaded";
}

$("#analyze-button").addEventListener("click", () => {
  const text = input.value;
  if (!text.trim()) {
    errorMessage.textContent = "Paste some text, upload a file, or load a sample before analyzing.";
    errorMessage.hidden = false;
    return;
  }
  if (Array.from(text).length > MAX_INPUT_CHARACTERS) {
    errorMessage.textContent = `Please limit input to ${MAX_INPUT_CHARACTERS.toLocaleString()} characters for responsive browser analysis.`;
    errorMessage.hidden = false;
    return;
  }
  errorMessage.hidden = true;
  renderDashboard(analyzeText(text, sourceName));
});

$("#load-sample").addEventListener("click", () => {
  const sample = samples[$("#sample-select").value];
  if (!sample) {
    errorMessage.textContent = "Choose a sample from the list first.";
    errorMessage.hidden = false;
    return;
  }
  input.value = sample.text;
  sourceName = sample.name;
  updateInputMeta();
  errorMessage.hidden = true;
});

input.addEventListener("input", () => {
  sourceName = "Pasted text";
  updateInputMeta();
  errorMessage.hidden = true;
});

fileInput.addEventListener("change", async () => {
  const file = fileInput.files?.[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    errorMessage.textContent = "Please choose a file smaller than 2 MB for responsive browser analysis.";
    errorMessage.hidden = false;
    fileInput.value = "";
    return;
  }
  try {
    input.value = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
    if (Array.from(input.value).length > MAX_INPUT_CHARACTERS) {
      input.value = "";
      errorMessage.textContent = `Please choose a file with no more than ${MAX_INPUT_CHARACTERS.toLocaleString()} characters.`;
      errorMessage.hidden = false;
      fileInput.value = "";
      updateInputMeta();
      return;
    }
    sourceName = file.name;
    updateInputMeta();
    errorMessage.hidden = true;
  } catch {
    errorMessage.textContent = "Could not read the file. Try a UTF-8 encoded text file.";
    errorMessage.hidden = false;
  }
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => selectTab(tab.dataset.tab));
});

$("#download-report").addEventListener("click", () => {
  if (currentResult) download("entropy_analysis_report.txt", buildReport(currentResult), "text/plain;charset=utf-8");
});
$("#download-frequency").addEventListener("click", () => {
  if (!currentResult) return;
  const headings = ["Character", "Frequency", "Probability", "Entropy contribution", "Numerical gradient"];
  const rows = currentResult.rows.map((row) => [
    row.character, row.frequency, row.probability, row.contribution, row.gradient,
  ]);
  download("character_probability_analysis.csv", [headings, ...rows].map((row) => row.map(csvEscape).join(",")).join("\r\n"), "text/csv;charset=utf-8");
});
$("#download-findings").addEventListener("click", () => {
  if (!currentResult) return;
  const headings = ["Finding", "Severity", "Location", "Masked example"];
  const rows = currentResult.findings.map((item) => [item.name, item.severity, item.location, item.masked]);
  download("security_findings.csv", [headings, ...rows].map((row) => row.map(csvEscape).join(",")).join("\r\n"), "text/csv;charset=utf-8");
});

window.addEventListener("resize", () => {
  if (currentResult && !$("#tab-entropy").hidden) {
    drawFrequencyChart(currentResult.rows);
    drawContributionChart(currentResult.sorted);
  }
});
