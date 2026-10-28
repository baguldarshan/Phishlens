const historyKey = "phishlens.scan-history.v1";
const $ = (selector) => document.querySelector(selector);
const form = $("#analyze-form");

function readHistory() {
  try { const value = JSON.parse(localStorage.getItem(historyKey) || "[]"); return Array.isArray(value) ? value : []; }
  catch { return []; }
}
function writeHistory(items) { try { localStorage.setItem(historyKey, JSON.stringify(items.slice(0, 20))); } catch { /* local history is optional */ } }
function escapeText(value) { return String(value).replace(/[&<>"']/g, (char) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#039;" })[char]); }
function setGauge(score, classification) {
  const gauge = $("#gauge-value"); const colors = { Low: "#15803d", Medium: "#d97706", High: "#dc2626", Invalid: "#98a2b3" };
  gauge.style.stroke = colors[classification] || "#ff6500";
  gauge.style.strokeDashoffset = String(314 - (314 * score / 100));
}
function renderFeatures(features) {
  const labels = [["original_url","Original URL"],["normalized_url","Normalized URL"],["scheme","Protocol"],["hostname","Hostname"],["registered_domain","Registered domain"],["subdomain","Subdomain"],["top_level_domain","Top-level domain"],["port","Port"],["path","Path"],["query_parameters","Query parameters"],["has_userinfo","User information"],["is_ip_hostname","IP hostname"],["url_length","URL length"]];
  $("#features").innerHTML = labels.map(([key,label]) => `<div><dt>${label}</dt><dd>${escapeText(features[key] === "" || features[key] === null ? "Not available" : features[key])}</dd></div>`).join("");
}
function renderRules(result) {
  $("#rule-count").textContent = `${result.triggered_rule_count} of ${result.total_rule_count} triggered`;
  $("#rules").innerHTML = result.rules.map((rule) => `<div class="rule ${rule.triggered ? "triggered" : ""}"><div class="rule-top"><strong>${escapeText(rule.name)}</strong><span class="rule-status">${rule.triggered ? "TRIGGERED" : "NOT TRIGGERED"}</span></div><div class="rule-meta">${escapeText(rule.category)} · ${escapeText(rule.severity)} · weight ${rule.weight}</div><p>${escapeText(rule.explanation)}</p></div>`).join("");
}
function renderHistory() {
  const items = readHistory(); const body = $("#history-body");
  if (!items.length) { body.innerHTML = '<tr><td colspan="6" class="empty">No scans yet. Your recent analyses will appear here.</td></tr>'; return; }
  body.innerHTML = items.map((item, index) => `<tr><td>${index + 1}</td><td class="url-cell">${escapeText(item.url)}</td><td><strong>${item.score}</strong> / 100</td><td><span class="history-badge ${item.classification.toLowerCase()}">${escapeText(item.classification)}</span></td><td>${escapeText(item.date)}</td><td><button class="remove-scan" data-index="${index}" aria-label="Remove scan">Remove</button></td></tr>`).join("");
}
function saveResult(result) {
  const items = readHistory(); items.unshift({ url: result.submitted_url, score: result.score, classification: result.classification, date: new Date().toLocaleString() }); writeHistory(items); renderHistory();
}
async function analyze(url) {
  $("#form-message").textContent = ""; $(".primary-button").disabled = true; $(".primary-button").textContent = "Analyzing...";
  try {
    const response = await fetch("/api/analyze", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url}) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error || result.summary || "Unable to analyze this URL.");
    $("#score").textContent = result.score; $("#classification").textContent = `${result.classification} Risk`;
    $("#summary").textContent = result.summary; $("#recommendation").textContent = result.recommendation;
    const badge = $("#status-badge"); badge.textContent = result.classification; badge.className = `badge ${result.classification.toLowerCase()}`;
    setGauge(result.score, result.classification); renderFeatures(result.features); renderRules(result); saveResult(result);
  } catch (error) { $("#form-message").textContent = error.message; }
  finally { $(".primary-button").disabled = false; $(".primary-button").innerHTML = 'Analyze URL <span>→</span>'; }
}
form.addEventListener("submit", (event) => { event.preventDefault(); analyze($("#url-input").value); });
document.querySelectorAll("[data-url]").forEach((button) => button.addEventListener("click", () => { $("#url-input").value = button.dataset.url; analyze(button.dataset.url); }));
$("#history-body").addEventListener("click", (event) => { const index = event.target.dataset.index; if (index === undefined) return; const items = readHistory(); items.splice(Number(index), 1); writeHistory(items); renderHistory(); });
$("#clear-history").addEventListener("click", () => { writeHistory([]); renderHistory(); });
$("#export-history").addEventListener("click", () => { const blob = new Blob([JSON.stringify(readHistory(), null, 2)], {type:"application/json"}); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = "phishlens-scan-history.json"; link.click(); URL.revokeObjectURL(link.href); });
renderHistory();
