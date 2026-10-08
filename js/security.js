// Security event helpers. The source is a persistent per-browser device identifier.
const TRUSTED_SOURCE = "browser-98fabb55";
function getSource() {
  try {
    let id = localStorage.getItem("cg_browser_id");
    if (!id) { id = "browser-" + crypto.randomUUID().slice(0, 8); localStorage.setItem("cg_browser_id", id); }
    return id;
  } catch (e) { return "LOCAL_CLIENT"; }
}
async function logSecurityEvent(userId, type, target, description, severity) {
  const { error } = await sb.from("security_events").insert({
    user_id: userId, event_type: type, target, description, severity, source: getSource() });
  if (error) throw error;
}
async function logFailedLogin(email) {
  const { error } = await sb.rpc("log_failed_login", { p_email: email, p_source: getSource() });
  if (error) throw error;
}
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function timeAgo(iso) {
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso)) / 1000));
  if (s < 60) return s + " seconds ago";
  if (s < 3600) return Math.floor(s / 60) + " minutes ago";
  if (s < 86400) return Math.floor(s / 3600) + " hours ago";
  return new Date(iso).toLocaleString();
}
function showMessage(id, text, type = "error") {
  const el = document.getElementById(id); if (!el) return;
  el.textContent = text; el.className = "msg show " + type;
}
