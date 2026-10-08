let currentUser = null;

async function fetchRecentEvents() {
  const { data, error, count } = await sb.from("security_events").select("*", { count: "exact" })
    .order("created_at", { ascending: false }).limit(10); // RLS returns only this user's rows
  if (error) throw error;
  return { events: data, count };
}
async function loadActivity() {
  try {
    const { events, count } = await fetchRecentEvents();
    document.getElementById("count").textContent = count;
    document.getElementById("events").innerHTML = events.length
      ? events.map(e => `<tr><td class="mono">${esc(e.event_type)}</td><td><span class="badge ${esc(e.severity).toLowerCase()}">${esc(e.severity)}</span></td><td class="mono">${esc(e.target)}</td><td>${timeAgo(e.created_at)}</td></tr>`).join("")
      : '<tr><td colspan="4" class="empty">No security activity yet.</td></tr>';
  } catch (e) { console.error(e); showMessage("msg", "Could not load activity. Please try again."); }
}
// Real action: a round-trip request to the database (server_time()). The event is logged only if it succeeds.
async function runTestActivity() {
  const btn = document.getElementById("test-btn");
  btn.disabled = true; btn.textContent = "RUNNING...";
  try {
    const { data, error } = await sb.rpc("server_time");
    if (error) throw error;
    await logSecurityEvent(currentUser.id, "TEST_REQUEST", "/test-activity", "Test request completed. Server time: " + data, "LOW");
    showMessage("msg", "Test request completed and recorded.", "ok");
    await loadActivity();
  } catch (e) { console.error(e); showMessage("msg", "Test activity failed. Please try again."); }
  btn.disabled = false; btn.textContent = "TEST ACTIVITY";
}
async function initDashboard() {
  if (!sb) return window.location.replace("index.html");
  let session;
  try { ({ data: { session } } = await sb.auth.getSession()); } catch (e) { session = null; }
  if (!session) return window.location.replace("index.html"); // session protection
  currentUser = session.user;
  sb.auth.onAuthStateChange(ev => { if (ev === "SIGNED_OUT") window.location.replace("index.html"); });
  document.getElementById("welcome").textContent = "Welcome, " + currentUser.email;
  document.getElementById("last-login").textContent = new Date(currentUser.last_sign_in_at).toLocaleString();
  document.getElementById("test-btn").addEventListener("click", runTestActivity);
  document.getElementById("logout-btn").addEventListener("click", logout);
  document.getElementById("page").style.display = "block";
  const { data } = await sb.from("profiles").select("display_name").maybeSingle();
  document.getElementById("name").textContent = data?.display_name || "—";
  loadActivity();
}
initDashboard();
