// CyberGuard secure login endpoint.
// Deploy as a Supabase Edge Function named: secure-login
// Required function secrets: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
// The browser never receives the service-role key.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS"
};
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const anon = Deno.env.get("SUPABASE_ANON_KEY");
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !anon || !service) return json({ error: "Server configuration missing" }, 500);

  const body = await req.json().catch(() => null);
  const email = String(body?.email ?? "").trim();
  const password = String(body?.password ?? "");
  const source = String(body?.source ?? "LOCAL_CLIENT").trim().slice(0, 64) || "LOCAL_CLIENT";
  if (!/^\S+@\S+\.\S+$/.test(email) || !password) return json({ error: "Email and password are required." }, 400);

  const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: blockedUntil, error: blockError } = await admin.rpc("is_source_blocked", { p_source: source });
  if (blockError) return json({ error: "Unable to check source status." }, 500);
  if (blockedUntil) {
    // Record a real security event for the rejected login. Trusted sources are never inserted here because they cannot be blocked.
    const { data: profile } = await admin.from("profiles").select("id").eq("email", email.toLowerCase()).maybeSingle();
    await admin.from("security_events").insert({
      user_id: profile?.id ?? null,
      event_type: "BLOCKED_LOGIN",
      target: "/login",
      description: `Login rejected because source ${source} is temporarily blocked.`,
      severity: "HIGH",
      source
    });
    return json({ error: "Source temporarily blocked.", blocked_until: blockedUntil }, 423);
  }

  const auth = createClient(url, anon, { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } });
  const { data, error } = await auth.auth.signInWithPassword({ email, password });
  if (error) {
    if (error.status === 400 || error.code === "invalid_credentials") {
      const { data: profile } = await admin.from("profiles").select("id").eq("email", email.toLowerCase()).maybeSingle();
      await admin.from("security_events").insert({
        user_id: profile?.id ?? null,
        event_type: "FAILED_LOGIN",
        target: "/login",
        description: "Failed authentication attempt.",
        severity: "MEDIUM",
        source
      });
      return json({ error: "Invalid email or password." }, 401);
    }
    if (error.status === 429) return json({ error: "Too many attempts. Please wait a moment and try again." }, 429);
    return json({ error: "Unable to reach the authentication service." }, 502);
  }

  return json({
    access_token: data.session.access_token,
    refresh_token: data.session.refresh_token,
    expires_in: data.session.expires_in,
    user: { id: data.user.id, email: data.user.email }
  });
});

