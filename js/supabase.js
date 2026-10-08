// Same Supabase project as CyberGuard SOC. Public/publishable key ONLY in browser code.
const SUPABASE_URL = "https://sqgbtmeafbvztwaexxyf.supabase.co";
const SUPABASE_ANON_KEY = "sb_publishable_f458get7aYPgMTPZDrrP8w_-4LZjDSG";
const CONFIGURED = !SUPABASE_URL.startsWith("YOUR_") && !SUPABASE_ANON_KEY.startsWith("YOUR_");
const sb = (CONFIGURED && window.supabase) ? window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY) : null;
