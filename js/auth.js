// CyberGuard Test Server authentication.
// Login continues to use the existing secure-login Edge Function.
// Existing security event logging is preserved.

const LOGIN_FUNCTION = "secure-login";


async function handleLogin(ev) {

  ev.preventDefault();

  const email =
    document.getElementById("email").value.trim();

  const password =
    document.getElementById("password").value;

  const btn =
    document.getElementById("login-btn");

  btn.disabled = true;
  btn.textContent = "SIGNING IN...";

  try {

    const source = getSource();

    const res = await fetch(
      `${SUPABASE_URL}/functions/v1/${LOGIN_FUNCTION}`,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          apikey: SUPABASE_ANON_KEY
        },

        body: JSON.stringify({
          email,
          password,
          source
        })
      }
    );

    const payload =
      await res.json().catch(() => ({}));


    if (!res.ok) {

      if (res.status === 423) {

        const mins = Math.max(
          1,
          Math.ceil(
            (
              new Date(payload.blocked_until) -
              Date.now()
            ) / 60000
          )
        );

        showMessage(
          "msg",
          `This source is temporarily blocked. Try again in about ${mins} minute${mins === 1 ? "" : "s"}.`
        );

      } else if (res.status === 401) {

        showMessage(
          "msg",
          "Invalid email or password."
        );

      } else if (res.status === 429) {

        showMessage(
          "msg",
          "Too many attempts. Please wait a moment and try again."
        );

      } else {

        showMessage(
          "msg",
          payload.error ||
          "Unable to sign in right now. Please try again."
        );

      }

      return;
    }


    const { error: sessionError } =
      await sb.auth.setSession({
        access_token: payload.access_token,
        refresh_token: payload.refresh_token
      });

    if (sessionError)
      throw sessionError;


    try {

      await logSecurityEvent(
        payload.user.id,
        "LOGIN_SUCCESS",
        "/login",
        "Successful user authentication.",
        "LOW"
      );

    } catch (e) {

      console.error(
        "Event logging failed",
        e
      );

    }


    window.location.href =
      "dashboard.html";


  } catch (e) {

    console.error(e);

    showMessage(
      "msg",
      "Connection error. Please check your network and try again."
    );

  } finally {

    btn.disabled = false;

    btn.textContent =
      "LOGIN TO TEST ENVIRONMENT";
  }
}


/* =========================================================
   LOGOUT
   ========================================================= */

async function logout() {

  try {

    const { data } =
      await sb.auth.getSession();

    if (data.session) {

      await logSecurityEvent(
        data.session.user.id,
        "LOGOUT",
        "/logout",
        "User logged out.",
        "LOW"
      );

    }

  } catch (e) {

    console.error(
      "Event logging failed",
      e
    );

  }

  await sb.auth.signOut();

  window.location.href =
    "index.html";
}


/* =========================================================
   LOGIN PAGE INITIALIZATION
   ========================================================= */

async function initLoginPage() {

  const form =
    document.getElementById("login-form");

  if (!form)
    return;


  if (!sb) {

    showMessage(
      "msg",
      "Supabase configuration required. Edit js/supabase.js (see README)."
    );

    const button =
      document.getElementById("login-btn");

    if (button)
      button.disabled = true;

    return;
  }


  form.addEventListener(
    "submit",
    handleLogin
  );


  try {

    const { data } =
      await sb.auth.getSession();

    if (data.session) {

      const continueBox =
        document.getElementById("continue");

      if (continueBox)
        continueBox.style.display = "block";

      const emailInput =
        document.getElementById("email");

      if (emailInput)
        emailInput.value =
          data.session.user.email || "";

    }

  } catch (e) {

    showMessage(
      "msg",
      "Session error. Please log in again."
    );

  }
}


initLoginPage();