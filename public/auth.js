(function () {
  var SITEKEY = "0x4AAAAAAFInUXQcQ9cdKUFk"; // public by design
  var form = document.getElementById("auth-form");
  var errBox = document.getElementById("form-error");
  var signup = form.dataset.mode === "signup";
  var btn = form.querySelector('button[type="submit"]');
  var label = btn.textContent;
  var widgetId = null;
  var token = "";

  function clearErrors() {
    errBox.textContent = "";
    Array.prototype.forEach.call(form.elements, function (el) { el.removeAttribute("aria-invalid"); });
  }
  function fail(msg, field) {
    errBox.textContent = msg;
    if (field) { field.setAttribute("aria-invalid", "true"); field.focus(); }
    else errBox.focus();
    return false;
  }
  function resetButton() { btn.disabled = false; btn.textContent = label; }

  // Tokens are single-use: get a fresh one after every attempt
  function resetWidget() {
    token = "";
    if (widgetId !== null && window.turnstile) window.turnstile.reset(widgetId);
  }

  // Load Turnstile explicitly so we keep the widget id for resets
  window.onTurnstileLoad = function () {
    widgetId = window.turnstile.render("#turnstile-widget", {
      sitekey: SITEKEY,
      action: signup ? "signup" : "login",
      callback: function (t) { token = t; },
      "expired-callback": function () { token = ""; },
      "error-callback": function () {
        token = "";
        fail("The verification check could not load. Reload the page and try again.");
      }
    });
  };
  var s = document.createElement("script");
  s.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit";
  s.async = true;
  s.defer = true;
  s.onerror = function () { fail("The verification check could not load. Check your connection and reload."); };
  document.head.appendChild(s);

  form.addEventListener("input", clearErrors);

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    clearErrors();
    var f = form.elements;
    var email = f.email.value.trim();
    var password = f.password.value;

    if (signup && !f.name.value.trim()) return fail("Enter your name.", f.name);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail("Enter a valid email address.", f.email);
    if (!signup && !password) return fail("Enter your password.", f.password);
    if (signup && password.length < 10) return fail("Use at least 10 characters for your password.", f.password);
    if (signup && password !== f.confirm.value) return fail("The passwords don't match.", f.confirm);
    if (!token) return fail("Complete the verification check first.");

    var payload = signup
      ? { name: f.name.value.trim(), email: email, password: password }
      : { email: email, password: password };
    payload["cf-turnstile-response"] = token;

    btn.disabled = true;
    btn.textContent = signup ? "Creating account..." : "Signing in...";

    fetch(signup ? "/api/signup" : "/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, data: d }; });
      })
      .then(function (res) {
        if (res.ok) { window.location.href = "/"; return; }
        resetWidget();
        resetButton();
        fail(res.data.error || "Something went wrong. Try again.");
      })
      .catch(function () { resetWidget(); resetButton(); fail("Network error. Try again."); });
  });
})();
