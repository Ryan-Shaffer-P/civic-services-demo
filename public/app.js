(function () {
  var STATUS = { received: ["Received", ""], progress: ["In progress", "progress"], done: ["Resolved", "done"] };
  var requests = [
    { id: "SR-2026-10482", kind: "Pothole or road damage", where: "Maple Ave and 4th St", when: "2 days ago", status: "progress" },
    { id: "SR-2026-10477", kind: "Streetlight out", where: "210 Harbor Rd", when: "3 days ago", status: "received" },
    { id: "SR-2026-10431", kind: "Water leak or sewer backup", where: "Cedar Ct", when: "6 days ago", status: "done" },
    { id: "SR-2026-10419", kind: "Sidewalk or curb damage", where: "88 Mill St", when: "8 days ago", status: "progress" },
    { id: "SR-2026-10402", kind: "Traffic signal or sign", where: "River Rd and Elm Ave", when: "10 days ago", status: "done" }
  ];

  var form = document.getElementById("request-form");
  var confirmBox = document.getElementById("confirm");
  var list = document.getElementById("recent-list");

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function renderRecent() {
    list.textContent = "";
    requests.slice(0, 6).forEach(function (r) {
      var li = el("li");
      var top = el("div", "top");
      top.appendChild(el("span", "kind", r.kind));
      top.appendChild(el("span", "pill " + STATUS[r.status][1], STATUS[r.status][0]));
      li.appendChild(top);
      li.appendChild(el("p", "where", r.where));
      li.appendChild(el("p", "meta", r.id + " \u00b7 " + r.when));
      list.appendChild(li);
    });
  }

  function setError(field, id, msg) {
    var err = document.getElementById("err-" + id);
    err.textContent = msg || "";
    if (field) {
      if (msg) field.setAttribute("aria-invalid", "true");
      else field.removeAttribute("aria-invalid");
    }
    return !msg;
  }

  function validate() {
    var f = form.elements;
    var first = null;
    function note(ok, node) { if (!ok && !first) first = node; }

    var cat = form.querySelector('input[name="category"]:checked');
    note(setError(null, "category", cat ? "" : "Choose the kind of problem."), form.querySelector('input[name="category"]'));
    note(setError(f.address, "address", f.address.value.trim() ? "" : "Enter a street address or cross streets."), f.address);
    note(setError(f.details, "details", f.details.value.trim().length >= 10 ? "" : "Describe the problem in at least 10 characters."), f.details);
    note(setError(f.name, "name", f.name.value.trim() ? "" : "Enter your name."), f.name);
    var emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(f.email.value.trim());
    note(setError(f.email, "email", emailOk ? "" : "Enter an email address like name@example.com."), f.email);

    if (first) first.focus();
    return !first;
  }

  function newId() {
    return "SR-2026-" + String(Math.floor(10500 + Math.random() * 89000));
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    if (!validate()) return;
    var f = form.elements;
    var cat = form.querySelector('input[name="category"]:checked').value;
    var where = f.address.value.trim();
    var id = newId();

    requests.unshift({ id: id, kind: cat, where: where, when: "just now", status: "received" });
    renderRecent();

    document.getElementById("confirm-num").textContent = id;
    document.getElementById("confirm-cat").textContent = cat;
    document.getElementById("confirm-where").textContent = where;
    document.getElementById("confirm-email").textContent = f.updates.checked ? f.email.value.trim() : "No email updates";

    form.hidden = true;
    confirmBox.hidden = false;
    confirmBox.focus();
  });

  form.addEventListener("input", function (e) {
    var t = e.target;
    if (t.name === "category") setError(null, "category", "");
    else if (t.id && document.getElementById("err-" + t.id)) setError(t, t.id, "");
  });

  document.getElementById("another").addEventListener("click", function () {
    form.reset();
    form.hidden = false;
    confirmBox.hidden = true;
    window.scrollTo({ top: document.getElementById("report").offsetTop - 16 });
    form.querySelector('input[name="category"]').focus();
  });

  document.getElementById("status-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var out = document.getElementById("status-result");
    var q = document.getElementById("req-num").value.trim().toUpperCase();
    if (!q) { out.textContent = "Enter the request number from your confirmation."; return; }
    var hit = requests.filter(function (r) { return r.id === q; })[0];
    out.textContent = hit
      ? hit.id + ": " + STATUS[hit.status][0] + " (" + hit.kind + ", " + hit.where + ")."
      : "No request found for " + q + ". Check the number and try again.";
  });

  renderRecent();
})();

/* Account: show who is signed in, prefill contact fields, log out */
(function () {
  var who = document.getElementById("who");
  var logout = document.getElementById("logout");
  fetch("/api/me", { credentials: "same-origin" })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (u) {
      if (!u) return;
      who.textContent = u.name;
      var f = document.getElementById("request-form").elements;
      if (!f.name.value) f.name.value = u.name;
      if (!f.email.value) f.email.value = u.email;
    });
  logout.addEventListener("click", function () {
    fetch("/api/logout", { method: "POST", credentials: "same-origin" })
      .finally(function () { window.location.href = "/login"; });
  });
})();

