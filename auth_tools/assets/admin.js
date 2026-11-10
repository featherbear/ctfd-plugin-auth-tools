/*
 * auth_tools admin enhancements (served by /plugins/auth_tools/admin.js and
 * loaded only on admin pages).
 *
 * Adds an "External" badge next to the name of each user who signs in through
 * the reverse proxy or OpenID Connect. Normal password accounts get no
 * badge. Hovering the badge shows which method and the external ID.
 *
 * Pages: the admin user list (/admin/users) and a user's admin page
 * (/admin/users/<id>). Data comes from the admin-only identities API.
 *
 * On a linked user's page, the Edit User form also hides the password field
 * and the "require password change" checkbox: these accounts can't have a
 * password (the server refuses both). Email and everything else stay editable.
 */
(function () {
  var root = (window.init && window.init.urlRoot) || "";
  var path = location.pathname.slice(root.length);
  var onList = /^\/admin\/users\/?$/.test(path);
  var onUser = /^\/admin\/users\/\d+\/?$/.test(path);
  if (!onList && !onUser) return;

  var LABEL = "External";
  var METHODS = { header: "header claim", oidc: "OpenID Connect" };

  // Own colour, distinct from the admin theme's other badges (admin, verified,
  // hidden, banned), with over 4.5:1 text contrast.
  var CSS = ".auth-tools-external{background:#0b6e69;color:#fff}";

  function addStyles() {
    if (document.getElementById("auth-tools-admin-style")) return;
    var style = document.createElement("style");
    style.id = "auth-tools-admin-style";
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  function badge(identity) {
    var span = document.createElement("span");
    span.className = "badge auth-tools-external auth-tools-signin";
    span.textContent = LABEL;
    var title = "Signs in with " + METHODS[identity.via] + " as " + identity.subject;
    if (identity.via === "oidc") title += " (" + identity.provider + ")";
    span.title = title;
    span.setAttribute("aria-label", title);
    return span;
  }

  function load(query) {
    return fetch(root + "/api/v1/auth_tools/identities" + query, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(function (r) { return r.ok ? r.json() : { data: [] }; })
      .then(function (body) {
        var byUser = {};
        (body.data || []).forEach(function (i) { byUser[i.user_id] = i; });
        return byUser;
      });
  }

  function markList(byUser) {
    document.querySelectorAll("tr[name] td.team-name").forEach(function (cell) {
      var identity = byUser[cell.parentNode.getAttribute("name")];
      if (!identity || cell.querySelector(".auth-tools-signin")) return;
      // Right after the name link, before any affiliation or other badges.
      var name = cell.querySelector("a") || cell.firstChild;
      var b = badge(identity);
      name.insertAdjacentElement ? name.insertAdjacentElement("afterend", b) : cell.appendChild(b);
      b.insertAdjacentText("beforebegin", " ");
    });
  }

  function lockEditForm() {
    var form = document.getElementById("user-info-edit-form");
    if (!form) return;
    ["password", "change_password"].forEach(function (name) {
      var input = form.querySelector("[name=" + name + "]");
      if (!input) return;
      input.disabled = true; // never submitted
      if (input.type === "checkbox") input.checked = false;
      var group = input.closest(".form-group") || input.parentElement;
      group.style.display = "none";
    });
  }

  function markUser(byUser) {
    var id = window.USER_ID;
    var heading = document.getElementById("team-id");
    if (!id || !heading) return;
    if (!byUser[id]) return; // normal password account: nothing to mark
    lockEditForm();
    var row = heading.nextElementSibling;
    if (!row || row.querySelector(".auth-tools-signin")) return;
    row.insertBefore(badge(byUser[id]), row.firstChild);
    row.insertBefore(document.createTextNode(" "), row.firstChild.nextSibling);
  }

  function start() {
    addStyles();
    if (onList) load("").then(markList);
    else load("?user_id=" + encodeURIComponent(window.USER_ID)).then(markUser);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
