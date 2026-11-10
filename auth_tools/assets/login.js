/*
 * auth_tools login page enhancements (served by /plugins/auth_tools/login.js).
 *
 * In OIDC mode:
 *   - login page: the SSO button comes first, followed by an "or" divider and
 *     a toggle that reveals CTFd's username/password form.
 *   - register page: the SSO button is shown above the registration form.
 *
 * Theme-agnostic: it looks for the form containing a password field, and waits
 * for it if the theme renders client-side (e.g. Svelte/React themes). It never
 * moves the theme's form; it only inserts siblings and hides the form with a
 * class, so framework-managed DOM stays intact.
 *
 * Styling hooks for themes: #auth-tools-sso, #auth-tools-divider,
 * #auth-tools-password-toggle, and .auth-tools-open on the toggle.
 *
 * The server replaces the placeholder below with the current settings.
 */
(function () {
  var config = __AUTH_TOOLS_CONFIG__;
  var EXPAND_KEY = "auth_tools_password_open";
  var HIDDEN_CLASS = "auth-tools-hidden";

  if (!config.enabled) return;
  var isLogin = location.pathname === config.loginPath;
  var isRegister = location.pathname === config.registerPath;
  if (!isLogin && !isRegister) return;

  var CSS = [
    "." + HIDDEN_CLASS + "{display:none!important}",
    "#auth-tools-sso{display:block;width:100%;margin-bottom:0;text-align:center}",
    "#auth-tools-divider{display:flex;align-items:center;gap:.75em;margin:1em 0;",
    "  font-size:.85em;text-transform:lowercase;opacity:.65}",
    "#auth-tools-divider::before,#auth-tools-divider::after{content:'';flex:1;",
    "  border-top:1px solid currentColor;opacity:.5}",
    "#auth-tools-password-toggle{display:flex;align-items:center;justify-content:center;",
    "  gap:.5em;width:100%;margin-bottom:1em;text-decoration:none;",
    // Bootstrap 5 themes: use body text/border colours instead of the low
    // contrast "secondary" grey, so it reads well in light and dark modes.
    // Themes without these variables keep their own button styling.
    "  --bs-btn-color:var(--bs-body-color);--bs-btn-border-color:var(--bs-border-color);",
    "  --bs-btn-hover-color:var(--bs-body-color);--bs-btn-hover-bg:var(--bs-tertiary-bg);",
    "  --bs-btn-hover-border-color:var(--bs-border-color);",
    "  --bs-btn-active-color:var(--bs-body-color);--bs-btn-active-bg:var(--bs-secondary-bg);",
    "  --bs-btn-active-border-color:var(--bs-border-color)}",
    "#auth-tools-password-toggle svg{width:1em;height:1em;flex:none;",
    "  transition:transform .2s ease}",
    "#auth-tools-password-toggle.auth-tools-open svg{transform:rotate(180deg)}",
    "@keyframes auth-tools-reveal{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}",
    ".auth-tools-reveal{animation:auth-tools-reveal .18s ease-out}",
    "@media (prefers-reduced-motion:reduce){#auth-tools-password-toggle svg{transition:none}",
    "  .auth-tools-reveal{animation:none}}",
  ].join("");

  var CHEVRON =
    '<svg viewBox="0 0 16 16" aria-hidden="true" focusable="false">' +
    '<path d="M3.5 6l4.5 4.5L12.5 6" fill="none" stroke="currentColor" ' +
    'stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function storage(fn) {
    try {
      return fn(window.sessionStorage);
    } catch (e) {
      return null;
    }
  }

  function addStyles() {
    if (document.getElementById("auth-tools-style")) return;
    var style = document.createElement("style");
    style.id = "auth-tools-style";
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  function ssoButton() {
    var next = new URLSearchParams(location.search).get("next");
    var a = document.createElement("a");
    a.id = "auth-tools-sso";
    a.className = "btn btn-primary btn-lg btn-block";
    a.href = config.url + (next ? "?next=" + encodeURIComponent(next) : "");
    a.textContent = config.buttonText;
    return a;
  }

  function enhance(form) {
    if (document.getElementById("auth-tools-sso")) return;
    addStyles();
    var parent = form.parentNode;
    var sso = ssoButton();

    if (isRegister) {
      sso.classList.add("mb-3");
      parent.insertBefore(sso, form);
      parent.insertBefore(document.createElement("hr"), form);
      return;
    }

    var divider = document.createElement("div");
    divider.id = "auth-tools-divider";
    divider.setAttribute("role", "separator");
    divider.textContent = config.dividerText;

    if (!form.id) form.id = "auth-tools-password-form";
    var toggle = document.createElement("button");
    toggle.type = "button";
    toggle.id = "auth-tools-password-toggle";
    toggle.className = "btn btn-outline-secondary btn-block";
    toggle.setAttribute("aria-controls", form.id);
    var label = document.createElement("span");
    label.textContent = config.toggleText;
    toggle.appendChild(label);
    toggle.insertAdjacentHTML("beforeend", CHEVRON);

    parent.insertBefore(sso, form);
    parent.insertBefore(divider, form);
    parent.insertBefore(toggle, form);

    function setOpen(open, interactive) {
      form.classList.toggle(HIDDEN_CLASS, !open);
      toggle.classList.toggle("auth-tools-open", open);
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      // With the form open, its own submit button is the primary action.
      sso.classList.toggle("btn-primary", !open);
      sso.classList.toggle("btn-outline-primary", open);
      if (open && interactive) {
        form.classList.remove("auth-tools-reveal");
        void form.offsetWidth; // restart the animation
        form.classList.add("auth-tools-reveal");
        var first = form.querySelector("input:not([type=hidden])");
        if (first) first.focus();
      }
    }

    toggle.addEventListener("click", function () {
      setOpen(form.classList.contains(HIDDEN_CLASS), true);
    });

    // Re-open after a password attempt so CTFd's error is next to the form.
    form.addEventListener("submit", function () {
      storage(function (s) { s.setItem(EXPAND_KEY, "1"); });
    });
    var reopen = storage(function (s) {
      var v = s.getItem(EXPAND_KEY);
      s.removeItem(EXPAND_KEY);
      return v;
    });

    setOpen(Boolean(reopen) || location.hash === "#password", false);
  }

  function findForm() {
    var password = document.querySelector("form input[name=password]");
    return password && password.form;
  }

  function start() {
    var form = findForm();
    if (form) return enhance(form);
    // Client-rendered themes may add the form after this script runs.
    var observer = new MutationObserver(function () {
      var f = findForm();
      if (f) {
        observer.disconnect();
        enhance(f);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
    setTimeout(function () { observer.disconnect(); }, 10000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
