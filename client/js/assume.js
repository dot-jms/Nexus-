// "Be someone" support. MUST load first. When this tab was switched into another account (sessionStorage flag),
// localStorage is redirected to a private prefix so the admin's own cached data is never touched.
(function () {
  let A = null; try { A = JSON.parse(sessionStorage.getItem('nx-assume') || 'null'); } catch (_) {}
  window.NX_ASSUME = A;
  if (!A) return;
  const sp = Storage.prototype, g = sp.getItem, s = sp.setItem, r = sp.removeItem, L = window.localStorage, P = 'as:';
  sp.getItem = function (k) { return g.call(this, this === L ? P + k : k); };
  sp.setItem = function (k, v) { return s.call(this, this === L ? P + k : k, v); };
  sp.removeItem = function (k) { return r.call(this, this === L ? P + k : k); };
  window.nxAssumeExit = function () {
    try { sessionStorage.setItem('nx-session', A.real); sessionStorage.removeItem('nx-assume'); } catch (_) {}
    location.reload();
  };
  document.addEventListener('DOMContentLoaded', function () {
    const b = document.createElement('div');
    b.style.cssText = 'position:fixed;top:6px;left:50%;transform:translateX(-50%);z-index:2147483000;display:flex;align-items:center;gap:10px;padding:5px 6px 5px 14px;border-radius:99px;background:linear-gradient(135deg,#5865f2,#c084fc);color:#fff;font:600 12px system-ui,sans-serif;box-shadow:0 4px 18px rgba(0,0,0,.45);animation:nxa .3s ease';
    b.innerHTML = '<style>@keyframes nxa{from{opacity:0;transform:translate(-50%,-14px)}}</style><span>🎭 You are <b></b> — everything you do is as them</span><button style="border:0;border-radius:99px;padding:4px 12px;font:700 12px system-ui;cursor:pointer;background:#fff;color:#4338ca">Exit</button>';
    b.querySelector('b').textContent = A.name;
    b.querySelector('button').onclick = window.nxAssumeExit;
    document.body.appendChild(b);
  });
})();
