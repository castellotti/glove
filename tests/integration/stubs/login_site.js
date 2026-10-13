// A stand-in single-sign-on site for test_playwright_login.sh (node, no deps;
// runs in the session's playwright image). Plain HTTP on argv[2] (default 80).
//
//   idp.corp.test/login   a sign-in: n += 1, the SSO cookie sso=sso-tok-<n> for
//                         the parent domain (Domain=corp.test, HttpOnly) and a
//                         script-readable one, pref=pref-tok-<n>, then
//                         302 → tracker.test/hop
//   tracker.test/hop      a cookie of a host the session doesn't name (tk),
//                         then 302 → app.chat.test/
//   app.chat.test/        a chat app: its cookie d=xoxd-<n>-test (Domain=chat.test)
//                         and localStorage cfg = {"token": "xoxc-<n>-test"};
//                         the page then fetches /done, logged `done login=<n>`
//   wiki.corp.test/whoami a resource: "signed in as user-<n>" for a right sso
//                         cookie, else "not signed in" (its title); logged
//                         `whoami sso=login-<n>|wrong|none` (never a value)
//
// Every request is logged as `<method> <host> <path> cookies=<names>`.
const http = require("http");

let n = 0;
http.createServer((req, res) => {
  const host = (req.headers.host || "").split(":")[0];
  const cookies = {};
  for (const c of (req.headers.cookie || "").split(/;\s*/).filter(Boolean)) {
    const i = c.indexOf("=");
    cookies[c.slice(0, i)] = c.slice(i + 1);
  }
  console.log(`${req.method} ${host} ${req.url} cookies=${Object.keys(cookies).sort().join(",")}`);
  const send = (code, body, headers = {}) => {
    res.writeHead(code, { "Content-Type": "text/html", "Cache-Control": "no-store", ...headers });
    res.end(body);
  };
  if (host === "idp.corp.test" && req.url === "/login") {
    n += 1;
    return send(302, "", { "Set-Cookie": [`sso=sso-tok-${n}; Domain=corp.test; Path=/; HttpOnly; Max-Age=7200`,
                                          `pref=pref-tok-${n}; Domain=corp.test; Path=/; Max-Age=7200`],
                           Location: "http://tracker.test/hop" });
  }
  if (host === "tracker.test") {
    return send(302, "", { "Set-Cookie": "tk=tracker-1; Path=/; Max-Age=3600", Location: "http://app.chat.test/" });
  }
  if (host === "app.chat.test" && req.url === "/") {
    return send(200, `<script>localStorage.setItem("cfg", JSON.stringify({token: "xoxc-${n}-test"}));
                       fetch("/done");</script><h1>chat</h1>`,
                { "Set-Cookie": `d=xoxd-${n}-test; Domain=chat.test; Path=/; Max-Age=3600` });
  }
  if (host === "app.chat.test" && req.url === "/done") {
    console.log(`done login=${n}`);
    return send(200, "ok");
  }
  if (host === "wiki.corp.test" && req.url === "/whoami") {
    const m = /^sso-tok-(\d+)$/.exec(cookies.sso || "");
    console.log(`whoami sso=${m ? "login-" + m[1] : cookies.sso ? "wrong" : "none"}`);
    // in the title too: the MCP's result shows the title, the snapshot is a file
    const who = m ? `signed in as user-${m[1]}` : "not signed in";
    return send(200, `<title>${who}</title><h1>${who}</h1>`);
  }
  send(404, "no");
}).listen(Number(process.argv[2] || 80), "0.0.0.0");
