export function parseSetCookie(header) {
  if (typeof header !== "string" || !header.trim()) throw new Error("Enter one Set-Cookie header.");
  const parts = header.split(";").map(part => part.trim()).filter(Boolean);
  const firstEquals = parts[0].indexOf("=");
  if (firstEquals <= 0) throw new Error("The first segment must be a cookie name and value.");
  const cookie = {name: parts[0].slice(0, firstEquals), value: parts[0].slice(firstEquals + 1), attributes: {}};
  for (const part of parts.slice(1)) {
    const index = part.indexOf("=");
    const name = (index === -1 ? part : part.slice(0, index)).toLowerCase();
    cookie.attributes[name] = index === -1 ? true : part.slice(index + 1);
  }
  return cookie;
}

export function examineCookie(header, context = "https") {
  const cookie = parseSetCookie(header);
  const a = cookie.attributes;
  const findings = [];
  const add = (severity, title, detail) => findings.push({severity, title, detail});
  if (context === "https" && !a.secure) add("high", "Secure is missing", "Production cookies should not travel over an unencrypted HTTP connection.");
  if (!a.httponly) add("medium", "HttpOnly is missing", "If JavaScript does not need the value, HttpOnly reduces exposure to script-based theft.");
  if (!a.samesite) add("medium", "SameSite is implicit", "Set an explicit SameSite policy so cross-site behavior is intentional and reviewable.");
  if (String(a.samesite).toLowerCase() === "none" && !a.secure) add("critical", "SameSite=None requires Secure", "Modern browsers reject or restrict this combination.");
  if (a.domain) add("review", "Domain broadens scope", `The cookie may be sent to ${a.domain} and matching subdomains; host-only scope is narrower.`);
  if (a.path && a.path !== "/") add("info", "Path is not a security boundary", "Path controls sending behavior but does not isolate a cookie from other scripts on the origin.");
  if (cookie.name.startsWith("__Host-")) {
    if (!a.secure || a.path !== "/" || a.domain) add("critical", "__Host- prefix rules are not satisfied", "A __Host- cookie requires Secure, Path=/, and no Domain attribute.");
    else add("good", "__Host- prefix is correctly configured", "The prefix enforces a host-only, root-path, Secure cookie in supporting browsers.");
  }
  if (cookie.name.startsWith("__Secure-") && !a.secure) add("critical", "__Secure- requires Secure", "The prefix is only valid when the Secure attribute is present.");
  const harmful = findings.filter(item => ["critical", "high", "medium"].includes(item.severity));
  const score = Math.max(0, 100 - findings.reduce((sum, item) => sum + ({critical:35,high:25,medium:12,review:5,info:0,good:0}[item.severity] || 0), 0));
  const label = harmful.length === 0 ? "Healthy baseline" : score >= 70 ? "Needs review" : "Needs treatment";
  if (!findings.length) add("good", "No baseline issue found", "Configuration still depends on the application's threat model and session design.");
  return {cookie, score, label, findings, disclaimer:"This checks header configuration, not the security of the application or session lifecycle."};
}
