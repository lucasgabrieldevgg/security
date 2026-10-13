# Injection — SQL, command, XSS, path, template, deserialization

The interpreter family. One rule covers them all: **an interpreter (SQL, shell, HTML, a file path, a template, a deserializer) never receives a string you built by concatenating anything dynamic.** Guards are parameterization, context-correct encoding, or allow-lists — in that order of preference.

This file is the deep reference: what each class **is and is not** (false positives waste everyone's trust), vulnerable-vs-secure patterns per stack, and the taint-tracing method for audits.

> Upstream credit: the is/is-not discipline, taint-tracing procedure, and batched verification merged from `utkusen/sast-skills` (MIT); category catalog and CWE anchors from `bridge-mind/BridgeSecurity` (MIT); dangerous-sink awareness from `allsmog/vuln-scout` (MIT). See `/ATTRIBUTION.md`.

---

## SQL injection (CWE-89 — OWASP A03)

### What it IS

- Concatenation or interpolation of anything dynamic into a query string: `"... WHERE id = " + id`, `f"... '{name}'"`, `` `... ${id}` ``
- String-formatting functions used to build the query: `%` formatting, `.format()`, `String.format`, `sprintf`
- ORM raw/unsafe methods with a dynamic string: `objects.raw(f"…")`, `where("col = '" + v + "'")`, `$queryRawUnsafe(…)`, `FromSqlRaw("…" + v)`, `extra(where=[f"…"])`, `literal(v)`
- **Dynamic identifiers** — a variable used as column/table name or `ORDER BY` value: parameterization cannot protect identifiers; only an allow-list can
- **Second-order** — input stored in the DB earlier (by a "safe" write path) later interpolated into a raw query

### What it is NOT (do not flag)

- Parameterized calls with a static string: `execute("… WHERE id = %s", (val,))`, `query("… ?", [val])`, `prepare` + bind
- ORM query builders: `.filter()`, `.where(col: val)`, `.findUnique()`, Prisma `$queryRaw` **tagged-template** form
- IDOR (id swapping) — that's access control, class 1, not injection
- XSS-via-database (a stored `<script>` rendered unescaped) — the sink there is HTML, not SQL

### Fix patterns per stack

```python
# Python — bind, never interpolate
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# SQLAlchemy
db.session.execute(text("… WHERE name = :name"), {"name": name})
```

```javascript
// Node — placeholders (mysql2 ?, pg $1)
db.query('SELECT * FROM users WHERE email = $1', [email]);
// Prisma raw — tagged template only
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`;
```

```go
// Go — database/sql
row := db.QueryRow("SELECT * FROM users WHERE id = $1", userID)
```

```java
// Java — PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```

```php
// PHP — PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $userId]);
```

**Dynamic identifiers** (the case parameterization cannot fix):

```python
ALLOWED_SORT = {'name', 'price', 'created_at'}
sort_col = req.args.get('sort', 'name')
if sort_col not in ALLOWED_SORT:
    abort(400)                      # allow-list gates it; only then interpolate
cursor.execute(f"SELECT * FROM products ORDER BY {sort_col}")
```

Custom escaping (`addslashes`, `mysql_real_escape_string`, homegrown sanitizers) is **not** a fix — classify as vulnerable and parameterize.

## Command injection (CWE-78, CWE-77 — OWASP A03)

### What it IS

- `child_process.exec("convert " + file)` — shell string with any dynamic part
- `os.system(f"ffmpeg -i {path}")`, `` exec(`git ${branch}`) ``, `Runtime.exec("… " + x)` string form
- `eval`, `new Function`, `Function()` on anything derived from input; `pickle.loads` / `Marshal.load` / `yaml.load` (non-safe) / `node-serialize` / Java `ObjectInputStream` on untrusted bytes (deserialization is code execution with extra steps — CWE-502)
- Template engines fed user text as template source: Jinja `Template(user_input)`, `render_template_string`, Mustache/Handlebars from input (SSTI, CWE-1336/94)

### What it is NOT

- `execFile("convert", [file])` / `spawn` with an **argv array** — no shell in the loop
- `eval` on a hardcoded string in a test fixture with no input path
- `yaml.safe_load`, JSON parse of plain data

### Fix patterns

```javascript
// ✗ exec(`convert ${path}`)      ✓ argv array, no shell
execFile('convert', [path], (err, out) => { /* … */ });
```

```python
# ✗ os.system(f"ffmpeg -i {path}")   ✓ subprocess with list
subprocess.run(["ffmpeg", "-i", path], check=True)
```

For templates: render user data **as values** (`render_template_string(tpl, name=user_name)`), never splice it into the template source. For deserialization: never deserialize untrusted bytes with format-preserving loaders; use JSON, and validate the shape.

## XSS (CWE-79 — OWASP A03)

### What it IS

- `element.innerHTML = userText`, `dangerouslySetInnerHTML={{__html: userText}}`, `v-html`, Svelte `{@html}`
- DOM sinks fed by URL fragments: `location.hash` → `innerHTML`, `document.write`
- Markdown/rich-text rendered raw (`marked()` with no sanitizer; `rehype-raw` on input)
- Reflected error/validation messages that echo input back as HTML

### What it is NOT (precision gate)

- `innerHTML = '<b>Done</b>'` with a **static literal** — no data path
- React `{userText}` / Vue `{{ }}` / `textContent` — framework auto-escaping doing its job
- `Math.random()` in UI animation — not crypto, but not XSS either (it's a crypto-context smell only)

### Fix patterns

- Default to `textContent` and framework interpolation; `innerHTML` only for trusted, static markup.
- Rich text from users: sanitize server-side with an allow-list sanitizer (e.g., DOMPurify config) and render through the same policy.
- Add CSP as the second layer (see `secrets-config.md`) — a backstop, never the fix.

## Path traversal (CWE-22 — OWASP A01/A03)

### What it IS

`fs.readFile('/data/' + req.query.name)` → `?name=../../etc/passwd`; `send_file(params[:path])`; `path.join(base, userInput)` unchecked; zip extraction with entry names (`../` inside archives).

### Fix patterns

```javascript
// allow-list the name shape, then contain the resolve
const name = path.basename(req.query.name);          // strips any directory component
const full = path.resolve(BASE, name);
if (!full.startsWith(path.resolve(BASE) + path.sep)) throw new Error('bad path');
```

- Prefer allow-listed filenames or generated ids mapped server-side to real paths.
- For archives: canonicalize each entry name, reject absolute paths and `..`, cap extraction size and count.

## SSRF (CWE-918 — OWASP A10)

### What it IS

Server-side `fetch`/`requests`/`http.get` where scheme, host, or full URL derives from user input — link preview, "import by URL", webhook test buttons, image proxies. Targets that matter: cloud metadata IPs (`169.254.169.254`), localhost/admin panels, internal RFC1918 ranges, redirect chains that bounce back into them, and DNS-rebinding tricks.

### Fix pattern

```javascript
async function safeFetch(rawUrl, { allowHosts } = {}) {
  const u = new URL(rawUrl);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('scheme');
  if (allowHosts && !allowHosts.includes(u.hostname)) throw new Error('host');
  const ip = (await dns.promises.lookup(u.hostname)).address;
  if (isPrivateOrLoopback(ip)) throw new Error('private range'); // incl. 169.254.0.0/16
  const r = await fetch(u, { redirect: 'error', signal: AbortSignal.timeout(10_000) });
  // cap response size before reading the body
}
```

Block the resolved IP's range (not the hostname — that's the rebinding hole), pin the protocol, refuse redirects, cap size and time.

---

## Auditing this family: the taint-trace method

When auditing existing code (see `the-audit.md` for the full workflow), injection classes get the deep treatment because they hide behind helpers:

1. **Recon (structural).** Grep for sinks: `execute(`, `query(`, `raw(`, `exec(`, `eval(`, `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `pickle.loads`, `yaml.load`, `readFile(`, `fetch(`. Flag every **dynamically built** argument — you are not yet tracing who controls it; that's the next step's job.
2. **Trace (per site).** Walk each dynamic variable backwards to its origin:
   - *Direct input* — query/path/body/header/cookie → real
   - *Indirect* — via helper returns, class state, conditionals → follow every branch and setter
   - *Second-order* — read from DB → find the write site; was it user-controlled?
   - *Server-side constant* — config/env/hardcoded → not exploitable (still note it: it rots into a vuln the day someone parametrizes it)
3. **Classify.** *Vulnerable* (input reaches sink, no guard) / *Likely vulnerable* (indirect flow, or only weak escaping) / *Not vulnerable* (server-only, or true parameterization) / *Needs manual review* (opaque helpers). When in doubt between the last two: manual review — **false negatives are worse than false positives in security**.
4. **Verify precision.** Read 10–20 lines of context around the match before reporting: dead code, commented-out code, and test fixtures are not findings. One consolidated finding per distinct bug — locations can be many, the bug is one.

**The one-lift rule for fixes:** fix the sink (parameterize / argv / encode / allow-list), then sweep for the same construction pattern across the repo — sibling branches, other methods on the same resource, duplicated handlers, and non-HTTP entry points (CLI, cron, queue consumers) that reach the same query but bypass the route's auth.
