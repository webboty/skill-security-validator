---
name: skill-security-validator
description: Validates third-party skills and scripts for security vulnerabilities, malicious code patterns, and suspicious behavior. Use when: (1) Installing or auditing new 3rd party skills from external sources, (2) Reviewing scripts before execution, (3) Checking skills for dangerous patterns like shell execution, network calls, credential access, or file system manipulation, (4) Performing security audits on AI agent capabilities.
---

# Skill Security Validator

Analyzes skills and scripts for security risks before installation or use.

## Usage

```bash
python3 .opencode/skill/skill-security-validator/scripts/validate_security.py <path-to-skill-or-script>
```

## What It Checks

### Malicious Keywords (CRITICAL)
- Malware: trojan, spyware, ransomware, rootkit, worm, cryptominer
- Attack tools: keylogger, stealer, dropper, injector, packer
- Attack techniques: pass the hash, mimikatz, metasploit, cobalt strike
- Evasion: anti-debug, anti-vm, stealth mode, obfuscate, FUD

### Sensitive File Access (HIGH)
- `.env` files (credentials, API keys)
- `.ssh/` directory (private keys)
- `.aws/credentials` (AWS keys)
- `.kube/config` (Kubernetes config)
- `credentials.json`, `service-account.json`
- Certificate/key files: `.pem`, `.key`, `.crt`

### Dangerous Patterns (HIGH)
- Shell execution: `os.system()`, `subprocess.call/run/Popen()`
- Code execution: `exec()`, `eval()`
- Dynamic imports: `__import__("os")`, `__import__("subprocess")`
- Deserialization: `pickle.load()`, `marshal.load()`, unsafe YAML
- PTY manipulation: `pty.spawn` (possible reverse shell)
- Network sockets: Raw socket creation, outbound connections

### Package Installation
- `pip install`, `pip.main()`
- `npm install`, `yarn add`
- `apt-get install`, `yum install`, `brew install`

### Persistence Mechanisms
- Cron jobs, systemd services, launchd
- Windows registry, startup entries
- Task scheduling

### Network Access (MEDIUM)
- HTTP/HTTPS, WebSocket, FTP
- SMTP/POP3/IMAP, socket connections

## Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| SAFE | 0 | OK to use |
| LOW | 1-9 | Minor concerns - review |
| MEDIUM | 10-29 | Exercise caution |
| HIGH | 30-49 | Do not use without review |
| CRITICAL | 50+ | Strongly recommend NOT using |

## Exit Codes

- 0: SAFE or LOW risk
- 1: MEDIUM risk
- 2: HIGH or CRITICAL risk
