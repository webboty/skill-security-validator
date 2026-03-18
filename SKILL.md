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

Or by skill name:
```bash
python3 .opencode/skill/skill-security-validator/scripts/validate_security.py notebooklm
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

---

# LLM Instructions: Post-Scan Assessment

After running the validator, analyze the results and provide recommendations to the user:

## 1. Interpret Smart Analysis
The validator outputs a "smart_analysis" section with:
- `adjusted_risk_level` - Lower risk if findings are mostly documentation
- `context_notes` - Explanations about false positives
- `potential_libraries` - Library names found that should be verified

## 2. Provide Context to User
Always explain findings in plain language:
- What the risk means
- Why it might be a false positive (e.g., "this is in documentation explaining pip install")
- What action to take

## 3. Offer Follow-up Actions
After showing results, ALWAYS ask the user if they want:

**Option 1: Verify Libraries Online**
> "Would you like me to web search to verify if [library-name] is a legitimate library?"

If yes, search for the library to check:
- Is it a known legitimate package?
- Any security advisories?
- Is the source trusted (GitHub, PyPI, npm)?

**Option 2: Scan Downloaded Package**
> "Would you like me to scan the actual Python/npm package this skill installs?"

If yes, use webfetch or download the package and run validate_security.py on it.

## 4. How to Present Results (DYNAMIC!)

The validator returns a `potential_followups` array - ONLY ask about items that are IN this array!

### If potential_followups is EMPTY:
Simply state:
```
✅ All automated checks complete. This skill appears [SAFE/RISKY].
No further checks recommended at this time.
```

### If potential_followups has items:
Present ONLY those options that make sense:

```
🔍 Further verification available:
[For each item in potential_followups]:
[X]. [title]
    [description]
    Why: [why this might matter]

Just say the number!
```

## 5. What Was Already Checked

The report includes `checks_performed` showing what was already done:
- code_patterns: ✅ Always done
- network_calls: ✅ Always done  
- sensitive_files: ✅ Always done
- skill_instructions: ✅ Now done for ALL skill files (SKILL.md, references/, assets/, etc.)

## 6. Security Recommendations
Based on findings, provide actionable advice:
- If CRITICAL: Strongly recommend NOT using until expert review
- If HIGH: Suggest manual code review
- If MEDIUM: Note what patterns were found and why they're likely safe/risky
- If SAFE: Confirm it's likely safe to use

## Example Response Template

```
📊 SECURITY SCAN COMPLETE

[Skill Name]: [path]
[Risk Level]: [Score]/100

📝 Summary:
- Files scanned: [X]
- Code findings: [X] 
- Skill instruction issues: [X]

🔍 What was checked (all done automatically):
- ✅ Code patterns (subprocess, eval, etc.)
- ✅ Network calls  
- ✅ Sensitive file access
- ✅ ALL skill files for prompt injection

⚠️ Assessment:
[Plain language explanation]

✅ VERDICT: This skill appears [SAFE/RISKY] to use.

[If potential_followups has items]:
🔍 Want more verification?
1. [first option from potential_followups]
2. [second option...]

Just say the number (or "none" if done)!
```
```
