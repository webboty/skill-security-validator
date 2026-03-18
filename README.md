# 🔒 Skill Security Validator

*The ultimate security scanner for AI agent skills and scripts - protect your AI agents from malicious code before it's too late.*

---

## ⚡ TL;DR

**Before installing ANY third-party skill or script, run this validator first.** It scans for malware, trojans, spyware, credential theft, reverse shells, and 200+ other attack patterns. Don't let a malicious skill compromise your AI agent.

---

## 🎯 Why You ABSOLUTELY Need This Skill!

### The Threat Is Real
**Your AI agent just installed a malicious skill.**

What if that "helpful" third-party skill contained a trojan? A keylogger? A reverse shell? With 341+ malicious skills discovered in 2025 alone (the ClawHavoc incident), blindly trusting skills is no longer safe.

### The Problem
Every time you install a skill from GitHub, ClawHub, or any marketplace, you're trusting code written by strangers. That "handy automation skill" could be:

- 😈 **Stealing your API keys and credentials**
- 🦠 **Installing malware on your machine**
- 👁️ **Keylogging everything you type**
- 📡 **Opening backdoors for attackers**
- ⛏️ **Using your GPU for crypto mining**
- 📡 **Exfiltrating your data to attacker's servers**

**You wouldn't install random executables from the internet. Why trust random AI skills?**

### The Solution
**Meet Skill Security Validator**

The only security scanner built specifically for AI agent skills and scripts. It detects:

- 🔴 **Malware**: Trojans, spyware, ransomware, rootkits, cryptominers
- 🔴 **Attack Tools**: Keyloggers, stealers, droppers, metasploit, cobalt strike
- 🔴 **Credential Theft**: .env stealing, SSH keys, AWS tokens, API keys
- 🔴 **Remote Access**: Reverse shells, bind shells, C2 communications
- 🔴 **Persistence**: Cron jobs, systemd services, Windows registry
- 🔴 **Obfuscation**: Base64 encoding, anti-debug, anti-VM detection

**200+ detection patterns** covering the entire attack kill chain.

### Why You'll Love It
- ✅ **Instant security scan** - Get results in seconds
- ✅ **Clear risk scoring** - SAFE → LOW → MEDIUM → HIGH → CRITICAL
- ✅ **Detailed findings** - Line numbers and explanations
- ✅ **Actionable recommendations** - Know exactly what to do
- ✅ **No false alarms** - Legitimate skills pass with no issues
- ✅ **Zero setup** - Just run and get results

**Used by security-conscious developers who:**
- Install skills from untrusted sources
- Evaluate open-source skills before use
- Audit internal skill libraries
- Verify skill supply chain
- Run CI/CD security gates

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| **Malware Detection** | 200+ keywords for trojans, spyware, ransomware, keyloggers |
| **Credential Protection** | Detects .env theft, SSH keys, API tokens, certificates |
| **Reverse Shell Detection** | Identifies remote access trojans and C2 communications |
| **Persistence Scanning** | Finds cron jobs, systemd, registry, startup entries |
| **Package Install Detection** | Warns about pip, npm, apt, brew installations |
| **Risk Scoring** | Quantified risk level from SAFE to CRITICAL |
| **Multi-Language** | Python, JavaScript, TypeScript, Bash, Go, Rust, Java |

---

## 🤖 OpenCode Integration

**The skill works directly inside OpenCode!**

### Option 1: Tell Your Agent
Just tell OpenCode to validate a skill:

> "Validate this skill for security issues: /path/to/skill"

> "Run security check on the skill at ~/skills/new-skill"

> "Is this skill safe? Check ~/downloads/some-skill for malware"

OpenCode will automatically use the skill-security-validator to scan and report findings.

### Option 2: Use the Dropdown
1. Type `/skills` in OpenCode
2. Select "skill-security-validator" from the dropdown
3. Tell it which skill to validate

### Option 3: Direct Command
```bash
python3 ~/.opencode/skill/skill-security-validator/scripts/validate_security.py /path/to/skill
```

---

## ⚡ Quick Start

### Install
```bash
git clone https://github.com/webboty/skill-security-validator.git ~/.opencode/skill/skill-security-validator
```

### Validate Any Skill
```bash
python3 ~/.opencode/skill/skill-security-validator/scripts/validate_security.py /path/to/skill-to-validate
```

**Before installing ANY new skill, run the validator first!**

---

## 🌍 Supported Locations

The validator automatically scans skills from **all major AI agents** across **all operating systems**:

### Global Locations (User's Home Directory)
| Agent | Path (macOS/Linux) | Path (Windows) |
|-------|-------------------|----------------|
| Claude Code | `~/.claude/skills/` | `%USERPROFILE%\.claude\skills\` |
| OpenCode | `~/.agents/skills/` | `%USERPROFILE%\.agents\skills\` |
| OpenCode Config | `~/.config/opencode/skills/` | `%APPDATA%\opencode\skills\` |
| Cursor | `~/.cursor/rules/` | `%USERPROFILE%\.cursor\rules\` |
| Windsurf | `~/.windsurf/skills.json` | `%USERPROFILE%\.windsurf\skills.json\` |
| Codex | `~/.codex/skills/` | `%USERPROFILE%\.codex\skills\` |
| Goose | `~/.goose/skills/` | `%USERPROFILE%\.goose\skills\` |
| Letta | `~/.letta/skills/` | `%USERPROFILE%\.letta\skills\` |
| Gemini CLI | `~/.gemini/cli/skills/` | `%USERPROFILE%\.gemini\cli\skills\` |
| KiloCode | `~/.kilocode/skills/` | `%USERPROFILE%\.kilocode\skills\` |

### Project Locations (Current Directory)
| Agent | Path |
|-------|------|
| Claude Code | `.claude/skills/` |
| OpenCode | `.agents/skills/` |
| OpenCode | `.opencode/skills/` |
| Cursor | `.cursor/rules/` |
| Windsurf | `.windsurf/skills.json` |
| GitHub | `.github/skills/` |
| Codex | `.codex/skills/` |
| Codex/通用 | `AGENTS.md` |
| Claude | `CLAUDE.md` |

---

## 📊 Risk Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🟢 SAFE | 0 | Ready to use |
| 🟡 LOW | 1-9 | Minor concerns |
| 🟠 MEDIUM | 10-29 | Exercise caution |
| 🔴 HIGH | 30-49 | Manual review required |
| ⛔ CRITICAL | 50+ | **DO NOT USE** |

---

## 🤖 Installing for Different AI Agents

### For Claude Code
```bash
# Clone to Claude Code skills folder
git clone https://github.com/webboty/skill-security-validator.git ~/.claude/skills/skill-security-validator
```
Then use it with `/skill-security-validator` in Claude Code.

### For OpenCode
```bash
git clone https://github.com/webboty/skill-security-validator.git ~/.opencode/skill/skill-security-validator
```

### For Cursor
```bash
git clone https://github.com/webboty/skill-security-validator.git ~/.cursor/rules/skill-security-validator
```

### For All Agents (using openskills)
```bash
npx openskills install webboty/skill-security-validator
```

---

## 💻 Usage

### Basic Scan
```bash
python3 validate_security.py /path/to/skill
```

### Scan and Get Exit Code
```bash
python3 validate_security.py /path/to/skill
# Exit 0 = SAFE/LOW, Exit 1 = MEDIUM, Exit 2 = HIGH/CRITICAL
```

### CI/CD Integration
```bash
if python3 validate_security.py ./my-skill; then
    echo "Security check passed - safe to install"
else
    echo "Security issues detected!"
    exit 1
fi
```

---

## 📝 Example Output

```json
{
  "target_path": "/path/to/suspicious-skill",
  "risk_level": "CRITICAL",
  "risk_score": 150,
  "total_findings": 11,
  "findings": [
    {
      "type": "malicious_keyword",
      "severity": "CRITICAL",
      "file": "script.py",
      "line": 9,
      "pattern": "Malicious/attack keyword: keylogger"
    },
    {
      "type": "sensitive_file_access",
      "severity": "HIGH",
      "file": "script.py",
      "line": 6,
      "pattern": ".env file - contains secrets/credentials"
    }
  ],
  "recommendation": "CRITICAL RISK - Strongly recommend NOT using this skill/script."
}
```

---

## 🛡️ Security First

**This skill validates BEFORE you install.**

Think of it as:
- 🏥 A security scanner for AI skills (like VirusTotal for files)
- 🔍 A linter for malicious patterns (like ESLint for code)
- 🚦 A gatekeeper before execution (like a pre-commit hook)

---

## 🤝 Contributing

Found a new attack pattern? PRs welcome!

1. Fork the repo
2. Add your pattern to `scripts/validate_security.py`
3. Submit a PR

---

## 📜 License

MIT - Free to use, modify, and distribute.

---

## ⚠️ Disclaimer

This tool helps identify potentially malicious code but cannot guarantee 100% detection. Always exercise caution when installing skills from untrusted sources. Use at your own risk.
