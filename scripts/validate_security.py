#!/usr/bin/env python3
"""
Security validator for skills and scripts.
Analyzes third-party skills/scripts for malicious code patterns.
"""

import os
import re
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Any


class SecurityValidator:
    DANGEROUS_PATTERNS = [
        (r"os\.system\s*\(", "Shell execution via os.system"),
        (r"subprocess\.(call|run|Popen)\s*\(", "Shell execution via subprocess"),
        (r"exec\s*\(", "Direct code execution"),
        (r"eval\s*\(", "Code evaluation"),
        (r"__import__\s*\(\s*['\"]os['\"]", "Dynamic os import"),
        (r"__import__\s*\(\s*['\"]subprocess", "Dynamic subprocess import"),
        (
            r"requests\.(get|post)\s*\([^)]*timeout\s*=\s*[^)]*\)",
            "External network request",
        ),
        (r"urllib\.request", "Network request via urllib"),
        (r"socket\.socket\s*\(", "Raw socket creation"),
        (r"pty\.spawn", "PTY spawn - possible reverse shell"),
        (r"socket\.connect", "Outbound socket connection"),
        (r"base64\.(b64encode|b64decode)", "Base64 encoding/decoding"),
        (r"codecs\.encode\s*\([^)]*['\"]base64", "Base64 encoding via codecs"),
        (r"import\s+pty", "pty module - possible PTY manipulation"),
        (r"import\s+crypt", "crypt module - password hashing"),
        (r"os\.chmod\s*\(\s*0o", "File permission change"),
        (r"os\.chown", "File ownership change"),
        (r"shutil\.copyfileobj", "File copy operations"),
        (r"shutil\.rmtree", "Directory removal"),
        (r"pathlib\.Path\.unlink", "File deletion"),
        (r"Path\.glob", "File globbing - enumeration"),
        (r"os\.listdir", "Directory listing"),
        (r"os\.walk", "Directory traversal"),
        (r"glob\.glob", "File globbing"),
        (r"open\s*\([^)]*['\"]w['\"]", "File write operation"),
        (r"with\s+open\s*\([^)]*['\"]w", "File write operation"),
        (r"json\.dump", "JSON write to file"),
        (r"pickle\.(load|loads)", "Pickle deserialization"),
        (r"marshal\.load", "Marshal deserialization"),
        (
            r"yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.FullLoader",
            "YAML FullLoader - code execution risk",
        ),
        (
            r"yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.UnsafeLoader",
            "YAML UnsafeLoader - code execution risk",
        ),
        (r"eval\s*\(.*input\s*\(", "eval with user input"),
        (r"compile\s*\(", "Dynamic code compilation"),
        (r"getattr\s*\([^,]+,\s*['\"]", "Dynamic attribute access"),
        (r"setattr\s*\(", "Dynamic attribute setting"),
        (r"delattr\s*\(", "Dynamic attribute deletion"),
        (r"hasattr\s*\([^)]+,\s*['\"]", "Dynamic attribute check"),
        (r"vars\s*\(\s*__", "Reading internal vars"),
        (r"__globals__", "Accessing globals"),
        (r"__builtins__", "Accessing builtins"),
        (r"import\s+os", "OS module import"),
        (r"import\s+subprocess", "Subprocess module import"),
        (r"import\s+sys", "Sys module import"),
        (r"import\s+threading", "Threading module import"),
        (r"import\s+multiprocessing", "Multiprocessing module import"),
        (r"import\s+websocket", "WebSocket module import"),
        (r"import\s+http", "HTTP module import"),
        (r"import\s+urllib", "URLlib module import"),
        (r"import\s+ftplib", "FTP module import"),
        (r"import\s+telnetlib", "Telnet module import"),
        (r"import\s+poplib", "POP3 module import"),
        (r"import\s+imaplib", "IMAP module import"),
        (r"import\s+smtplib", "SMTP module import"),
        (
            r"import\s+uuid",
            "UUID module - may be used for unique identifiers in attacks",
        ),
        (r"hashlib\.sha256\s*\([^)]*input", "Hashing user input"),
        (r"hmac\.new\s*\([^)]*input", "HMAC with user input"),
        (r"time\.sleep\s*\(\s*\)", "Time delay - possible covert channel"),
        (r"signal\.alarm", "Signal alarm - possible timeout bypass"),
        (r"resource\.setrlimit", "Resource limit manipulation"),
        (r"ctypes\.", "ctypes - low-level memory manipulation"),
        (r"winreg", "Windows registry access"),
        (r"platform\.system", "Platform detection"),
        (r"platform\.uname", "System information gathering"),
        (r"psutil", "System monitoring - possible reconnaissance"),
        (r"keyring", "Keyring access - credential theft risk"),
        (r"secretstorage", "Secret storage access"),
        (r"cryptography\.fernet", "Fernet encryption"),
        (r"cryptography\.hazmat", "Cryptography hazmat - advanced crypto"),
        (r"pycryptodome", "Cryptography library"),
        (r"pip\s+install", "pip package installation"),
        (r"pip\.main\s*\(", "pip programmatic install"),
        (r"npm\s+install", "npm package installation"),
        (r"yarn\s+add", "yarn package installation"),
        (r"apt-get\s+install", "apt package installation"),
        (r"yum\s+install", "yum package installation"),
        (r"brew\s+install", "brew package installation"),
        (r"go\s+install", "Go package installation"),
        (r"cargo\s+install", "Rust package installation"),
        (r"\.env", "Accessing .env file - credential exposure"),
        (r"dotenv", "dotenv library - environment variable loading"),
        (r"os\.environ", "Environment variables access"),
        (r"environ\.get\s*\(\s*['\"]", "Reading environment variables"),
        (r"shutil\.copyfile", "File copy - may be used for spreading"),
        (r"shutil\.move", "File move - may be used for spreading"),
        (r"os\.rename", "File rename"),
        (r"tempfile", "Temporary file creation"),
        (r"tmpdir", "Temporary directory"),
        (r"tmpfile", "Temporary file"),
        (r"cron", "Cron job - persistence mechanism"),
        (r"systemd", "Systemd service - persistence mechanism"),
        (r"launchd", "Launchd service - macOS persistence"),
        (r"registry", "Windows registry"),
        (r"runat\s+startup", "Windows startup persistence"),
        (r"runonce", "Windows runonce key"),
        (r"schedule\.add", "Task scheduling"),
        (r"schedule\.cron", "Cron scheduling"),
        (r"threading\.Timer", "Timer thread - delayed execution"),
        (r"setinterval", "SetInterval - periodic execution"),
        (r"settimeout", "SetTimeout - delayed execution"),
        (r"setInterval", "setInterval - periodic execution"),
        (r"setTimeout", "setTimeout - delayed execution"),
        (r"process\.exec", "Process execution"),
        (r"child_process\.exec", "Child process execution"),
        (r"child_process\.spawn", "Child process spawn"),
        (r"child_process\.fork", "Child process fork"),
        (r"\.exec\(", "Command execution"),
        (r"\.execFile\(", "Executable file execution"),
        (r"\.spawn\(", "Process spawn"),
        (r"CreateProcess", "Windows process creation"),
        (r"WinExec", "Windows execution"),
        (r"ShellExecute", "Shell execution"),
        (r"popen", "Pipe open - shell command"),
        (r"popen2", "Pipe open2 - shell command"),
        (r"popen3", "Pipe open3 - shell command"),
        (r"popen4", "Pipe open4 - shell command"),
        (r"msvcrt\.popen", "MSVCRT pipe open"),
        (r"os\.popen", "OS pipe open"),
        (r"os\.fork", "Process fork"),
        (r"os\.spawn", "OS process spawn"),
        (r"stdlib\.system", "stdlib system call"),
        (r"stdlib\.popen", "stdlib popen"),
        (r"fcntl\.flock", "File locking"),
        (r"fcntl\.lockf", "File lockf"),
        (r"mmap", "Memory mapping"),
        (r"memoryview", "Memory view"),
        (r"ctypes\.create_string_buffer", "String buffer creation"),
        (r"ctypes\.windll", "Windows DLL access"),
        (r"ctypes\.cdll", "CDLL access"),
        (r"win32api", "Win32 API access"),
        (r"win32con", "Win32 constants"),
        (r"win32gui", "Win32 GUI"),
        (r"win32process", "Win32 process"),
        (r"win32service", "Windows service"),
        (r"pywin32", "PyWin32 - Windows API"),
        (r"wmi", "Windows Management Instrumentation"),
        (r"subprocess", "Subprocess module - command execution"),
    ]

    MALICIOUS_KEYWORDS = [
        "trojan",
        "spyware",
        "adware",
        "virus",
        "worm",
        "ransomware",
        "cryptominer",
        "coinminer",
        "rootkit",
        "bootkit",
        "keylogger",
        "stealer",
        "grabber",
        "clipper",
        "dropper",
        "loader",
        "injector",
        "packer",
        "obfuscator",
        "crypter",
        "fUD",
        "FUD",
        "bypass antivirus",
        "bypass av",
        "kill antivirus",
        "disable antivirus",
        "terminate process",
        "hide process",
        "hide window",
        "invisible",
        "stealth mode",
        "anti-debug",
        "anti-vm",
        "virtual machine detection",
        "vm detection",
        "sandbox detection",
        "emulation detection",
        "persistence",
        "keylog",
        "clipboard",
        "screen capture",
        "screenshot",
        "webcam",
        "microphone",
        "audio capture",
        "browser history",
        "browser password",
        "steal session",
        "session hijack",
        "cookie steal",
        "form grabber",
        "credit card",
        "banking trojan",
        "banking malware",
        "mitm",
        "man in the middle",
        "arp spoof",
        "dns spoof",
        "ssl strip",
        "ssl bypass",
        "proxychains",
        "torify",
        "onion router",
        "i2p",
        "darknet",
        "c2 server",
        "c&c server",
        "command control",
        "botnet",
        "ddos",
        "syn flood",
        "udp flood",
        "icmp flood",
        "http flood",
        "brute force",
        "credential stuffing",
        "password spray",
        "hashcat",
        "john the ripper",
        "hydra",
        "medusa",
        "ncrack",
        "rainbow table",
        "pass the hash",
        "pass the ticket",
        "golden ticket",
        "silver ticket",
        "kerberoasting",
        "asrep roast",
        "ldapenum",
        "sam dump",
        "lsass dump",
        "mimikatz",
        "procdump",
        "lsassy",
        "gsecdump",
        "pwdump",
        "cachedump",
        "fgdump",
        "wce",
        "gamer",
        "logkeys",
        "ubertox",
        "blackhole",
        "neutrino",
        "angler",
        "neutrino",
        "magnitude",
        "sweet orange",
        "rig",
        "gootkit",
        "zloader",
        "emotet",
        "trickbot",
        "qakbot",
        "icedid",
        "cobalt strike",
        "metasploit",
        "msfvenom",
        "empire",
        "covenant",
        "pupy",
        "silenttrinity",
        "koadic",
        "merlin",
        "mythic",
        "sliver",
        "brute ratel",
        "devoops",
        "faction",
    ]

    SENSITIVE_FILE_PATTERNS = [
        (r"\.env", ".env file - contains secrets/credentials"),
        (r"\.git/config", "Git config - may contain credentials"),
        (r"\.aws/credentials", "AWS credentials file"),
        (r"\.aws/config", "AWS config file"),
        (r"\.ssh/", "SSH directory - private keys"),
        (r"\.gnupg/", "GPG directory"),
        (r"\.pki/", "PKI certificates"),
        (r"\.npmrc", "npm config - may contain tokens"),
        (r"\.pypirc", "PyPI config - may contain tokens"),
        (r"\.docker/config\.json", "Docker config - may contain credentials"),
        (r"\.kube/config", "Kubernetes config"),
        (r"\.azure/", "Azure credentials"),
        (r"\.google/", "Google Cloud credentials"),
        (r"credentials\.json", "GCP credentials"),
        (r"service-account\.json", "Service account credentials"),
        (r"\.htpasswd", "Apache password file"),
        (r"\.git-credentials", "Git credentials cache"),
        (r"\.netrc", "Netrc - FTP/HTTP credentials"),
        (r"\.wgetrc", "Wget credentials"),
        (r"\.curlrc", "Curl credentials"),
        (r"\.smbcredentials", "SMB credentials"),
        (r"keytab", "Kerberos keytab"),
        (r"\.kwallet", "KWallet - KDE wallet"),
        (r"pass\.db", "macOS Keychain database"),
        (r"secrets\.yaml", "Kubernetes secrets"),
        (r"secrets\.yml", "Kubernetes secrets"),
        (r"\.pem", "PEM certificate/private key"),
        (r"\.key", "Private key file"),
        (r"\.crt", "Certificate file"),
        (r"\.pfx", "PKCS#12 bundle"),
        (r"\.p12", "PKCS#12 bundle"),
    ]

    NETWORK_PATTERNS = [
        r"http[s]?://",
        r"ftp://",
        r"ws://",
        r"wss://",
        r"socket://",
        r"telnet://",
        r"smtp://",
        r"pop3://",
        r"imap://",
    ]

    def __init__(self, target_path: str):
        self.target_path = Path(target_path)
        self.findings: List[Dict[str, Any]] = []
        self.risk_score = 0
        self.risk_level = "SAFE"

    def analyze(self) -> Dict[str, Any]:
        if not self.target_path.exists():
            return {"error": f"Path does not exist: {self.target_path}"}

        if self.target_path.is_file():
            self._analyze_file(self.target_path)
        else:
            for file_path in self.target_path.rglob("*"):
                if file_path.is_file() and self._is_code_file(file_path):
                    if "skill-security-validator" in str(file_path):
                        continue
                    self._analyze_file(file_path)

        self._calculate_risk()
        return self._generate_report()

    def _get_pattern_explanation(
        self, pattern: str, finding_type: str
    ) -> Dict[str, str]:
        """Get specific explanation for a pattern."""
        explanations = {
            "Shell execution via os.system": {
                "explanation": "Executes shell commands. Could run malicious commands if input is not sanitized.",
                "recommendation": "Verify the command is hardcoded and doesn't use user input. Check for command injection risks.",
            },
            "Shell execution via subprocess": {
                "explanation": "Spawns subprocesses. Could execute malicious commands.",
                "recommendation": "Ensure commands are controlled and sanitized. Avoid passing raw user input.",
            },
            "Direct code execution": {
                "explanation": "Executes dynamic code strings. Extremely dangerous if input is not strictly controlled.",
                "recommendation": "Never use exec() with untrusted input. This is a major security risk.",
            },
            "Code evaluation": {
                "explanation": "Evaluates code strings. Can execute arbitrary code.",
                "recommendation": "Avoid eval() entirely. Use safer alternatives like JSON parsing.",
            },
            ".env file - contains secrets/credentials": {
                "explanation": "Accesses environment file that typically contains API keys, passwords, and secrets.",
                "recommendation": "Ensure the skill doesn't exfiltrate these values. Check network calls for data leakage.",
            },
            "Environment variables access": {
                "explanation": "Reads environment variables which may contain sensitive information.",
                "recommendation": "Check if sensitive env vars are being logged or transmitted.",
            },
            "HTTP module import": {
                "explanation": "Makes HTTP requests. Could exfiltrate data to external servers.",
                "recommendation": "Verify destination URLs are legitimate. Check for data exfiltration.",
            },
            "import os": {
                "explanation": "Imports OS module for system operations. Common in legitimate software.",
                "recommendation": "Check how OS functions are used. File operations may need scrutiny.",
            },
            "import subprocess": {
                "explanation": "Imports subprocess for running commands. Common in legitimate software.",
                "recommendation": "Verify commands are safe and don't accept untrusted input.",
            },
            "import requests": {
                "explanation": "Makes HTTP requests. Common in legitimate API clients.",
                "recommendation": "Verify destination URLs are expected services.",
            },
            "json.dump": {
                "explanation": "Writes JSON to files. Could write sensitive data.",
                "recommendation": "Check what data is being written and to where.",
            },
            "pickle.load": {
                "explanation": "Deserializes Python objects. Can execute arbitrary code.",
                "recommendation": "NEVER unpickle untrusted data. Use JSON for data exchange.",
            },
            "base64 encoding/decoding": {
                "explanation": "Encodes/decodes data. Often used to obfuscate payloads.",
                "recommendation": "Check if encoded data is being executed or transmitted.",
            },
            "pip package installation": {
                "explanation": "Installs packages at runtime. Could install malicious packages.",
                "recommendation": "Ensure packages are from trusted sources. This is unusual behavior.",
            },
            "npm package installation": {
                "explanation": "Installs npm packages at runtime. Could install malicious packages.",
                "recommendation": "Verify package sources. This is unusual behavior.",
            },
            "Reverse shell": {
                "explanation": "Creates a reverse shell for remote access. MALICIOUS.",
                "recommendation": "DO NOT USE this skill. This is clearly malicious code.",
            },
            "keylogger": {
                "explanation": "Records keystrokes. MALICIOUS.",
                "recommendation": "DO NOT USE this skill. This is clearly malicious code.",
            },
            "credential": {
                "explanation": "References credentials. Could be stealing or managing credentials.",
                "recommendation": "Check if credentials are being logged or transmitted.",
            },
            "password": {
                "explanation": "References passwords. Could be stealing or managing passwords.",
                "recommendation": "Verify password handling is secure and not being exfiltrated.",
            },
            "token": {
                "explanation": "References authentication tokens. Could be stealing or using tokens.",
                "recommendation": "Check if tokens are being logged or transmitted.",
            },
            "api_key": {
                "explanation": "References API keys. Could be stealing or using API keys.",
                "recommendation": "Verify API keys are not being logged or transmitted.",
            },
            "socket.connect": {
                "explanation": "Creates network socket connection. Could connect to attacker server.",
                "recommendation": "Verify the connection destination is legitimate.",
            },
            "pty.spawn": {
                "explanation": "Creates pseudo-terminal. Often used for reverse shells.",
                "recommendation": "This is suspicious. Verify the purpose of PTY creation.",
            },
        }

        # Default explanations by finding type
        default_explanations = {
            "dangerous_pattern": {
                "explanation": "This pattern could be dangerous if abused, but is also common in legitimate software.",
                "recommendation": "Review the specific code to understand its purpose.",
            },
            "malicious_keyword": {
                "explanation": "This keyword appears in security contexts. Could be malicious or legitimate.",
                "recommendation": "Check the context - many terms appear in legitimate security tools.",
            },
            "sensitive_file_access": {
                "explanation": "This accesses files that typically contain sensitive data.",
                "recommendation": "Verify the access is for legitimate purposes and data isn't exfiltrated.",
            },
            "network_access": {
                "explanation": "This makes network calls to external servers.",
                "recommendation": "Verify the destination is a trusted service.",
            },
            "malicious_filename": {
                "explanation": "This filename contains suspicious keywords.",
                "recommendation": "Review the file contents carefully.",
            },
        }

        # Check for specific pattern match first
        for key, exp in explanations.items():
            if key.lower() in pattern.lower() or pattern.lower() in key.lower():
                return exp

        # Return default for finding type
        return default_explanations.get(
            finding_type,
            {
                "explanation": "This pattern was detected during security scanning.",
                "recommendation": "Review the code to determine if it's legitimate.",
            },
        )

    def _is_code_file(self, path: Path) -> bool:
        code_extensions = {
            ".py",
            ".js",
            ".ts",
            ".sh",
            ".bash",
            ".ps1",
            ".rb",
            ".go",
            ".rs",
            ".java",
            ".c",
            ".cpp",
            ".h",
        }
        return path.suffix.lower() in code_extensions

    def _analyze_file(self, file_path: Path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")

            for i, line in enumerate(lines, 1):
                self._check_patterns(line, file_path, i)
                self._check_malicious_keywords(line, file_path, i)
                self._check_network_calls(line, file_path, i)
                self._check_sensitive_files(line, file_path, i)

            self._check_filename(file_path)

        except Exception as e:
            self.findings.append(
                {
                    "type": "error",
                    "file": str(file_path),
                    "line": 0,
                    "message": f"Could not read file: {str(e)}",
                }
            )

    def _check_filename(self, file_path: Path):
        filename = file_path.name.lower()
        for keyword in self.MALICIOUS_KEYWORDS:
            if keyword in filename:
                exp = self._get_pattern_explanation(keyword, "malicious_filename")
                self.findings.append(
                    {
                        "type": "malicious_filename",
                        "severity": "CRITICAL",
                        "file": str(file_path),
                        "line": 0,
                        "pattern": f"Suspicious filename contains: {keyword}",
                        "content": file_path.name,
                        "explanation": exp["explanation"],
                        "recommendation": exp["recommendation"],
                    }
                )
                self.risk_score += 25

    def _check_malicious_keywords(self, line: str, file_path: Path, line_num: int):
        line_lower = line.lower()
        for keyword in self.MALICIOUS_KEYWORDS:
            if keyword in line_lower:
                exp = self._get_pattern_explanation(keyword, "malicious_keyword")
                self.findings.append(
                    {
                        "type": "malicious_keyword",
                        "severity": "CRITICAL",
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": f"Malicious/attack keyword: {keyword}",
                        "content": line.strip()[:100],
                        "explanation": exp["explanation"],
                        "recommendation": exp["recommendation"],
                    }
                )
                self.risk_score += 20

    def _check_sensitive_files(self, line: str, file_path: Path, line_num: int):
        for pattern, description in self.SENSITIVE_FILE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                exp = self._get_pattern_explanation(
                    description, "sensitive_file_access"
                )
                self.findings.append(
                    {
                        "type": "sensitive_file_access",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": description,
                        "content": line.strip()[:100],
                        "explanation": exp["explanation"],
                        "recommendation": exp["recommendation"],
                    }
                )
                self.risk_score += 15

    def _check_patterns(self, line: str, file_path: Path, line_num: int):
        for pattern, description in self.DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                exp = self._get_pattern_explanation(description, "dangerous_pattern")
                self.findings.append(
                    {
                        "type": "dangerous_pattern",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": description,
                        "content": line.strip()[:100],
                        "explanation": exp["explanation"],
                        "recommendation": exp["recommendation"],
                    }
                )
                self.risk_score += 10

    def _check_network_calls(self, line: str, file_path: Path, line_num: int):
        for pattern in self.NETWORK_PATTERNS:
            if re.search(pattern, line):
                self.findings.append(
                    {
                        "type": "network_access",
                        "severity": "MEDIUM",
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": "Network URL/connection detected",
                        "content": line.strip()[:100],
                        "explanation": "This code makes network requests to external servers. Could be exfiltrating data.",
                        "recommendation": "Verify the destination URLs are legitimate services. Check for unexpected data transmission.",
                    }
                )
                self.risk_score += 5
                break

    def _calculate_risk(self):
        # Cap risk score at 100
        capped_score = min(self.risk_score, 100)

        if capped_score == 0:
            self.risk_level = "SAFE"
        elif capped_score < 10:
            self.risk_level = "LOW"
        elif capped_score < 30:
            self.risk_level = "MEDIUM"
        elif capped_score < 50:
            self.risk_level = "HIGH"
        else:
            self.risk_level = "CRITICAL"

    def _analyze_skill_md(self):
        """Analyze SKILL.md for malicious prompts/instructions."""
        skill_md_issues = []

        # Patterns that might indicate malicious prompts
        prompt_dangerous_patterns = [
            (
                r"ignore\s+(previous|all|above)\s+(instructions?|rules?|prompts?)",
                "Prompt injection attempt - telling AI to ignore instructions",
            ),
            (
                r"forget\s+(everything|all|previous)",
                "Prompt injection - telling AI to forget context",
            ),
            (r"new\s+instructions?:", "Potential instruction override"),
            (r"#\s*system", "System prompt manipulation"),
            (r"you\s+are\s+now", "Role manipulation attempt"),
            (r"pretend\s+to\s+be", "Roleplaying bypass attempt"),
            (r"bypass\s+(safety|restriction|filter)", "Safety bypass attempt"),
            (r"disable\s+(safety|filter|protection)", "Disabling safety measures"),
            (r"malicious", "Mentions malicious intent"),
            (r"steal\s+(data|credentials|information)", "Data theft instruction"),
            (r"exfiltrat", "Data exfiltration instruction"),
            (r"send\s+.*\s+(to\s+)?(me|my|external)", "Data sending instruction"),
            (r"write\s+.*\s+(to\s+)?disk", "Disk write instruction"),
            (r"execute\s+.*\s+(shell|command|script)", "Command execution instruction"),
            (r"run\s+.*\s+(shell|command)", "Command execution instruction"),
            (r"download\s+.*\s+(and\s+)?execute", "Download and execute instruction"),
            (
                r"install\s+.*\s+(malware|virus|trojan)",
                "Malware installation instruction",
            ),
        ]

        # Check all relevant skill files for bad instructions
        target_path = Path(self.target_path)
        if target_path.is_dir():
            # Files to check (text-based that could contain instructions)
            check_extensions = {
                ".md",
                ".txt",
                ".yaml",
                ".yml",
                ".json",
                ".py",
                ".js",
                ".ts",
            }
            # Files to SKIP (contain real credentials)
            skip_names = {".env", "credentials", "secrets", "config.json", ".env.local"}

            for file_path in target_path.rglob("*"):
                if not file_path.is_file():
                    continue
                # Skip files that might contain real credentials
                if any(skip in file_path.name.lower() for skip in skip_names):
                    continue
                # Only check text-based files
                if file_path.suffix.lower() not in check_extensions:
                    continue
                # Skip node_modules, .git, etc.
                if any(part.startswith(".") for part in file_path.parts):
                    if (
                        ".claude" not in file_path.parts
                        and ".agents" not in file_path.parts
                    ):
                        continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    for pattern, description in prompt_dangerous_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            line_num = content[: match.start()].count("\n") + 1
                            skill_md_issues.append(
                                {
                                    "file": str(file_path.relative_to(target_path)),
                                    "line": line_num,
                                    "pattern": description,
                                    "content": content[
                                        max(0, match.start() - 30) : match.end() + 30
                                    ][:200],
                                }
                            )
                except Exception:
                    pass

        return skill_md_issues

    def _generate_report(self) -> Dict[str, Any]:
        smart_analysis = self._analyze_findings_context()

        # Analyze ALL skill files for prompt injection/bad instructions
        skill_md_issues = self._analyze_skill_md()

        # Determine what checks were performed
        checks_performed = {
            "code_patterns": True,  # Always done via scanning
            "network_calls": True,  # Always done via scanning
            "sensitive_files": True,  # Always done via scanning
            "skill_instructions": True,  # Now done for all skill files
            "skill_md_analysis": len(skill_md_issues),  # Count of issues found
        }

        # Determine what CAN be done as follow-up (not yet done or deeper)
        potential_followups = []

        # Library verification - only if libraries found and not verified
        if smart_analysis.get("potential_libraries"):
            potential_followups.append(
                {
                    "id": "web_search",
                    "title": "Web search to verify libraries are legitimate",
                    "description": f"Check if {[lib for lib in smart_analysis['potential_libraries'][:3]]} are known safe packages",
                    "why": "Some libraries may be typosquatting or malicious packages",
                }
            )

        # Package scan - only if skill installs packages
        if any("install" in str(f.get("content", "")).lower() for f in self.findings):
            potential_followups.append(
                {
                    "id": "scan_package",
                    "title": "Scan the installed Python/npm package",
                    "description": "Download and scan the actual package this skill installs",
                    "why": "The skill itself may be safe, but the package it installs could be malicious",
                }
            )

        # Cap the displayed score at 100
        displayed_score = min(self.risk_score, 100)

        return {
            "target_path": str(self.target_path),
            "risk_level": self.risk_level,
            "risk_score": displayed_score,
            "total_findings": len(self.findings),
            "findings": self.findings,
            "checks_performed": checks_performed,
            "skill_instructions_analysis": {
                "issues_found": len(skill_md_issues),
                "issues": skill_md_issues[:10],  # Limit to first 10
            },
            "recommendation": self._get_recommendation(),
            "explanation": self._get_detailed_explanation(),
            "smart_analysis": smart_analysis,
            "potential_followups": potential_followups,
        }

    def _get_detailed_explanation(self) -> Dict[str, Any]:
        explanations = {
            "dangerous_pattern": {
                "title": "Potentially Dangerous Code Pattern",
                "description": "This code uses patterns that could be used for malicious purposes if abused. However, these patterns are also commonly used in legitimate software.",
                "what_to_do": "Review the specific code to understand its purpose. Check if it's essential for the skill's functionality.",
                "common_false_positives": "OS operations, JSON handling, and network calls are often needed for legitimate purposes.",
            },
            "malicious_keyword": {
                "title": "Suspicious Keyword Detected",
                "description": "This code contains keywords commonly associated with malware, attack tools, or hacking techniques.",
                "what_to_do": "Investigate the context. Many of these terms appear in legitimate security tools, tests, and documentation.",
                "common_false_positives": "Words like 'rig', 'loader', 'proxy' appear in legitimate software names (e.g., Playwright, data loaders).",
            },
            "sensitive_file_access": {
                "title": "Access to Sensitive Files",
                "description": "This code attempts to access files that typically contain credentials, secrets, or sensitive configuration.",
                "what_to_do": "Ensure the skill only accesses these files for legitimate purposes. Check if credentials are being exfiltrated.",
                "common_false_positives": "Reading .env for configuration is common in legitimate apps; ensure it's not sending data elsewhere.",
            },
            "network_access": {
                "title": "Network Communication",
                "description": "This code makes network requests to external servers.",
                "what_to_do": "Verify the network destinations are legitimate. Check if data is being sent to unexpected servers.",
                "common_false_positives": "API calls to known services (Google, GitHub, etc.) are common in legitimate skills.",
            },
            "malicious_filename": {
                "title": "Suspicious Filename",
                "description": "The filename contains keywords associated with malware or attack tools.",
                "what_to_do": "This is a strong indicator. Review the file contents carefully before using the skill.",
                "common_false_positives": "Rare - filenames are less likely to have false positives.",
            },
        }

        # Count findings by type
        by_type = {}
        for finding in self.findings:
            ftype = finding.get("type", "unknown")
            by_type[ftype] = by_type.get(ftype, 0) + 1

        return {
            "summary_by_type": by_type,
            "explanations": explanations,
            "overall_assessment": self._get_assessment_text(),
        }

    def _get_assessment_text(self) -> str:
        if self.risk_level == "SAFE":
            return "No suspicious patterns detected. This skill appears safe for use based on automated analysis."
        elif self.risk_level == "LOW":
            return "Minor patterns detected that are commonly used in legitimate software. Manual review recommended but risk appears low."
        elif self.risk_level == "MEDIUM":
            return "Several patterns detected that warrant investigation. Review each finding to ensure they're legitimate uses."
        elif self.risk_level == "HIGH":
            return "Multiple concerning patterns detected. This skill requires careful manual review before use."
        else:
            return "CRITICAL: This skill exhibits multiple high-risk patterns. Strongly recommend NOT using until thoroughly reviewed by a security expert."

    def _analyze_findings_context(self) -> Dict[str, Any]:
        """Analyze the context of findings to provide smarter risk assessment."""

        # Count by type
        dangerous_patterns = sum(
            1 for f in self.findings if f.get("type") == "dangerous_pattern"
        )
        malicious_keywords = sum(
            1 for f in self.findings if f.get("type") == "malicious_keyword"
        )
        sensitive_files = sum(
            1 for f in self.findings if f.get("type") == "sensitive_file_access"
        )
        network_access = sum(
            1 for f in self.findings if f.get("type") == "network_access"
        )

        # Check if findings are in documentation files (SKILL.md, README.md, etc.)
        doc_files = [
            f
            for f in self.findings
            if "SKILL.md" in f.get("file", "") or "README.md" in f.get("file", "")
        ]
        code_files = [f for f in self.findings if f not in doc_files]

        # Check for common false positive patterns
        false_positive_patterns = [
            "pip install",
            "npm install",
            "import sys",
            "import os",
            "import json",
            "import requests",
            "import httpx",
            "http://",
            "https://",
            "documentation",
            "example",
            "tutorial",
            "how to",
            "install",
        ]

        false_positive_count = 0
        for finding in self.findings:
            content = finding.get("content", "").lower()
            pattern = finding.get("pattern", "").lower()
            for fp in false_positive_patterns:
                if fp in content or fp in pattern:
                    false_positive_count += 1
                    break

        # Determine if likely documentation vs actual code
        is_documentation_heavy = len(doc_files) > len(code_files) and len(doc_files) > 3

        # Calculate adjusted risk
        adjusted_score = self.risk_score

        # Reduce score significantly if findings are mostly documentation
        if is_documentation_heavy:
            adjusted_score = int(adjusted_score * 0.3)

        # Reduce score if most findings are known false positives
        if false_positive_count > len(self.findings) * 0.7:
            adjusted_score = int(adjusted_score * 0.2)

        # Determine adjusted risk level
        if adjusted_score == 0:
            adjusted_level = "SAFE"
        elif adjusted_score < 10:
            adjusted_level = "LOW"
        elif adjusted_score < 30:
            adjusted_level = "MEDIUM"
        elif adjusted_score < 50:
            adjusted_level = "HIGH"
        else:
            adjusted_level = "CRITICAL"

        # Generate context-aware assessment
        context_notes = []
        if is_documentation_heavy:
            context_notes.append(
                "⚠️ Most findings are in documentation files (SKILL.md, README.md). These are likely examples/instructions, not actual malicious code."
            )
        if false_positive_count > len(self.findings) * 0.7:
            context_notes.append(
                "⚠️ Most findings are common false positives (import statements, URLs in documentation)."
            )
        if doc_files and code_files:
            context_notes.append(
                f"📄 {len(doc_files)} findings in documentation, {len(code_files)} in code files."
            )

        # Extract potential library names for web search
        library_names = set()
        for finding in self.findings:
            content = finding.get("content", "")
            # Look for pip install, npm install patterns
            if "pip install" in content.lower() or "pip" in content.lower():
                import re

                matches = re.findall(r"pip install ([a-zA-Z0-9_-]+)", content)
                library_names.update(matches)
            if "import " in content:
                import re

                matches = re.findall(r"import ([a-zA-Z0-9_-]+)", content)
                library_names.update(
                    matches[:1]
                )  # First import is usually the main library

        # Filter out Python standard library modules
        stdlib_modules = {
            "os",
            "sys",
            "json",
            "re",
            "time",
            "datetime",
            "math",
            "random",
            "collections",
            "itertools",
            "functools",
            "operator",
            "string",
            "logging",
            "warnings",
            "threading",
            "multiprocessing",
            "asyncio",
            "subprocess",
            "platform",
            "pathlib",
            "typing",
            "abc",
            "copy",
            "io",
            "tempfile",
            "shutil",
            "glob",
            "fnmatch",
            "argparse",
            "configparser",
            "csv",
            "sqlite3",
            "zipfile",
            "tarfile",
            "html",
            "xml",
            "urllib",
            "http",
            "ftplib",
            "smtplib",
            "poplib",
            "imaplib",
            "socket",
            "ssl",
            "email",
            "base64",
            "hashlib",
            "hmac",
            "secrets",
            "cryptography",
            "pickle",
            "marshal",
            "ast",
            "dis",
            "inspect",
            "traceback",
            "gc",
            "weakref",
            "types",
            "contextlib",
            "dataclasses",
            "enum",
            "graphlib",
            "pprint",
            "textwrap",
            "unittest",
            "doctest",
            "pdb",
        }

        # Filter to only external libraries
        external_libs = [
            lib for lib in library_names if lib.lower() not in stdlib_modules
        ]

        return {
            "original_risk_level": self.risk_level,
            "original_risk_score": self.risk_score,
            "adjusted_risk_level": adjusted_level,
            "adjusted_risk_score": adjusted_score,
            "context_notes": context_notes,
            "potential_libraries": external_libs[:5],  # Max 5
            "is_documentation_heavy": is_documentation_heavy,
            "false_positive_ratio": false_positive_count / max(len(self.findings), 1),
        }

    def _get_recommendation(self) -> str:
        if self.risk_level == "SAFE":
            return "This skill/script appears safe for use."
        elif self.risk_level == "LOW":
            return "Minor concerns detected. Review findings before use."
        elif self.risk_level == "MEDIUM":
            return "Exercise caution. Review findings carefully."
        elif self.risk_level == "HIGH":
            return "HIGH RISK - Do not use without thorough manual review."
        else:
            return "CRITICAL RISK - Strongly recommend NOT using this skill/script."


def get_home_dir():
    """Get the user's home directory cross-platform."""
    return Path.home()


def get_cwd():
    """Get current working directory."""
    return Path.cwd()


def get_skill_locations():
    """Get all known skill locations for different AI agents and OS (global and project)."""
    home = get_home_dir()
    cwd = get_cwd()
    is_windows = sys.platform == "win32"

    locations = []

    if is_windows:
        userprofile = Path(os.environ.get("USERPROFILE", str(home)))
        appdata = Path(
            os.environ.get("APPDATA", str(userprofile / "AppData" / "Roaming"))
        )

        # GLOBAL locations (user's home directory)
        locations.extend(
            [
                (userprofile / ".claude" / "skills", "Claude Code (global)"),
                (userprofile / ".agents" / "skills", "OpenCode/OpenClaw (global)"),
                (appdata / "opencode" / "skills", "OpenCode config (global)"),
                (
                    appdata
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "codeium"
                    / "workspace",
                    "Codeium (global)",
                ),
                (userprofile / ".cursor" / "rules", "Cursor (global)"),
                (
                    userprofile / "AppData" / "Local" / "Programs" / "Windsurf",
                    "Windsurf",
                ),
                (userprofile / ".codex" / "skills", "Codex (global)"),
                (userprofile / ".goose" / "skills", "Goose (global)"),
                (userprofile / ".letta" / "skills", "Letta (global)"),
                (userprofile / ".gemini" / "cli" / "skills", "Gemini CLI (global)"),
                (userprofile / ".kilocode" / "skills", "KiloCode (global)"),
            ]
        )

        # PROJECT locations (current working directory)
        locations.extend(
            [
                (cwd / ".claude" / "skills", "Claude Code (project)"),
                (cwd / ".agents" / "skills", "OpenCode/OpenClaw (project)"),
                (cwd / ".opencode" / "skills", "OpenCode (project)"),
                (cwd / ".cursor" / "rules", "Cursor (project)"),
                (cwd / ".windsurf" / "skills.json", "Windsurf (project)"),
                (cwd / ".github" / "skills", "GitHub (project)"),
                (cwd / ".codex" / "skills", "Codex (project)"),
                (cwd / "AGENTS.md", "Codex/通用 (project)"),
                (cwd / "CLAUDE.md", "Claude (project)"),
            ]
        )
    else:
        # macOS/Linux GLOBAL locations
        locations.extend(
            [
                (home / ".claude" / "skills", "Claude Code (global)"),
                (home / ".agents" / "skills", "OpenCode/OpenClaw (global)"),
                (home / ".config" / "opencode" / "skills", "OpenCode config (global)"),
                (home / ".cursor" / "rules", "Cursor (global)"),
                (home / ".windsurf" / "skills.json", "Windsurf (global)"),
                (home / ".codex" / "skills", "Codex (global)"),
                (home / ".goose" / "skills", "Goose (global)"),
                (home / ".letta" / "skills", "Letta (global)"),
                (home / ".gemini" / "cli" / "skills", "Gemini CLI (global)"),
                (home / ".kilocode" / "skills", "KiloCode (global)"),
            ]
        )

        # macOS/Linux PROJECT locations
        locations.extend(
            [
                (cwd / ".claude" / "skills", "Claude Code (project)"),
                (cwd / ".agents" / "skills", "OpenCode/OpenClaw (project)"),
                (cwd / ".opencode" / "skills", "OpenCode (project)"),
                (cwd / ".cursor" / "rules", "Cursor (project)"),
                (cwd / ".windsurf" / "skills.json", "Windsurf (project)"),
                (cwd / ".github" / "skills", "GitHub (project)"),
                (cwd / ".codex" / "skills", "Codex (project)"),
                (cwd / "AGENTS.md", "Codex/通用 (project)"),
                (cwd / "CLAUDE.md", "Claude (project)"),
            ]
        )

    valid_locations = [(p, name) for p, name in locations if p.exists()]
    return valid_locations


def find_skill_by_name(skill_name: str) -> List[Path]:
    """Find a skill by name across all known locations.

    IMPORTANT: Always search GLOBAL locations first, then project locations.
    This ensures skills are found regardless of current working directory.
    """
    home = get_home_dir()
    is_windows = sys.platform == "win32"
    global_locations = []
    project_locations = []

    if is_windows:
        userprofile = Path(os.environ.get("USERPROFILE", str(home)))
        appdata = Path(
            os.environ.get("APPDATA", str(userprofile / "AppData" / "Roaming"))
        )

        # GLOBAL locations
        global_locations.extend(
            [
                (userprofile / ".claude" / "skills", "Claude Code (global)"),
                (userprofile / ".agents" / "skills", "OpenCode/OpenClaw (global)"),
                (appdata / "opencode" / "skills", "OpenCode config (global)"),
                (
                    appdata
                    / "Code"
                    / "User"
                    / "globalStorage"
                    / "codeium"
                    / "workspace",
                    "Codeium (global)",
                ),
                (userprofile / ".cursor" / "rules", "Cursor (global)"),
                (
                    userprofile / "AppData" / "Local" / "Programs" / "Windsurf",
                    "Windsurf",
                ),
                (userprofile / ".codex" / "skills", "Codex (global)"),
                (userprofile / ".goose" / "skills", "Goose (global)"),
                (userprofile / ".letta" / "skills", "Letta (global)"),
                (userprofile / ".gemini" / "cli" / "skills", "Gemini CLI (global)"),
                (userprofile / ".kilocode" / "skills", "KiloCode (global)"),
            ]
        )

        # PROJECT locations - from current directory
        project_locations.extend(
            [
                (get_cwd() / ".claude" / "skills", "Claude Code (project)"),
                (get_cwd() / ".agents" / "skills", "OpenCode/OpenClaw (project)"),
                (get_cwd() / ".opencode" / "skills", "OpenCode (project)"),
                (get_cwd() / ".cursor" / "rules", "Cursor (project)"),
                (get_cwd() / ".windsurf" / "skills.json", "Windsurf (project)"),
                (get_cwd() / ".github" / "skills", "GitHub (project)"),
                (get_cwd() / ".codex" / "skills", "Codex (project)"),
            ]
        )
    else:
        # macOS/Linux GLOBAL locations
        global_locations.extend(
            [
                (home / ".claude" / "skills", "Claude Code (global)"),
                (home / ".agents" / "skills", "OpenCode/OpenClaw (global)"),
                (home / ".config" / "opencode" / "skills", "OpenCode config (global)"),
                (home / ".cursor" / "rules", "Cursor (global)"),
                (home / ".windsurf" / "skills.json", "Windsurf (global)"),
                (home / ".codex" / "skills", "Codex (global)"),
                (home / ".goose" / "skills", "Goose (global)"),
                (home / ".letta" / "skills", "Letta (global)"),
                (home / ".gemini" / "cli" / "skills", "Gemini CLI (global)"),
                (home / ".kilocode" / "skills", "KiloCode (global)"),
            ]
        )

        # PROJECT locations
        project_locations.extend(
            [
                (get_cwd() / ".claude" / "skills", "Claude Code (project)"),
                (get_cwd() / ".agents" / "skills", "OpenCode/OpenClaw (project)"),
                (get_cwd() / ".opencode" / "skills", "OpenCode (project)"),
                (get_cwd() / ".cursor" / "rules", "Cursor (project)"),
                (get_cwd() / ".windsurf" / "skills.json", "Windsurf (project)"),
                (get_cwd() / ".github" / "skills", "GitHub (project)"),
                (get_cwd() / ".codex" / "skills", "Codex (project)"),
            ]
        )

    found_paths = []

    # FIRST: Search all GLOBAL locations
    for base_path, location_name in global_locations:
        if not base_path.exists() or not base_path.is_dir():
            continue

        skill_path = base_path / skill_name
        if skill_path.exists():
            found_paths.append(skill_path)

        for subdir in base_path.iterdir():
            if subdir.is_dir() and subdir.name.lower() == skill_name.lower():
                found_paths.append(subdir)

    # SECOND: Search project locations only if not found globally
    if not found_paths:
        for base_path, location_name in project_locations:
            if not base_path.exists() or not base_path.is_dir():
                continue

            skill_path = base_path / skill_name
            if skill_path.exists():
                found_paths.append(skill_path)

            for subdir in base_path.iterdir():
                if subdir.is_dir() and subdir.name.lower() == skill_name.lower():
                    found_paths.append(subdir)

    return found_paths


def list_all_skills() -> Dict[str, List[Dict[str, str]]]:
    """List all skills found in all known locations."""
    locations = get_skill_locations()
    all_skills = {}

    for base_path, location_name in locations:
        if not base_path.exists():
            continue

        # Handle single file locations (like AGENTS.md, CLAUDE.md)
        if base_path.is_file():
            all_skills.setdefault(location_name, []).append(
                {
                    "name": base_path.stem,
                    "path": str(base_path),
                    "location": location_name,
                }
            )
            continue

        # Handle directory locations
        skills = []
        for item in base_path.iterdir():
            if item.is_dir():
                skill_file = item / "SKILL.md"
                if skill_file.exists():
                    skills.append(
                        {
                            "name": item.name,
                            "path": str(item),
                            "location": location_name,
                        }
                    )
                elif (item / "skill.md").exists():
                    skills.append(
                        {
                            "name": item.name,
                            "path": str(item),
                            "location": location_name,
                        }
                    )

        if skills:
            all_skills[location_name] = skills

    return all_skills


def scan_all_skills() -> Dict[str, Any]:
    """Scan all skills found in all known locations."""
    all_skills = list_all_skills()
    results = {
        "scanned_locations": [],
        "total_skills": 0,
        "skills": [],
        "summary": {"safe": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
    }

    for location_name, skills in all_skills.items():
        results["scanned_locations"].append(location_name)
        results["total_skills"] += len(skills)

        for skill in skills:
            validator = SecurityValidator(skill["path"])
            report = validator.analyze()

            results["skills"].append(
                {
                    "name": skill["name"],
                    "path": skill["path"],
                    "location": location_name,
                    "risk_level": report["risk_level"],
                    "risk_score": report["risk_score"],
                    "findings_count": report["total_findings"],
                    "recommendation": report["recommendation"],
                }
            )

            results["summary"][report["risk_level"].lower()] += 1

    return results


def main():
    if len(sys.argv) < 2:
        print("Skill Security Validator")
        print("=" * 50)
        print("\nUsage:")
        print("  validate_security.py <path>              - Scan a specific path")
        print("  validate_security.py --list             - List all skills found")
        print("  validate_security.py --scan-all          - Scan all skills")
        print(
            "  validate_security.py <skill-name>        - Find and scan skill by name"
        )
        print("\nExamples:")
        print("  validate_security.py ~/skills/my-skill")
        print("  validate_security.py notebooklm")
        print("  validate_security.py --scan-all")
        print("\nKnown skill locations:")
        locations = get_skill_locations()
        for path, name in locations:
            print(f"  - {name}: {path}")
        print()
        sys.exit(0)

    arg = sys.argv[1]

    if arg == "--list":
        all_skills = list_all_skills()
        print(json.dumps(all_skills, indent=2))
        sys.exit(0)

    if arg == "--scan-all":
        results = scan_all_skills()
        print(json.dumps(results, indent=2))

        if results["summary"]["critical"] > 0 or results["summary"]["high"] > 0:
            sys.exit(2)
        elif results["summary"]["medium"] > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    target = sys.argv[1]

    # If path doesn't exist, try to find skill by name in all locations
    if not Path(target).exists():
        # Extract skill name from path (handle both paths like .opencode/skill/notebooklm and just notebooklm)
        skill_name = target
        # If path contains path separators, try to extract the skill name
        if "/" in target or "\\" in target:
            # Get just the last part of the path
            parts = target.replace("\\", "/").split("/")
            skill_name = parts[-1]

        print(
            f"Path '{target}' not found. Searching for skill '{skill_name}' in all locations..."
        )
        found = find_skill_by_name(skill_name)

        if not found:
            print(f"Skill '{skill_name}' not found in any known location.")
            print("\nSearching in:")
            locations = get_skill_locations()
            for path, name in locations:
                print(f"  - {name}: {path}")
            sys.exit(1)

        # Remove duplicates (same skill might be in multiple lists)
        unique_found = list(set(found))

        # Found multiple instances - scan ALL of them
        print(f"Found {len(unique_found)} unique instance(s) of skill '{skill_name}':")
        for i, f in enumerate(unique_found, 1):
            print(f"  {i}. {f}")

        if len(unique_found) == 1:
            print(f"\nScanning single skill...")
            validator = SecurityValidator(str(unique_found[0]))
            report = validator.analyze()

            # Print human-readable summary with smart analysis
            print("\n" + "=" * 60)
            print("SECURITY SCAN RESULTS")
            print("=" * 60)

            sa = report.get("smart_analysis", {})
            print(
                f"\n📊 Raw Risk Score: {sa.get('original_risk_score', report.get('risk_score'))}/100 ({sa.get('original_risk_level', report.get('risk_level'))})"
            )

            if sa.get("adjusted_risk_score") is not None:
                print(
                    f"📊 Adjusted Risk: {sa.get('adjusted_risk_score')}/100 ({sa.get('adjusted_risk_level')})"
                )

            # Print context notes
            for note in sa.get("context_notes", []):
                print(f"\n{note}")

            # Print recommendation
            print(f"\n💡 Recommendation: {report.get('recommendation')}")

            # Check for potential libraries to verify
            libraries = sa.get("potential_libraries", [])
            if libraries:
                print(f"\n🔍 Potential libraries detected: {', '.join(libraries)}")
                print(
                    "   → Would you like me to web search to verify these are legitimate?"
                )

            print("\n" + "=" * 60)

        else:
            print(f"\nScanning ALL {len(unique_found)} instances...")
            all_reports = []
            all_smart_analyses = []
            all_potential_libraries = set()

            for f in unique_found:
                validator = SecurityValidator(str(f))
                report = validator.analyze()

                all_reports.append(
                    {
                        "path": str(f),
                        "risk_level": report["risk_level"],
                        "risk_score": report["risk_score"],
                        "findings_count": report["total_findings"],
                        "recommendation": report["recommendation"],
                    }
                )

                # Collect smart analysis
                sa = report.get("smart_analysis", {})
                all_smart_analyses.append(sa)
                all_potential_libraries.update(sa.get("potential_libraries", []))

            # Print combined report with smart analysis
            combined = {
                "skill_name": skill_name,
                "total_instances": len(unique_found),
                "instances_scanned": all_reports,
                "summary": {
                    "safe": sum(1 for r in all_reports if r["risk_level"] == "SAFE"),
                    "low": sum(1 for r in all_reports if r["risk_level"] == "LOW"),
                    "medium": sum(
                        1 for r in all_reports if r["risk_level"] == "MEDIUM"
                    ),
                    "high": sum(1 for r in all_reports if r["risk_level"] == "HIGH"),
                    "critical": sum(
                        1 for r in all_reports if r["risk_level"] == "CRITICAL"
                    ),
                },
            }

            highest_risk = max(all_reports, key=lambda x: x["risk_score"])
            combined["overall_risk_level"] = highest_risk["risk_level"]
            combined["overall_risk_score"] = highest_risk["risk_score"]
            combined["recommendation"] = highest_risk["recommendation"]

            # Add smart analysis to combined
            combined["smart_analysis"] = {
                "all_context_notes": [
                    sa.get("context_notes", []) for sa in all_smart_analyses
                ],
                "potential_libraries": list(all_potential_libraries)[:5],
            }

            # Print human-readable summary
            print("\n" + "=" * 60)
            print("SECURITY SCAN RESULTS")
            print("=" * 60)

            print(
                f"\n📊 Raw Risk Score: {combined['overall_risk_score']}/100 ({combined['overall_risk_level']})"
            )

            # Print context notes from first report
            for sa in all_smart_analyses:
                for note in sa.get("context_notes", []):
                    print(f"\n{note}")

            print(f"\n💡 Recommendation: {combined['recommendation']}")

            # Check for potential libraries to verify
            if all_potential_libraries:
                print(
                    f"\n🔍 Potential libraries detected: {', '.join(list(all_potential_libraries)[:5])}"
                )
                print(
                    "   → Would you like me to web search to verify these are legitimate?"
                )

            print("\n" + "=" * 60)

            # Print full JSON
            print(json.dumps(combined, indent=2))

            if combined["overall_risk_level"] in ["HIGH", "CRITICAL"]:
                sys.exit(2)
            elif combined["overall_risk_level"] == "MEDIUM":
                sys.exit(1)
            else:
                sys.exit(0)
            return

        print(json.dumps(report, indent=2))

        if report.get("risk_level") in ["HIGH", "CRITICAL"]:
            sys.exit(2)
        elif report.get("risk_level") == "MEDIUM":
            sys.exit(1)
        else:
            sys.exit(0)
        return

    validator = SecurityValidator(target)
    report = validator.analyze()

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
