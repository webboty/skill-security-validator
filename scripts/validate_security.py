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
                self.findings.append(
                    {
                        "type": "malicious_filename",
                        "severity": "CRITICAL",
                        "file": str(file_path),
                        "line": 0,
                        "pattern": f"Suspicious filename contains: {keyword}",
                        "content": file_path.name,
                    }
                )
                self.risk_score += 25

    def _check_malicious_keywords(self, line: str, file_path: Path, line_num: int):
        line_lower = line.lower()
        for keyword in self.MALICIOUS_KEYWORDS:
            if keyword in line_lower:
                self.findings.append(
                    {
                        "type": "malicious_keyword",
                        "severity": "CRITICAL",
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": f"Malicious/attack keyword: {keyword}",
                        "content": line.strip()[:100],
                    }
                )
                self.risk_score += 20

    def _check_sensitive_files(self, line: str, file_path: Path, line_num: int):
        for pattern, description in self.SENSITIVE_FILE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                self.findings.append(
                    {
                        "type": "sensitive_file_access",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": description,
                        "content": line.strip()[:100],
                    }
                )
                self.risk_score += 15

    def _check_patterns(self, line: str, file_path: Path, line_num: int):
        for pattern, description in self.DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                self.findings.append(
                    {
                        "type": "dangerous_pattern",
                        "severity": "HIGH",
                        "file": str(file_path),
                        "line": line_num,
                        "pattern": description,
                        "content": line.strip()[:100],
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
                    }
                )
                self.risk_score += 5
                break

    def _calculate_risk(self):
        if self.risk_score == 0:
            self.risk_level = "SAFE"
        elif self.risk_score < 10:
            self.risk_level = "LOW"
        elif self.risk_score < 30:
            self.risk_level = "MEDIUM"
        elif self.risk_score < 50:
            self.risk_level = "HIGH"
        else:
            self.risk_level = "CRITICAL"

    def _generate_report(self) -> Dict[str, Any]:
        return {
            "target_path": str(self.target_path),
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "total_findings": len(self.findings),
            "findings": self.findings,
            "recommendation": self._get_recommendation(),
        }

    def _get_recommendation(self) -> str:
        if self.risk_level == "SAFE":
            return "This skill/script appears safe for use."
        elif self.risk_level == "LOW":
            return "Minor concerns detected. Review findings before use."
        elif self.risk_level == "MEDIUM":
            return "Exercise caution. Review all findings carefully."
        elif self.risk_level == "HIGH":
            return "HIGH RISK - Do not use without thorough manual review."
        else:
            return "CRITICAL RISK - Strongly recommend NOT using this skill/script."


def main():
    if len(sys.argv) < 2:
        print("Usage: validate_security.py <path-to-skill-or-script>")
        sys.exit(1)

    target = sys.argv[1]
    validator = SecurityValidator(target)
    report = validator.analyze()

    print(json.dumps(report, indent=2))

    if report.get("risk_level") in ["HIGH", "CRITICAL"]:
        sys.exit(2)
    elif report.get("risk_level") == "MEDIUM":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
