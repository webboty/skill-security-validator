# Output Format

The security validator outputs results in a structured format:

## Script Output (Automated)

```
=================================================================
║               SECURITY SCAN RESULTS                       ║
╚═══════════════════════════════════════════════════════════╝

📦 Skill: [skill-name]
📍 Location: [path]

┌─────────────────────────────────────────────────────────┐
│  SCRIPT SCAN RESULTS (automated)                        │
├─────────────────────────────────────────────────────────┤
│  Risk Level:    [LEVEL]                                 │
│  Risk Score:    [SCORE]/100                             │
│  Code Issues:   [X] findings                            │
└─────────────────────────────────────────────────────────┘

📂 Files Checked: [X] total
⚠️  Issues Found: [X]

🔍 Sample Issues:
    • [type]: [pattern]
      File: [filename]:[line]
```

## Risk Levels

| Level | Score | Action |
|-------|-------|--------|
| SAFE | 0 | OK to use |
| LOW | 1-9 | Minor concerns - review |
| MEDIUM | 10-29 | Exercise caution |
| HIGH | 30-49 | Do not use without review |
| CRITICAL | 50+ | Strongly recommend NOT using |
