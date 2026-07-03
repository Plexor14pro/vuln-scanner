<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">VulnScan</h1>

<p align="center">Lightweight security scanner for source code. Upload your project and find vulnerabilities before deploying.</p>

---

### About

VulnScan is a web-based tool that scans source code for security vulnerabilities. Upload a `.zip` file or individual source files and get an instant report with severity ratings, line numbers, and fix recommendations.

Built for developers, students, and teams who need a quick security check before deploying.

### How It Works

1. **Upload** — Drag and drop a `.zip` archive or select a source code file
2. **Scan** — The engine analyzes every line against 15 vulnerability rules using regex pattern matching
3. **Report** — Results are sorted by severity with code snippets, descriptions, and how to fix each issue

### Vulnerability Rules

| ID | Severity | What It Detects |
|---|---|---|
| SEC001 | CRITICAL | Hardcoded passwords and secrets |
| SEC002 | CRITICAL | Exposed private keys |
| SEC003 | HIGH | SQL injection patterns |
| SEC004 | HIGH | Cross-Site Scripting (XSS) |
| SEC005 | HIGH | Command injection |
| SEC006 | MEDIUM | Insecure HTTP usage |
| SEC007 | MEDIUM | Weak cryptographic hashes (MD5, SHA1) |
| SEC008 | MEDIUM | Debug mode enabled |
| SEC009 | MEDIUM | CORS wildcard configuration |
| SEC010 | LOW | TODO/FIXME with security notes |
| SEC011 | HIGH | Path traversal |
| SEC012 | CRITICAL | AWS keys exposed |
| SEC013 | MEDIUM | Insecure deserialization (pickle, yaml.load) |
| SEC014 | LOW | Missing error handling |
| SEC015 | HIGH | Insecure file upload |

### Supported Languages

Python, JavaScript, TypeScript, Java, PHP, Ruby, Go, Rust, C, C++, C#, Shell, YAML, JSON, XML, HTML, SQL, Terraform, Dockerfile

### Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript (vanilla)
- **Scanning:** Regex-based pattern matching (no external dependencies)

### Installation

```bash
git clone https://github.com/Plexor14pro/vuln-scanner.git
cd vuln-scanner
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

### Project Structure

```
vuln-scanner/
├── app.py              # Scanning engine + Flask routes
├── requirements.txt    # Dependencies
├── README.md           # Documentation
├── static/
│   └── style.css       # Dark UI styling
└── templates/
    └── index.html      # Upload interface + results
```

### Roadmap

- [ ] Support for more language-specific patterns
- [ ] Dependency vulnerability checking
- [ ] PDF report export
- [ ] CLI version
- [ ] CI/CD integration

### License

MIT License
