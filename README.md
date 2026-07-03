<p align="center">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">VulnScan</h1>

<p align="center">Scan your source code for security vulnerabilities before deploying.</p>

---

### About

VulnScan is a lightweight web-based security scanner that analyzes source code for common vulnerabilities. Upload a `.zip` file or individual source files and get an instant report with severity ratings, descriptions, and fix suggestions.

### Features

- Upload `.zip` archives or individual files
- Scans multiple languages (Python, JavaScript, Java, PHP, Go, Ruby, C, and more)
- 15+ vulnerability rules covering:
  - Hardcoded secrets & API keys
  - SQL injection
  - Cross-Site Scripting (XSS)
  - Command injection
  - Path traversal
  - Insecure cryptography
  - AWS key exposure
  - Insecure deserialization
  - And more
- Severity ratings: CRITICAL, HIGH, MEDIUM, LOW
- Code snippets with line numbers
- Fix recommendations for each finding
- Clean, modern dark UI

### Tech Stack

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, JavaScript
- **Scanning:** Regex-based pattern matching

### Installation

```bash
git clone https://github.com/Plexor14pro/vuln-scanner.git
cd vuln-scanner
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

### Usage

1. Open the app in your browser
2. Drag and drop a `.zip` file or click to browse
3. Wait for the scan to complete
4. Review the findings sorted by severity

### Roadmap

- [ ] Support for more languages and frameworks
- [ ] Dependency vulnerability checking
- [ ] PDF report export
- [ ] CLI version
- [ ] CI/CD integration

### License

MIT License
