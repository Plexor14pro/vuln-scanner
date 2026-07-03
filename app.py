import os
import re
import zipfile
import tempfile
import shutil
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

VULNERABILITY_RULES = [
    {
        'id': 'SEC001',
        'severity': 'CRITICAL',
        'title': 'Hardcoded Secret/Password',
        'pattern': r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth)\s*[:=]\s*["\'][^"\']{4,}["\']',
        'description': 'A hardcoded secret or password was found. Never commit secrets to source code.',
        'fix': 'Use environment variables or a secrets manager.'
    },
    {
        'id': 'SEC002',
        'severity': 'CRITICAL',
        'title': 'Private Key Exposed',
        'pattern': r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        'description': 'A private key was found in the code. This is a critical security risk.',
        'fix': 'Remove the key immediately and rotate it. Use a secrets manager.'
    },
    {
        'id': 'SEC003',
        'severity': 'HIGH',
        'title': 'SQL Injection Vulnerability',
        'pattern': r'(?i)(execute|cursor\.execute|query)\s*\(\s*["\'].*(%s|%d|\{|\+).*["\']',
        'description': 'Possible SQL injection. User input may be directly concatenated into SQL queries.',
        'fix': 'Use parameterized queries or ORM instead of string formatting.'
    },
    {
        'id': 'SEC004',
        'severity': 'HIGH',
        'title': 'Cross-Site Scripting (XSS)',
        'pattern': r'(?i)(innerHTML|document\.write|eval\s*\(|setTimeout\s*\(\s*["\']|setInterval\s*\(\s*["\'])',
        'description': 'Possible XSS vulnerability. Unescaped user input may be executed as code.',
        'fix': 'Sanitize and escape all user input before rendering.'
    },
    {
        'id': 'SEC005',
        'severity': 'HIGH',
        'title': 'Command Injection',
        'pattern': r'(?i)(os\.system|subprocess\.call|subprocess\.Popen|exec\s*\(|eval\s*\()',
        'description': 'Possible command injection. User input may be passed to system commands.',
        'fix': 'Use subprocess with shell=False and validate input.'
    },
    {
        'id': 'SEC006',
        'severity': 'MEDIUM',
        'title': 'Insecure HTTP Usage',
        'pattern': r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
        'description': 'HTTP (not HTTPS) is being used. Data may be transmitted in cleartext.',
        'fix': 'Use HTTPS for all external connections.'
    },
    {
        'id': 'SEC007',
        'severity': 'MEDIUM',
        'title': 'Weak Cryptographic Hash',
        'pattern': r'(?i)(md5|sha1)\s*\(',
        'description': 'A weak hashing algorithm (MD5/SHA1) is being used.',
        'fix': 'Use SHA-256 or stronger for hashing. Use bcrypt for passwords.'
    },
    {
        'id': 'SEC008',
        'severity': 'MEDIUM',
        'title': 'Debug Mode Enabled',
        'pattern': r'(?i)(debug\s*=\s*true|DEBUG\s*=\s*True|app\.run\(.*debug)',
        'description': 'Debug mode is enabled. This may expose sensitive information.',
        'fix': 'Disable debug mode in production.'
    },
    {
        'id': 'SEC009',
        'severity': 'MEDIUM',
        'title': 'CORS Wildcard',
        'pattern': r'(?i)(Access-Control-Allow-Origin.*\*|CORS.*\*)',
        'description': 'CORS is configured to allow all origins. This may allow unauthorized access.',
        'fix': 'Restrict CORS to specific trusted domains.'
    },
    {
        'id': 'SEC010',
        'severity': 'LOW',
        'title': 'TODO/FIXME with Security Note',
        'pattern': r'(?i)(TODO|FIXME|HACK|XXX).*(security|vuln|hack|exploit|password|secret)',
        'description': 'A TODO or FIXME comment mentions a security concern.',
        'fix': 'Address the security issue noted in the comment.'
    },
    {
        'id': 'SEC011',
        'severity': 'HIGH',
        'title': 'Path Traversal',
        'pattern': r'(?i)(open|read|write)\s*\(.*(\.\.\/|\.\.\\)',
        'description': 'Possible path traversal. Directory navigation may be exploited.',
        'fix': 'Validate and sanitize file paths. Use os.path.abspath.'
    },
    {
        'id': 'SEC012',
        'severity': 'CRITICAL',
        'title': 'AWS Keys Exposed',
        'pattern': r'(?i)(AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key)',
        'description': 'AWS credentials were found in the code.',
        'fix': 'Use IAM roles or environment variables. Rotate keys immediately.'
    },
    {
        'id': 'SEC013',
        'severity': 'MEDIUM',
        'title': 'Insecure Deserialization',
        'pattern': r'(?i)(pickle\.loads|yaml\.load\s*\(|marshal\.loads)',
        'description': 'Insecure deserialization detected. This can lead to remote code execution.',
        'fix': 'Use yaml.safe_load() instead of yaml.load(). Avoid pickle with untrusted data.'
    },
    {
        'id': 'SEC014',
        'severity': 'LOW',
        'title': 'Missing Error Handling',
        'pattern': r'except\s*:\s*(pass|continue)',
        'description': 'Bare except clause with pass/continue. Errors are being silently swallowed.',
        'fix': 'Catch specific exceptions and handle them properly.'
    },
    {
        'id': 'SEC015',
        'severity': 'HIGH',
        'title': 'Insecure File Upload',
        'pattern': r'(?i)(save|write|upload).*filename',
        'description': 'File upload without proper validation. May allow arbitrary file write.',
        'fix': 'Validate file types, sanitize filenames, and store outside web root.'
    },
]

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.php', '.rb', '.go',
    '.rs', '.c', '.cpp', '.h', '.cs', '.sh', '.bash', '.yml', '.yaml',
    '.json', '.xml', '.env', '.cfg', '.conf', '.ini', '.properties',
    '.sql', '.html', '.htm', '.vue', '.svelte', '.tf', '.dockerfile'
}

def scan_file(filepath, content):
    findings = []
    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        for rule in VULNERABILITY_RULES:
            if re.search(rule['pattern'], line):
                findings.append({
                    'rule_id': rule['id'],
                    'severity': rule['severity'],
                    'title': rule['title'],
                    'description': rule['description'],
                    'fix': rule['fix'],
                    'file': filepath,
                    'line': line_num,
                    'code': line.strip()[:120]
                })
    return findings

def scan_directory(directory):
    all_findings = []
    scanned_files = 0
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', 'venv', '.venv', 'vendor'}]
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SCANNABLE_EXTENSIONS or filename in {'.env', 'Dockerfile', 'docker-compose.yml'}:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, directory)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    findings = scan_file(rel_path, content)
                    all_findings.extend(findings)
                    scanned_files += 1
                except Exception:
                    pass
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x['severity'], 99))
    return all_findings, scanned_files

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    tmpdir = tempfile.mkdtemp()
    try:
        filename = file.filename.lower()
        if filename.endswith('.zip'):
            zip_path = os.path.join(tmpdir, 'upload.zip')
            file.save(zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(tmpdir)
            os.remove(zip_path)
        else:
            file.save(os.path.join(tmpdir, file.filename))

        findings, scanned_files = scan_directory(tmpdir)

        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            severity_count[f['severity']] += 1

        return jsonify({
            'status': 'ok',
            'scanned_files': scanned_files,
            'total_findings': len(findings),
            'severity_count': severity_count,
            'findings': findings
        })
    except zipfile.BadZipFile:
        return jsonify({'error': 'Invalid ZIP file'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
