/**
 * PhishGuard – Main Application JavaScript v2
 * Handles URL scanning, QR code scanning, PDF reports,
 * cybercrime reporting, and all UI interactions.
 */

// ──────────────────────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────────────────────
const API_BASE = window.location.origin + '/api';
const DEFAULT_API = (window.location.port === '5000' || window.location.port === '3000')
    ? API_BASE
    : (window.location.protocol + '//' + window.location.hostname + ':5000/api');

let lastScanResult = null;
let html5QrCode = null;
let qrScannerActive = false;

// ──────────────────────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    createParticles();
    loadStats();
    loadRecentScans();
    setupDragDrop();

    // Allow Enter key to trigger scan
    document.getElementById('urlInput').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') scanURL();
    });
});

// ──────────────────────────────────────────────────────────────
// Particle Background
// ──────────────────────────────────────────────────────────────
function createParticles() {
    const container = document.getElementById('particles');
    if (!container) return;
    for (let i = 0; i < 25; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 8 + 's';
        particle.style.animationDuration = (6 + Math.random() * 6) + 's';
        const colors = ['var(--accent-cyan)', 'var(--accent-purple)', 'var(--accent-green)'];
        particle.style.background = colors[Math.floor(Math.random() * colors.length)];
        particle.style.width = (2 + Math.random() * 3) + 'px';
        particle.style.height = particle.style.width;
        container.appendChild(particle);
    }
}

// ──────────────────────────────────────────────────────────────
// Scan Mode Tabs (URL / QR)
// ──────────────────────────────────────────────────────────────
function switchScanMode(mode) {
    // Update tabs
    document.getElementById('tabUrl').classList.toggle('active', mode === 'url');
    document.getElementById('tabQr').classList.toggle('active', mode === 'qr');
    document.getElementById('tabEmail').classList.toggle('active', mode === 'email');

    // Show/hide panels
    document.getElementById('urlPanel').classList.toggle('active', mode === 'url');
    document.getElementById('qrPanel').classList.toggle('active', mode === 'qr');
    document.getElementById('emailPanel').classList.toggle('active', mode === 'email');

    // Stop camera if switching away from QR
    if (mode !== 'qr') {
        stopQrCamera();
    }
}

// ──────────────────────────────────────────────────────────────
// URL Scanning
// ──────────────────────────────────────────────────────────────
async function scanURL() {
    const input = document.getElementById('urlInput');
    const btn = document.getElementById('scanBtn');
    let url = input.value.trim();

    if (!url) {
        showToast('Please enter a URL to scan.', 'error');
        input.focus();
        return;
    }

    if (!url.match(/^https?:\/\//i) && !url.match(/^ftp:\/\//i)) {
        url = 'http://' + url;
    }

    showLoading(true);
    btn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Scan failed');

        await animateLoadingText([
            'Extracting URL features...',
            'Running ML analysis...',
            'Generating risk assessment...'
        ]);

        lastScanResult = data;
        displayResult(data);
        loadStats();
        loadRecentScans();
        showToast('URL scan complete!', 'success');

    } catch (err) {
        console.error('Scan error:', err);
        showToast(err.message || 'Failed to scan URL.', 'error');
    } finally {
        showLoading(false);
        btn.disabled = false;
    }
}

// ──────────────────────────────────────────────────────────────
// Email Content Scanning
// ──────────────────────────────────────────────────────────────
async function scanEmail() {
    const input = document.getElementById('emailInput');
    const btn = document.getElementById('emailScanBtn');
    const content = input.value.trim();

    if (!content || content.length < 10) {
        showToast('Please enter at least 10 characters of email content.', 'error');
        input.focus();
        return;
    }

    showLoading(true);
    document.getElementById('loadingText').textContent = 'Analyzing Email...';
    btn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/scan-email`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Email scan failed');

        await animateLoadingText([
            'Scanning for urgency indicators...',
            'Harvesting embedded links...',
            'Analyzing psychological triggers...',
            'Generating combined risk score...'
        ]);

        lastScanResult = data;
        displayResult(data, 'email');
        loadStats();
        loadRecentScans();
        showToast('Email content analysis complete!', 'success');

    } catch (err) {
        console.error('Email scan error:', err);
        showToast(err.message || 'Failed to scan email.', 'error');
    } finally {
        showLoading(false);
        btn.disabled = false;
    }
}

// ── Email Test Samples Logic ──
let emailSamples = [];

async function fetchEmailSamples() {
    try {
        const response = await fetch(`${API_BASE}/email-samples`);
        const data = await response.json();
        if (response.ok) {
            emailSamples = data;
            populateEmailSamplesDropdown();
        }
    } catch (err) {
        console.error('Failed to fetch email samples:', err);
    }
}

function populateEmailSamplesDropdown() {
    const dropdown = document.getElementById('emailSamplesDropdown');
    if (!dropdown) return;

    dropdown.innerHTML = emailSamples.map((sample, index) => {
        const icon = sample.phishing ? '⚠️' : '✅';
        const label = sample.category || (sample.subject ? sample.subject.substring(0, 20) + '...' : 'Sample');
        return `<a href="javascript:void(0)" onclick="loadEmailSample(${index})">${icon} ${label}</a>`;
    }).join('');
}

function toggleSampleDropdown() {
    const dropdown = document.getElementById('emailSamplesDropdown');
    if (dropdown) {
        if (emailSamples.length === 0) {
            fetchEmailSamples();
        }
        dropdown.classList.toggle('show');
    }
}

function loadEmailSample(index) {
    const sample = emailSamples[index];
    if (sample) {
        document.getElementById('emailInput').value = sample.content;
        const label = sample.category || 'sample';
        showToast(`Loaded ${label} sample`, 'info');
        toggleSampleDropdown();
    }
}

// ──────────────────────────────────────────────────────────────
// QR Code Scanning – Camera
// ──────────────────────────────────────────────────────────────
function startQrCamera() {
    const container = document.getElementById('qrCameraContainer');
    const options = document.getElementById('qrOptions');
    const fileUpload = document.getElementById('qrFileUpload');

    options.style.display = 'none';
    fileUpload.classList.remove('active');
    container.classList.add('active');

    if (qrScannerActive) return;

    // Check if Html5Qrcode is available
    if (typeof Html5Qrcode === 'undefined') {
        showToast('QR scanner library not loaded. Please refresh the page.', 'error');
        return;
    }

    html5QrCode = new Html5Qrcode("qr-reader");
    qrScannerActive = true;

    html5QrCode.start(
        { facingMode: "environment" },
        {
            fps: 10,
            qrbox: { width: 250, height: 250 },
            aspectRatio: 1.0
        },
        (decodedText) => {
            // QR code found
            onQrDecoded(decodedText, 'qr_camera');
            stopQrCamera();
        },
        (errorMessage) => {
            // Scan in progress, no QR found yet (normal)
        }
    ).catch((err) => {
        console.error("QR Camera error:", err);
        showToast('Unable to access camera. Please allow camera permission or try uploading an image.', 'error');
        stopQrCamera();
    });
}

function stopQrCamera() {
    const container = document.getElementById('qrCameraContainer');
    const options = document.getElementById('qrOptions');

    if (html5QrCode && qrScannerActive) {
        html5QrCode.stop().then(() => {
            html5QrCode.clear();
            qrScannerActive = false;
        }).catch(() => {
            qrScannerActive = false;
        });
    }

    container.classList.remove('active');
    options.style.display = 'flex';
}

// ──────────────────────────────────────────────────────────────
// QR Code Scanning – File Upload
// ──────────────────────────────────────────────────────────────
function openQrFileUpload() {
    const fileUpload = document.getElementById('qrFileUpload');
    const options = document.getElementById('qrOptions');
    const container = document.getElementById('qrCameraContainer');

    stopQrCamera();
    // Hide camera and options, show file upload UI
    if (options) options.style.display = 'none';
    if (container) container.classList.remove('active');
    if (fileUpload) fileUpload.classList.add('active');
    console.log('Opened QR file upload panel');
}

function setupDragDrop() {
    const dropZone = document.getElementById('fileDropZone');
    if (!dropZone) return;

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) {
            processQrImage(file);
        } else {
            showToast('Please drop an image file.', 'error');
        }
    });
}

function handleQrFile(event) {
    const file = event.target.files[0];
    if (file) {
        showToast(`Processing ${file.name}...`, 'info');
        processQrImage(file);
    }
}

function processQrImage(file) {
    if (typeof Html5Qrcode === 'undefined') {
        showToast('QR scanner library not loaded. Please refresh.', 'error');
        return;
    }

    const tempId = "qr-reader-temp-" + Date.now();
    const tempDiv = document.createElement('div');
    tempDiv.id = tempId;
    tempDiv.style.display = 'none';
    document.body.appendChild(tempDiv);

    const scanner = new Html5Qrcode(tempId);

    scanner.scanFile(file, true)
        .then((decodedText) => {
            onQrDecoded(decodedText, 'qr_image');
        })
        .catch((err) => {
            console.error("QR file scan error:", err);
            showToast('No QR code detected in the image. Please try another image.', 'error');
        })
        .finally(() => {
            tempDiv.remove();
            // Reset UI: hide file upload panel, show options again
            const fileUpload = document.getElementById('qrFileUpload');
            const options = document.getElementById('qrOptions');
            if (fileUpload) fileUpload.classList.remove('active');
            if (options) options.style.display = 'flex';
            // Clear file input
            const fileInput = document.getElementById('qrFileInput');
            if (fileInput) fileInput.value = '';
        });
}

async function onQrDecoded(decodedText, source) {
    // Show decoded URL
    const decodedUrlDiv = document.getElementById('qrDecodedUrl');
    const decodedValue = document.getElementById('decodedUrlValue');
    decodedValue.textContent = decodedText;
    decodedUrlDiv.classList.add('active');

    showToast(`QR Code decoded: ${decodedText.substring(0, 50)}...`, 'success');

    // Check if it's a URL
    const urlPattern = /^(https?:\/\/|ftp:\/\/|www\.)/i;
    let url = decodedText;

    if (!urlPattern.test(url)) {
        // It might still be a domain-like string
        if (url.includes('.') && !url.includes(' ')) {
            url = 'http://' + url;
        } else {
            showToast('The QR code does not contain a valid URL.', 'error');
            return;
        }
    }

    if (!url.match(/^https?:\/\//i)) {
        url = 'http://' + url;
    }

    // Auto-scan the decoded URL
    showLoading(true);

    try {
        const response = await fetch(`${API_BASE}/scan-qr`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, source })
        });

        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'QR scan failed');

        await animateLoadingText([
            'QR code decoded successfully...',
            'Extracting URL features...',
            'Running ML analysis...',
        ]);

        lastScanResult = data;
        displayResult(data);
        loadStats();
        loadRecentScans();

        showToast('QR code URL scan complete!', 'success');

    } catch (err) {
        console.error('QR scan error:', err);
        showToast(err.message || 'Failed to scan QR URL.', 'error');
    } finally {
        showLoading(false);
    }
}

// ──────────────────────────────────────────────────────────────
// Loading & Helpers
// ──────────────────────────────────────────────────────────────
async function animateLoadingText(phases) {
    const textEl = document.getElementById('loadingText');
    for (const text of phases) {
        textEl.textContent = text;
        await sleep(500);
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function showLoading(show) {
    const overlay = document.getElementById('loadingOverlay');
    if (show) {
        document.getElementById('loadingText').textContent = 'Analyzing URL...';
        overlay.classList.add('active');
    } else {
        overlay.classList.remove('active');
    }
}

// ──────────────────────────────────────────────────────────────
// Display Result
// ──────────────────────────────────────────────────────────────
function displayResult(data, type = 'url') {
    const section = document.getElementById('resultSection');
    section.classList.add('visible');

    const prediction = data.prediction.toLowerCase();

    // Result icon
    const iconEl = document.getElementById('resultIcon');
    const predEl = document.getElementById('resultPrediction');
    const sourceEl = document.getElementById('resultSource');

    const icons = { safe: '✅', suspicious: '⚠️', phishing: '🚫' };
    iconEl.textContent = icons[prediction] || '❓';
    iconEl.className = 'result-icon ' + prediction;

    predEl.textContent = data.prediction;
    predEl.className = 'result-prediction ' + prediction;

    // Source label
    sourceEl.textContent = data.scan_source ? `via ${data.scan_source}` : (type === 'email' ? 'via Email Analysis' : '');

    // Confidence
    animateCounter('confidenceValue', data.confidence, '%');

    // Risk score
    const riskBar = document.getElementById('riskBar');
    const riskValue = document.getElementById('riskValue');
    riskBar.style.width = data.risk_score + '%';
    riskBar.className = 'risk-bar-fill ' + prediction;
    riskValue.textContent = Math.round(data.risk_score) + '/100';

    // Toggle sections based on scan type
    const probSection = document.getElementById('probabilitySection');
    const flagsSection = document.getElementById('emailFlagsSection');
    const featSection = document.querySelector('.features-section');

    if (type === 'email') {
        probSection.style.display = 'none';
        featSection.style.display = 'none';
        flagsSection.style.display = 'block';

        // Display flags
        const flagList = document.getElementById('emailFlagsList');
        flagList.innerHTML = (data.flags && data.flags.length > 0)
            ? data.flags.map(f => `<div class="email-flag-item">${escapeHtml(f)}</div>`).join('')
            : '<div class="email-flag-item" style="color:var(--text-muted)">No major text-based red flags detected.</div>';

        // Display links
        const linkList = document.getElementById('emailLinksFound');
        if (data.urls_found && data.urls_found.length > 0) {
            linkList.innerHTML = `<h4>🔗 Extracted Links (${data.urls_found.length})</h4>` +
                data.urls_found.map(url => {
                    const r = Math.round(url.risk_score);
                    const riskClass = r > 70 ? 'risk-high' : (r > 30 ? 'risk-med' : 'risk-low');
                    return `
                        <div class="email-link-item">
                            <a href="${url.url}" target="_blank" class="email-link-url" title="${url.url}">${escapeHtml(url.url)}</a>
                            <span class="email-link-risk ${riskClass}">${url.prediction} (${r}%)</span>
                        </div>
                    `;
                }).join('');
        } else {
            linkList.innerHTML = `<h4>🔗 No links found in content</h4>`;
        }
    } else {
        probSection.style.display = 'block';
        featSection.style.display = 'block';
        flagsSection.style.display = 'none';

        // Probability bars
        if (data.probabilities) {
            animateBar('probSafe', data.probabilities.safe);
            document.getElementById('probSafeVal').textContent = data.probabilities.safe + '%';
            animateBar('probSuspicious', data.probabilities.suspicious);
            document.getElementById('probSuspiciousVal').textContent = data.probabilities.suspicious + '%';
            animateBar('probPhishing', data.probabilities.phishing);
            document.getElementById('probPhishingVal').textContent = data.probabilities.phishing + '%';
        }

        // Features
        displayFeatures(data.features || {});
    }

    // Timestamp
    const tsEl = document.getElementById('scanTimestamp');
    const ts = new Date(data.timestamp);
    tsEl.textContent = ts.toLocaleString();

    // SSL Trust Trap / Security Insight
    const insightBox = document.getElementById('securityInsight');
    const isPhish = (prediction === 'phishing' || prediction === 'suspicious');

    // In email scans, we check for flags added by backend
    const hasSslTrapFlag = (data.flags && data.flags.some(f => f.includes('HTTPS Trust Trap')));

    // In URL scans, check has_https feature
    const isSslUrl = (data.features && data.features.has_https);

    if (isPhish && (isSslUrl || hasSslTrapFlag)) {
        insightBox.style.display = 'block';
        insightBox.className = 'security-insight visible';
        insightBox.innerHTML = `
            <div class="insight-badge pulse">🛡️ SSL Intelligence Notice</div>
            <p style="margin-top:0.5rem; color:var(--text-primary); font-size:0.9rem;">
                <strong>Trust Trap Detected:</strong> This site uses HTTPS (the padlock) to appear safe. 
                However, encryption simply protects data in transit; it does <strong>not</strong> prove identity. 
                Our analysis shows this site is misusing SSL for phishing.
            </p>
        `;
    } else {
        insightBox.style.display = 'none';
        insightBox.className = 'security-insight';
    }

    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function animateCounter(elementId, target, suffix = '') {
    const el = document.getElementById(elementId);
    let current = 0;
    const step = target / 30;
    const interval = setInterval(() => {
        current += step;
        if (current >= target) {
            current = target;
            clearInterval(interval);
        }
        el.textContent = current.toFixed(1) + suffix;
    }, 30);
}

function animateBar(elementId, widthPercent) {
    const el = document.getElementById(elementId);
    el.style.width = '0%';
    setTimeout(() => {
        el.style.width = widthPercent + '%';
    }, 100);
}

function displayFeatures(features) {
    const grid = document.getElementById('featuresGrid');
    grid.innerHTML = '';

    const labels = {
        'url_length': 'URL Length', 'domain_length': 'Domain Length',
        'path_length': 'Path Length', 'num_dots': 'Dot Count',
        'num_hyphens': 'Hyphen Count', 'num_underscores': 'Underscore Count',
        'num_slashes': 'Slash Count', 'num_digits': 'Digit Count',
        'num_subdomains': 'Subdomains', 'digit_letter_ratio': 'Digit/Letter Ratio',
        'url_entropy': 'URL Entropy', 'domain_entropy': 'Domain Entropy',
        'has_ip_address': 'IP Address', 'has_https': 'HTTPS',
        'has_at_symbol': '"@" Symbol', 'has_double_slash_redirect': 'Double Slash //',
        'has_dash_in_domain': 'Dash in Domain', 'has_equals': '"=" Present',
        'has_question_mark': '"?" Present', 'has_ampersand': '"&" Present',
        'has_tilde': '"~" Present', 'has_percent_encoding': '% Encoding',
        'has_non_standard_port': 'Non-Std Port', 'has_suspicious_tld': 'Suspicious TLD',
        'has_www': 'Has WWW', 'has_fragment': 'Has Fragment',
        'suspicious_word_count': 'Suspicious Words', 'num_query_params': 'Query Params',
        'query_length': 'Query Length', 'num_path_tokens': 'Path Tokens',
        'max_path_token_length': 'Max Path Token Len', 'special_char_ratio': 'Special Char Ratio',
    };

    for (const [key, value] of Object.entries(features)) {
        const item = document.createElement('div');
        item.className = 'feature-item';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'feature-name';
        nameSpan.textContent = labels[key] || key;

        const valueSpan = document.createElement('span');
        valueSpan.className = 'feature-value';

        if (key.startsWith('has_')) {
            valueSpan.textContent = value ? 'Yes' : 'No';
            valueSpan.classList.add(value ? 'true' : 'false');
        } else if (typeof value === 'number') {
            valueSpan.textContent = Number.isInteger(value) ? value : value.toFixed(4);
        } else {
            valueSpan.textContent = value;
        }

        item.appendChild(nameSpan);
        item.appendChild(valueSpan);
        grid.appendChild(item);
    }
}

function toggleFeatures() {
    const grid = document.getElementById('featuresGrid');
    const icon = document.getElementById('toggleIcon');
    grid.classList.toggle('visible');
    icon.classList.toggle('open');
}

// ──────────────────────────────────────────────────────────────
// DOCX Report Download
// ──────────────────────────────────────────────────────────────
async function downloadDocxReport() {
    if (!lastScanResult) {
        showToast('No scan result to export. Scan a URL first.', 'error');
        return;
    }

    showToast('Generating DOCX report...', 'info');

    try {
        const response = await fetch(`${API_BASE}/generate-report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(lastScanResult)
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'DOCX generation failed');
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;

        // Get filename from Content-Disposition header or generate one
        const disposition = response.headers.get('Content-Disposition');
        let filename = 'PhishGuard_Report.docx';
        if (disposition) {
            const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (match) filename = match[1].replace(/['"]/g, '');
        }

        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);

        showToast('DOCX report downloaded successfully!', 'success');

    } catch (err) {
        console.error('DOCX generation error:', err);
        showToast(err.message || 'Failed to generate DOCX.', 'error');
    }
}

// ──────────────────────────────────────────────────────────────
// Cybercrime Reporting
// ──────────────────────────────────────────────────────────────
function openCybercrimePortal() {
    // Opens the cybercrime portal in a new tab
    window.open('https://cybercrime.gov.in', '_blank', 'noopener,noreferrer');
    showToast('Opening National Cybercrime Reporting Portal...', 'info');
}

// ──────────────────────────────────────────────────────────────
// Report Modal
// ──────────────────────────────────────────────────────────────
function openReportModal() {
    if (!lastScanResult) {
        showToast('No scan result to report. Scan something first.', 'error');
        return;
    }

    let reportUrl = lastScanResult.url || '';

    // If it's an email scan with a malicious link, suggest reporting that link instead
    if (lastScanResult.is_email_scan && lastScanResult.urls_found && lastScanResult.urls_found.length > 0) {
        const malicious = lastScanResult.urls_found.find(u => u.risk_score > 50);
        if (malicious) reportUrl = malicious.url;
    }

    document.getElementById('reportUrl').value = reportUrl;
    document.getElementById('reportReason').value = '';
    document.getElementById('reportModal').classList.add('active');
}

function closeReportModal() {
    document.getElementById('reportModal').classList.remove('active');
}

async function submitReport() {
    const url = document.getElementById('reportUrl').value;
    const reason = document.getElementById('reportReason').value.trim();

    if (!reason) {
        showToast('Please provide a reason for the report.', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/report-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url,
                reason,
                report_to_cybercrime: true
            })
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Report failed');

        closeReportModal();
        showToast('URL reported successfully! Consider also reporting to cybercrime authorities using the links provided.', 'success');

    } catch (err) {
        showToast(err.message || 'Failed to submit report.', 'error');
    }
}

// ──────────────────────────────────────────────────────────────
// Copy Result
// ──────────────────────────────────────────────────────────────
function copyResult() {
    if (!lastScanResult) return;

    const text = `PhishGuard Scan Result
URL: ${lastScanResult.url}
Source: ${lastScanResult.scan_source || 'URL Input'}
Prediction: ${lastScanResult.prediction}
Confidence: ${lastScanResult.confidence}%
Risk Score: ${Math.round(lastScanResult.risk_score)}/100
Scanned: ${lastScanResult.timestamp}`;

    navigator.clipboard.writeText(text)
        .then(() => showToast('Result copied to clipboard!', 'success'))
        .catch(() => showToast('Failed to copy.', 'error'));
}

// ──────────────────────────────────────────────────────────────
// Statistics
// ──────────────────────────────────────────────────────────────
async function loadStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const data = await res.json();
        animateStatCounter('statTotal', data.total_scans || 0);
        animateStatCounter('statSafe', data.safe_count || 0);
        animateStatCounter('statSuspicious', data.suspicious_count || 0);
        animateStatCounter('statPhishing', data.phishing_count || 0);
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

function animateStatCounter(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const current = parseInt(el.textContent) || 0;
    if (current === target) return;
    let count = current;
    const step = Math.max(1, Math.ceil((target - current) / 20));
    const interval = setInterval(() => {
        count += step;
        if (count >= target) {
            count = target;
            clearInterval(interval);
        }
        el.textContent = count;
    }, 40);
}

// ──────────────────────────────────────────────────────────────
// Recent Scans
// ──────────────────────────────────────────────────────────────
async function loadRecentScans() {
    try {
        const res = await fetch(`${API_BASE}/recent-scans?limit=30`);
        const data = await res.json();
        const tbody = document.getElementById('recentTableBody');

        if (!data.scans || data.scans.length === 0) {
            tbody.innerHTML = `
                <tr><td colspan="5">
                    <div class="empty-state">
                        <div class="empty-icon">🔍</div>
                        <p>No scans yet. Enter a URL or scan a QR code to get started.</p>
                    </div>
                </td></tr>`;
            return;
        }

        tbody.innerHTML = data.scans.map(scan => {
            const prediction = (scan.prediction || '').toLowerCase();
            const time = scan.timestamp || scan.created_at || '';
            const timeStr = time ? new Date(time).toLocaleString() : 'N/A';
            const source = scan.scan_source || 'URL';

            return `
                <tr>
                    <td><span class="recent-url" title="${escapeHtml(scan.url)}">${escapeHtml(scan.url)}</span></td>
                    <td><span class="badge ${prediction}">${scan.prediction}</span></td>
                    <td>${scan.confidence || 0}%</td>
                    <td><span class="source-badge">${source}</span></td>
                    <td style="font-size:12px;color:var(--text-muted)">${timeStr}</td>
                </tr>`;
        }).join('');

    } catch (err) {
        console.error('Failed to load recent scans:', err);
    }
}

// ──────────────────────────────────────────────────────────────
// Toast Notifications
// ──────────────────────────────────────────────────────────────
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icons = { success: '✅', error: '❌', info: 'ℹ️' };
    toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

// ──────────────────────────────────────────────────────────────
// Utilities
// ──────────────────────────────────────────────────────────────
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
