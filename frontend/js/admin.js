/**
 * PhishGuard AI – Admin Panel JavaScript
 * Handles reports management, statistics, and CSV export.
 */

const API_BASE = window.location.origin + '/api';

let allReports = [];

// ──────────────────────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    loadAdminStats();
    loadReports();
    loadAdminRecentScans();
});

// ──────────────────────────────────────────────────────────────
// Statistics
// ──────────────────────────────────────────────────────────────
async function loadAdminStats() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const data = await res.json();

        animateCounter('adminStatTotal', data.total_scans || 0);
        animateCounter('adminStatSafe', data.safe_count || 0);
        animateCounter('adminStatSuspicious', data.suspicious_count || 0);
        animateCounter('adminStatPhishing', data.phishing_count || 0);
    } catch (err) {
        console.error('Failed to load admin stats:', err);
    }
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    let count = 0;
    const step = Math.max(1, Math.ceil(target / 20));
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
// Reports
// ──────────────────────────────────────────────────────────────
async function loadReports() {
    try {
        const res = await fetch(`${API_BASE}/admin/reports?limit=50`);
        const data = await res.json();
        allReports = data.reports || [];
        renderReports(allReports);
    } catch (err) {
        console.error('Failed to load reports:', err);
    }
}

function renderReports(reports) {
    const tbody = document.getElementById('reportsTableBody');

    if (!reports || reports.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="4">
                    <div class="empty-state">
                        <div class="empty-icon">📋</div>
                        <p>No reports found.</p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    tbody.innerHTML = reports.map(report => {
        const time = report.reported_at || report.created_at || '';
        const timeStr = time ? new Date(time).toLocaleString() : 'N/A';
        const status = report.status || 'pending';

        return `
            <tr>
                <td><span class="recent-url" title="${escapeHtml(report.url)}">${escapeHtml(report.url)}</span></td>
                <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(report.reason || 'N/A')}</td>
                <td><span class="status-badge ${status}">${status}</span></td>
                <td style="font-size:12px;color:var(--text-muted)">${timeStr}</td>
            </tr>`;
    }).join('');
}

function refreshReports() {
    showToast('Refreshing reports...', 'info');
    loadReports();
    loadAdminStats();
    loadAdminRecentScans();
}

// ──────────────────────────────────────────────────────────────
// Recent Scans
// ──────────────────────────────────────────────────────────────
async function loadAdminRecentScans() {
    try {
        const res = await fetch(`${API_BASE}/recent-scans?limit=20`);
        const data = await res.json();

        const tbody = document.getElementById('adminRecentTableBody');
        if (!data.scans || data.scans.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5">
                        <div class="empty-state">
                            <div class="empty-icon">🔍</div>
                            <p>No scans yet.</p>
                        </div>
                    </td>
                </tr>`;
            return;
        }

        tbody.innerHTML = data.scans.map(scan => {
            const prediction = (scan.prediction || '').toLowerCase();
            const time = scan.timestamp || scan.created_at || '';
            const timeStr = time ? new Date(time).toLocaleString() : 'N/A';

            return `
                <tr>
                    <td><span class="recent-url" title="${escapeHtml(scan.url)}">${escapeHtml(scan.url)}</span></td>
                    <td><span class="badge ${prediction}">${scan.prediction}</span></td>
                    <td>${scan.confidence || 0}%</td>
                    <td>${Math.round(scan.risk_score || 0)}/100</td>
                    <td style="font-size:12px;color:var(--text-muted)">${timeStr}</td>
                </tr>`;
        }).join('');

    } catch (err) {
        console.error('Failed to load admin recent scans:', err);
    }
}

// ──────────────────────────────────────────────────────────────
// CSV Export
// ──────────────────────────────────────────────────────────────
function downloadCSV() {
    if (!allReports || allReports.length === 0) {
        showToast('No reports to download.', 'error');
        return;
    }

    const headers = ['URL', 'Reason', 'Status', 'Reported At'];
    const rows = allReports.map(r => [
        `"${(r.url || '').replace(/"/g, '""')}"`,
        `"${(r.reason || '').replace(/"/g, '""')}"`,
        r.status || 'pending',
        r.reported_at || r.created_at || ''
    ]);

    const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download = `phishguard_reports_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    showToast('CSV downloaded successfully!', 'success');
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
