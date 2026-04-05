// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PHISH_GUARD_RESULT') {
        const result = message.result;

        // Only show warning if risk is significant
        if (result.label === 'HIGH RISK' || result.risk_score > 0.7) {
            showWarningOverlay(result);
        }
    }
});

function showWarningOverlay(result) {
    // Check if warning already exists
    if (document.getElementById('phish-guard-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'phish-guard-overlay';

    const reasonsHtml = result.reasoning.map(reason => `<li>${reason}</li>`).join('');

    overlay.innerHTML = `
    <div class="pg-content">
      <div class="pg-warning-icon">⚠️</div>
      <h1>PhishGuard Protected: Malicious Site Detected</h1>
      <p class="pg-url">Target: <b>${result.url}</b></p>
      
      <div class="pg-risk-details">
        <div class="pg-score-pill">Risk Score: ${(result.risk_score * 100).toFixed(0)}%</div>
        <p>This site has been identified as a high-risk phishing attempt. PhishGuard detected suspicious patterns that match known malicious behavior.</p>
        <ul>${reasonsHtml}</ul>
      </div>

      <div class="pg-actions">
        <button id="pg-go-back" class="pg-btn pg-btn-primary">Go Back to Safety</button>
        <button id="pg-continue" class="pg-btn pg-btn-secondary">I understand the risks, continue anyway</button>
      </div>
      
      <p class="pg-footer">Powered by PhishGuard Advanced Neural Analysis</p>
    </div>
  `;

    document.body.appendChild(overlay);

    // Blocker: Disable interaction or blur the page
    document.body.style.overflow = 'hidden';

    // Event Listeners
    document.getElementById('pg-go-back').addEventListener('click', () => {
        window.location.href = 'https://www.google.com';
    });

    document.getElementById('pg-continue').addEventListener('click', () => {
        overlay.classList.add('pg-dismissed');
        setTimeout(() => {
            overlay.remove();
            document.body.style.overflow = 'auto';
        }, 500);
    });
}

// --- Hover Scan Feature ---
let hoverTooltip = null;
let hoverTimeout = null;

document.addEventListener('mouseover', (e) => {
    const anchor = e.target.closest('a');
    if (!anchor || !anchor.href || anchor.href.startsWith('javascript:')) return;

    clearTimeout(hoverTimeout);
    hoverTimeout = setTimeout(() => {
        handleHover(anchor, e.pageX, e.pageY);
    }, 500); // 500ms delay to avoid flickering
});

document.addEventListener('mouseout', (e) => {
    const anchor = e.target.closest('a');
    if (anchor) {
        clearTimeout(hoverTimeout);
        removeTooltip();
    }
});

async function handleHover(anchor, x, y) {
    const url = anchor.href;

    // Check if it's an internal or safe URL to avoid unnecessary API calls
    if (url.includes(window.location.hostname) || url.startsWith('mailto:')) return;

    showTooltip(x, y, 'Scanning...');

    chrome.runtime.sendMessage({ type: 'PHISH_GUARD_HOVER_SCAN', url }, (response) => {
        if (response && response.result) {
            updateTooltip(response.result);
        }
    });
}

function showTooltip(x, y, text) {
    removeTooltip();
    hoverTooltip = document.createElement('div');
    hoverTooltip.id = 'pg-hover-tooltip';
    hoverTooltip.style.left = `${x + 10}px`;
    hoverTooltip.style.top = `${y + 10}px`;
    hoverTooltip.innerHTML = `
        <div class="pg-tooltip-content">
            <span class="pg-tooltip-icon">🔍</span>
            <span class="pg-tooltip-text">${text}</span>
        </div>
    `;
    document.body.appendChild(hoverTooltip);
}

function updateTooltip(result) {
    if (!hoverTooltip) return;
    const isHighRisk = result.label === 'HIGH RISK' || result.risk_score > 0.7;
    const isSuspicious = result.label === 'SUSPICIOUS' || result.risk_score > 0.3;

    const icon = isHighRisk ? '⚠️' : isSuspicious ? '🧐' : '✅';
    const label = isHighRisk ? 'HIGH RISK' : isSuspicious ? 'SUSPICIOUS' : 'SAFE';
    const color = isHighRisk ? '#ff4d4d' : isSuspicious ? '#ffa500' : '#00ff88';

    hoverTooltip.querySelector('.pg-tooltip-icon').textContent = icon;
    const textEl = hoverTooltip.querySelector('.pg-tooltip-text');
    textEl.textContent = label;
    textEl.style.color = color;
    hoverTooltip.style.borderLeft = `3px solid ${color}`;
}

function removeTooltip() {
    if (hoverTooltip) {
        hoverTooltip.remove();
        hoverTooltip = null;
    }
}

// --- Floating Status Indicator ---
let statusPill = null;
let statusTimeout = null;

function initStatusIndicator() {
    if (document.getElementById('pg-status-pill')) return;

    statusPill = document.createElement('div');
    statusPill.id = 'pg-status-pill';
    statusPill.className = 'pg-analyzing';
    statusPill.innerHTML = `
        <div class="pg-pill-content">
            <span class="pg-pill-dot"></span>
            <span class="pg-pill-text">Checking...</span>
            <span class="pg-pill-details">PhishGuard is verifying site safety.</span>
        </div>
    `;
    document.body.appendChild(statusPill);

    // Auto-minimize after 4 seconds
    statusTimeout = setTimeout(() => {
        statusPill.classList.add('pg-minimized');
    }, 4000);

    // Hover to expand
    statusPill.addEventListener('mouseenter', () => {
        clearTimeout(statusTimeout);
        statusPill.classList.remove('pg-minimized');
    });

    statusPill.addEventListener('mouseleave', () => {
        statusTimeout = setTimeout(() => {
            statusPill.classList.add('pg-minimized');
        }, 2000);
    });
}

function updateStatusIndicator(result) {
    if (!statusPill) initStatusIndicator();

    const riskScore = result.risk_score * 100;
    const isHighRisk = result.label === 'HIGH RISK' || riskScore > 70;
    const isSuspicious = result.label === 'SUSPICIOUS' || riskScore > 30;

    statusPill.className = isHighRisk ? 'pg-danger' : isSuspicious ? 'pg-warning' : (result.error ? 'pg-offline' : 'pg-safe');

    const textEl = statusPill.querySelector('.pg-pill-text');
    const detailsEl = statusPill.querySelector('.pg-pill-details');

    if (result.error) {
        textEl.textContent = 'Unable to check';
        detailsEl.textContent = result.summary || 'Service is temporarily unavailable.';
    } else {
        textEl.textContent = isHighRisk ? 'PHISHING' : isSuspicious ? 'SUSPICIOUS' : 'SAFE';
        detailsEl.textContent = result.summary || (isHighRisk ? 'Critical threat detected!' : 'No immediate threats identified.');
    }
}

// Initialize on load
if (document.readyState === 'complete') {
    initStatusIndicator();
} else {
    window.addEventListener('load', initStatusIndicator);
}

// Update message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PHISH_GUARD_RESULT') {
        const result = message.result;
        updateStatusIndicator(result);

        if (result.label === 'HIGH RISK' || result.risk_score > 0.7) {
            showWarningOverlay(result);
        }
    }
});
