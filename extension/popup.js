document.addEventListener('DOMContentLoaded', () => {
    // Request current status from background script
    chrome.runtime.sendMessage({ type: 'GET_CURRENT_STATUS' }, (response) => {
        if (response) {
            updateUI(response.url, response.result);
        }
    });

    // Also listen for updates if the user keeps the popup open
    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === 'local' && changes.lastAnalysis) {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0] && tabs[0].url) {
                    updateUI(tabs[0].url, changes.lastAnalysis.newValue);
                }
            });
        }
    });
});

function updateUI(url, result) {
    const urlEl = document.getElementById('current-url');
    const riskLabelEl = document.getElementById('risk-label');
    const riskScoreFillEl = document.getElementById('risk-score-fill');
    const summaryEl = document.getElementById('analysis-summary');
    const confidenceEl = document.getElementById('stat-confidence');
    const statusDot = document.getElementById('status-dot');
    const card = document.getElementById('result-card');

    if (url) {
        urlEl.textContent = new URL(url).hostname;
    }

    if (result) {
        if (result.error) {
            statusDot.style.background = '#888888';
            statusDot.style.boxShadow = 'none';
            summaryEl.textContent = 'PhishGuard backend is currently unreachable. Protection is limited.';
            riskLabelEl.textContent = 'OFFLINE';
            riskLabelEl.style.color = '#888888';
            riskScoreFillEl.style.width = '0%';
            confidenceEl.textContent = '0%';
            return;
        }

        const riskScore = result.risk_score * 100;
        const label = result.label || (riskScore > 70 ? 'HIGH RISK' : riskScore > 30 ? 'SUSPICIOUS' : 'SAFE');

        riskLabelEl.textContent = label;
        riskScoreFillEl.style.width = `${riskScore}%`;
        summaryEl.textContent = result.summary || result.reasoning?.[0] || 'Site appears safe to use.';
        const riskScoreValue = typeof result.risk_score === 'number' ? result.risk_score : 0;
        confidenceEl.textContent = `${(riskScoreValue * 100).toFixed(0)}%`;

        // Visual styles based on risk
        if (label === 'HIGH RISK' || riskScore > 70) {
            statusDot.style.background = '#FF4D4D';
            statusDot.style.boxShadow = '0 0 10px #FF4D4D';
            riskScoreFillEl.style.background = '#FF4D4D';
            riskLabelEl.style.color = '#FF4D4D';
            card.style.borderLeft = '4px solid #FF4D4D';
        } else if (label === 'SUSPICIOUS' || riskScore > 30) {
            statusDot.style.background = '#FFA500';
            statusDot.style.boxShadow = '0 0 10px #FFA500';
            riskScoreFillEl.style.background = '#FFA500';
            riskLabelEl.style.color = '#FFA500';
            card.style.borderLeft = '4px solid #FFA500';
        } else {
            statusDot.style.background = '#00FF88';
            statusDot.style.boxShadow = '0 0 10px #00FF88';
            riskScoreFillEl.style.background = '#00FF88';
            riskLabelEl.style.color = '#00FF88';
            card.style.borderLeft = '4px solid #00FF88';
        }
    } else {
        summaryEl.textContent = 'Analyzing current page...';
    }
}
