const API_URL = 'https://phishguard-zv13.onrender.com/api/analyze';
const SCAN_TIMEOUT = 5000; // 5 seconds
const cache = new Map();
const pendingAnalyze = new Map();

// Initialize cache from storage
chrome.storage.local.get(['phishGuardCache'], (result) => {
    if (result.phishGuardCache) {
        Object.entries(result.phishGuardCache).forEach(([url, data]) => {
            cache.set(url, data);
        });
    }
});

// URL monitoring (Post-load)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        const url = tab.url;
        if (isIgnoredUrl(url)) return;
        debounceAnalyze(url, tabId);
    }
});

// Debounce helper to avoid rapid duplicate calls
function debounceAnalyze(url, tabId) {
    if (pendingAnalyze.has(url)) {
        clearTimeout(pendingAnalyze.get(url));
    }
    const timeout = setTimeout(() => {
        analyzeUrl(url, tabId);
        pendingAnalyze.delete(url);
    }, 300); // 300ms debounce
    pendingAnalyze.set(url, timeout);
}

// Hardened Mode: Pre-Navigation Blocking
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId !== 0) return; // Only block main frame navigation

    const url = details.url;
    if (isIgnoredUrl(url)) return;

    // Fast check cache for pre-blocking
    if (cache.has(url)) {
        const result = cache.get(url);
        if (result.label === 'HIGH RISK' || result.risk_score > 0.8) {
            chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL('blocked.html') });
        }
    }
});

function isIgnoredUrl(url) {
    return url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:') || url.includes(chrome.runtime.id);
}

async function analyzeUrl(url, tabId, isHover = false) {
    if (cache.has(url)) {
        const cachedResult = cache.get(url);
        if (!isHover) handleAnalysisResult(cachedResult, tabId);
        return cachedResult;
    }

    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), SCAN_TIMEOUT);

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
            signal: controller.signal
        });
        clearTimeout(id);

        const result = await response.json();
        updateCache(url, result);

        if (!isHover) handleAnalysisResult(result, tabId);
        return result;
    } catch (error) {
        clearTimeout(id);
        const errorType = error.name === 'AbortError' ? 'Timeout' : 'Network Error';
        const errorResult = { error: errorType, url: url, summary: 'Unable to check site safety.' };

        // Don't cache transient errors permanently, just in-memory
        cache.set(url, errorResult);
        if (!isHover) handleAnalysisResult(errorResult, tabId);
        return errorResult;
    }
}

function updateCache(url, result) {
    cache.set(url, result);
    // Persist to storage (keep only last 100 entries for performance)
    const cacheObj = Object.fromEntries(Array.from(cache.entries()).slice(-100));
    chrome.storage.local.set({ phishGuardCache: cacheObj });
}

function handleAnalysisResult(result, tabId) {
    // Send result to content script for overlay
    chrome.tabs.sendMessage(tabId, {
        type: 'PHISH_GUARD_RESULT',
        result: result
    }).catch(() => { });

    chrome.storage.local.set({ lastAnalysis: result });

    if (result.label === 'HIGH RISK' || result.risk_score > 0.7) {
        chrome.action.setBadgeText({ text: '!', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId: tabId });

        // Trigger pre-emptive redirect if high risk (for subsequent loads)
        if (result.risk_score > 0.8) {
            chrome.tabs.update(tabId, { url: chrome.runtime.getURL('blocked.html') });
        }
    } else {
        chrome.action.setBadgeText({ text: '', tabId: tabId });
    }
}

// Message Router
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_CURRENT_STATUS') {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0] && tabs[0].url) {
                const url = tabs[0].url;
                const result = cache.get(url) || null;
                sendResponse({ url, result });
            }
        });
        return true;
    }

    if (message.type === 'PHISH_GUARD_HOVER_SCAN') {
        analyzeUrl(message.url, null, true).then(result => {
            sendResponse({ result });
        });
        return true;
    }
});
