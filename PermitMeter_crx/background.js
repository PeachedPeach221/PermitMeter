// PermitMeter - Background Service Worker
// Detects if the active tab is a Chrome Web Store extension page

function isExtensionPage(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    return u.hostname === 'chromewebstore.google.com' &&
      /^\/detail\/[^/]+\/[a-p]{32}\/?$/i.test(u.pathname);
  } catch {
    return false;
  }
}

function getExtensionId(url) {
  try {
    const match = new URL(url).pathname.match(/\/detail\/[^/]+\/([a-p]{32})\/?$/i);
    return match ? match[1].toLowerCase() : null;
  } catch {
    return null;
  }
}

async function updateIcon(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (isExtensionPage(tab.url)) {
      await chrome.action.setTitle({ tabId, title: 'PermitMeter — Analyze this extension' });
    } else {
      await chrome.action.setTitle({ tabId, title: 'PermitMeter — Open Chrome Web Store' });
    }
  } catch {}
}

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'complete' || info.url) updateIcon(tabId);
});

chrome.tabs.onActivated.addListener(({ tabId }) => updateIcon(tabId));

chrome.runtime.onInstalled.addListener(async () => {
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (tab?.id) updateIcon(tab.id);
});
