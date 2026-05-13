// PermitMeter — popup.js
// Orchestrates tab detection, CRX fetch, manifest parse, risk scoring & UI rendering

// ==================== HELPERS ====================

const $ = id => document.getElementById(id);
const main = $('main');
const statusDot = $('status-dot');

function setDot(cls) {
  statusDot.className = 'dot dot-' + cls;
}

// Check if URL is a CWS extension detail page
function isExtensionPage(url) {
  if (!url) return false;
  try {
    const u = new URL(url);
    return u.hostname === 'chromewebstore.google.com' &&
      /^\/detail\/[^/]+\/[a-p]{32}\/?$/i.test(u.pathname);
  } catch { return false; }
}

function getExtensionId(url) {
  try {
    const m = new URL(url).pathname.match(/\/detail\/[^/]+\/([a-p]{32})\/?$/i);
    return m ? m[1].toLowerCase() : null;
  } catch { return null; }
}

// ==================== PERMISSION RISK TABLE ====================
// 5-tier system matching crxcavator.io risk breakdown
// Weights: none=0, low=5, medium=10, high=15, critical=45
// Synced against official Chrome for Developers permissions page (May 2025)

const PERM_RISK = {
  // ── CRITICAL (weight: 45) ─────────────────────────────────────────
  cookies:                            'critical',
  debugger:                           'critical',
  webRequest:                         'critical',
  declarativeWebRequest:              'critical',

  // ── HIGH (weight: 15) ─────────────────────────────────────────────
  clipboardRead:                      'critical',
  contentSettings:                    'high',
  declarativeNetRequest:              'high',
  declarativeNetRequestWithHostAccess:'high',
  desktopCapture:                     'high',
  dns:                                'high',
  experimental:                       'high',
  history:                            'high',
  pageCapture:                        'high',
  privacy:                            'high',
  proxy:                              'critical',
  tabCapture:                         'high',
  tabs:                               'high',
  userScripts:                        'critical',
  vpnProvider:                        'high',

  // ── MEDIUM (weight: 10) ───────────────────────────────────────────
  bookmarks:                          'medium',
  clipboardWrite:                     'medium',
  downloads:                          'medium',
  downloadsOpen:                      'medium',
  fileSystemProvider:                 'medium',
  geolocation:                        'medium',
  loginState:                         'medium',
  management:                         'high',
  nativeMessaging:                    'high',
  offscreen:                          'medium',
  printing:                           'medium',
  printingMetrics:                    'medium',
  processes:                          'high',
  readingList:                        'medium',
  scripting:                          'critical',
  'system.storage':                   'medium',
  topSites:                           'medium',
  ttsEngine:                          'medium',
  webNavigation:                      'medium',

  // ── LOW (weight: 5) ───────────────────────────────────────────────
  activeTab:                          'low',
  background:                         'low',
  certificateProvider:                'low',
  declarativeNetRequestFeedback:      'low',
  documentScan:                       'low',
  enterpriseDeviceAttributes:         'low',
  enterprisePlatformKeys:             'low',
  favicon:                            'low',
  identity:                           'low',
  notifications:                      'low',
  platformKeys:                       'low',
  printerProvider:                    'low',
  search:                             'low',
  sidePanel:                          'low',
  storage:                            'low',
  tabGroups:                          'low',
  webAuthenticationProxy:             'low',
  webRequestBlocking:                 'low',

  // ── NONE (weight: 0) ──────────────────────────────────────────────
  alarms:                             'none',
  audio:                              'none',
  browsingData:                       'medium',
  contextMenus:                       'none',
  declarativeContent:                 'none',
  fontSettings:                       'none',
  gcm:                                'none',
  idle:                               'none',
  power:                              'none',
  runtime:                            'none',
  sessions:                           'none',
  'system.cpu':                       'none',
  'system.display':                   'none',
  'system.memory':                    'none',
  tts:                                'none',
  unlimitedStorage:                   'none',
  wallpaper:                          'none',
};

// ==================== PERMISSION DESCRIPTIONS ====================
// Plain-language descriptions for the hover tooltip feature.
// Every permission in PERM_RISK has a corresponding entry here.

const PERM_DESCRIPTION = {
  // CRITICAL
  cookies:                            'Can read, write, and delete all browser cookies across every website, including session tokens and login credentials.',
  debugger:                           'Attaches the Chrome DevTools debugger to any tab, giving full control over JavaScript execution, network traffic, and page content.',
  webRequest:                         'Can intercept, inspect, and modify all HTTP and HTTPS network requests made by the browser in real time.',
  declarativeWebRequest:              'Can block or modify network requests using declarative rules. A legacy MV2 API with broad network control capabilities.',

  // HIGH
  clipboardRead:                      'Can silently read clipboard contents at any time without user awareness, directly capturing passwords copied from password managers, two-factor authentication codes, private keys, and any other sensitive data the user copies during normal browsing.',
  contentSettings:                    'Can change per-site browser settings such as JavaScript execution, cookie handling, camera access, and notification permissions.',
  declarativeNetRequest:              'Can block or redirect network requests across all websites using filter rules, affecting which content loads in your browser.',
  declarativeNetRequestWithHostAccess:'Can block or redirect network requests and also read the details of those requests, combining content filtering with traffic inspection.',
  desktopCapture:                     'Can record your entire screen, a specific application window, or any open browser tab as a live video stream.',
  dns:                                'Can query the browser internal DNS resolver to look up hostnames, potentially revealing internal network addresses or browsing activity.',
  experimental:                       'Grants access to experimental and unstable Chrome APIs that are not part of the official stable API surface and may have unpredictable behavior.',
  history:                            'Can read your full browsing history and add, modify, or delete history entries across all time.',
  pageCapture:                        'Can save any web page you visit as a full MHTML archive, capturing all content including text, images, and embedded resources.',
  privacy:                            'Can change Chrome privacy settings such as network prediction, safe browsing, referrer headers, and third-party cookie behavior.',
  proxy:                              'Can silently redirect all browser HTTP and HTTPS traffic through a server controlled by the extension, enabling full traffic interception, credential harvesting, and man-in-the-middle attacks. Equivalent in impact to webRequest but harder to detect because it operates at the network configuration level.',
  tabCapture:                         'Can capture the live audio and video stream of any browser tab in real time.',
  tabs:                               'Can read the URL, title, and favicon of all open tabs in every window, and monitor tab activity as you browse.',
  userScripts:                        'Can register and inject arbitrary JavaScript into web pages at runtime with fewer origin restrictions than scripting. In Manifest V3 this provides the same code injection capability as scripting and carries the same critical risk — full page content access, credential capture, and DOM manipulation.',
  vpnProvider:                        'Can implement a VPN client that routes all browser network traffic through an extension-controlled tunnel.',

  // MEDIUM
  bookmarks:                          'Can read, create, modify, and delete all bookmarks and bookmark folders stored in the browser.',
  clipboardWrite:                     'Can write content to your clipboard programmatically, potentially replacing text you intended to paste.',
  downloads:                          'Can initiate file downloads, monitor download progress, and access metadata about past and current downloads.',
  downloadsOpen:                      'Can open downloaded files directly from the browser using the system default application for that file type.',
  fileSystemProvider:                 'Can create a virtual file system that appears in ChromeOS Files app, allowing the extension to serve files as if from a real storage device.',
  geolocation:                        'Can request access to your physical location via the Geolocation API, subject to the same browser permission prompt as websites.',
  loginState:                         'Can detect whether the user is signed in to a ChromeOS device and whether the screen is locked. ChromeOS only.',
  management:                         'Can enumerate, enable, disable, and uninstall all other Chrome extensions. This is a known persistence technique used by malicious extensions to silently disable security tools, ad blockers, and antivirus extensions installed by the user.',
  nativeMessaging:                    'Allows the extension to communicate with a native binary installed on the operating system, effectively escaping the browser sandbox. The native application faces no Chrome-level restrictions and can access the file system, execute commands, make arbitrary network requests, or install additional software.',
  offscreen:                          'Can create hidden offscreen documents to run JavaScript and DOM operations in the background without a visible window.',
  printing:                           'Can send print jobs to printers connected to the device, including sending arbitrary document content to a printer silently.',
  printingMetrics:                    'Can access your print history and job metadata, revealing which documents you have printed and when.',
  processes:                          'Can query real-time information about all active Chrome renderer processes, including their CPU usage and association with specific tabs. This enables site fingerprinting through process names even without the tabs permission, and can be used to detect and target security tools running in the browser.',
  readingList:                        'Can read, add, and remove items from your Chrome Reading List, exposing saved URLs and reading habits.',
  scripting:                          'The most dangerous MV3 permission. Allows injecting arbitrary JavaScript into any page the extension has host access to, enabling full page content reading, form data capture, credential theft, and DOM manipulation. This is the primary capability used by malicious extensions in Manifest V3.',
  'system.storage':                   'Can detect when external storage devices such as USB drives are attached or removed from the system.',
  topSites:                           'Can read the list of your most frequently visited websites as displayed on the new tab page.',
  ttsEngine:                          'Can register the extension as a text-to-speech engine that other extensions or the browser itself can use to synthesize speech.',
  webNavigation:                      'Can monitor all navigation events in the browser including page loads, redirects, and frame navigations across all tabs.',

  // LOW
  activeTab:                          'Can access the content and URL of the currently active tab only at the moment the user interacts with the extension.',
  background:                         'Can run a persistent background page that stays active even when no extension windows or popups are open.',
  certificateProvider:                'Can provide TLS client certificates to the browser for authentication on secure enterprise or internal sites. ChromeOS only.',
  declarativeNetRequestFeedback:      'Can read information about which declarativeNetRequest rules were matched during network requests, useful for debugging filters.',
  documentScan:                       'Can access document scanners connected to the device to initiate scans and receive scanned image data. ChromeOS only.',
  enterpriseDeviceAttributes:         'Can read enterprise-specific device attributes such as asset ID and location, available only on managed ChromeOS devices.',
  enterprisePlatformKeys:             'Can manage enterprise cryptographic keys and certificates stored in platform key stores on managed ChromeOS devices.',
  favicon:                            'Can access the favicon URLs of pages you visit via a dedicated favicon fetching API.',
  identity:                           'Can authenticate users with Google accounts or other OAuth providers and obtain access tokens on their behalf.',
  notifications:                      'Can display desktop notifications outside the browser window using the system notification area.',
  platformKeys:                       'Can access cryptographic keys and certificates stored in the browser or system key store for authentication purposes.',
  printerProvider:                    'Can register the extension as a print destination that appears in the Chrome print dialog alongside physical printers.',
  search:                             'Can programmatically trigger a search using the browser default search engine.',
  sidePanel:                          'Can display custom content in the Chrome side panel that appears alongside web page content.',
  storage:                            'Can store and retrieve data locally using the extension storage API, separate from cookies or localStorage.',
  tabGroups:                          'Can read, create, modify, and remove tab groups and move tabs between groups.',
  webAuthenticationProxy:             'Can intercept WebAuthn authentication requests and proxy them to an external authenticator, modifying the authentication flow.',
  webRequestBlocking:                 'Can synchronously block or modify network requests as they occur. A legacy MV2-only permission no longer available in MV3.',

  // NONE
  alarms:                             'Can schedule code to run at specific times or intervals using the Chrome alarms API.',
  audio:                              'Can query and modify audio device settings such as volume and mute state for input and output devices.',
  browsingData:                       'Can silently delete cookies, browsing history, cached credentials, saved passwords, and other stored data. While it cannot read this data, destroying it can force re-authentication that other mechanisms then exploit. It can also be used to erase traces of malicious activity after the fact.',
  contextMenus:                       'Can add custom items to the right-click context menu that appears when users interact with pages or selected content.',
  declarativeContent:                 'Can show or hide the extension browser action button based on the content or URL of the current page, without reading page content.',
  fontSettings:                       'Can read and change the default fonts Chrome uses to render web page text.',
  gcm:                                'Can send and receive messages through Google Cloud Messaging, enabling push notifications from a remote server.',
  idle:                               'Can detect when the user has been idle or the screen has been locked, based on a configurable inactivity threshold.',
  power:                              'Can prevent the system from going to sleep or dimming the screen by requesting a power management wake lock.',
  runtime:                            'Provides access to the basic extension runtime API for messaging between extension components. All extensions have this implicitly.',
  sessions:                           'Can read and restore recently closed tabs and windows from the current browser session.',
  'system.cpu':                       'Can query information about the CPU installed in the device, such as the number of cores and usage statistics.',
  'system.display':                   'Can query information about connected displays including resolution, orientation, and bounds.',
  'system.memory':                    'Can query the total and available physical memory capacity of the device.',
  tts:                                'Can use the browser text-to-speech engine to synthesize and play spoken audio from text.',
  unlimitedStorage:                   'Removes the default storage quota for the extension, allowing it to store an unlimited amount of data locally.',
  wallpaper:                          'Can change the desktop wallpaper image on ChromeOS devices.',
};

function permRisk(name) {
  return PERM_RISK[name] ?? 'unknown';
}

function permDesc(name) {
  return PERM_DESCRIPTION[name] ?? null;
}

// Host permission risk — mapped to 5-tier system (crxcavator)
function hostRisk(pattern) {
  const t = pattern.trim();
  if (!t) return 'none';
  // Critical: <all_urls>, *://*/* or *://*/:
  if (t === '<all_urls>' || t === '*://*/*' || t === '*://*/:') return 'critical';
  // High: broad wildcard host patterns from crxcavator
  if (t === 'https://*/*' || t === 'http://*/*' || t === 'file:///*') return 'high';
  // Medium: any other wildcard pattern
  if (t.includes('*')) return 'medium';
  // Low: specific host
  return 'low';
}

// ==================== SCORING ====================
// Formula: Risk Score = 100 × (1 − ∏(1 − wᵢ))
// Weights as decimals: critical=0.45, high=0.15, medium=0.10, low=0.05, none=0
// Score: 0 = safe, 100 = critical

const TIER_WEIGHTS = { none: 0, low: 0.05, medium: 0.10, high: 0.15, critical: 0.45, unknown: 0.05 };

function calcRiskScore(permissions, hostPermissions) {
  // Collect all individual weights
  const allWeights = [
    ...permissions.map(p => TIER_WEIGHTS[permRisk(p)] ?? 0.05),
    ...hostPermissions.map(h => TIER_WEIGHTS[hostRisk(h)] ?? 0.05),
  ];

  if (allWeights.length === 0) return 0;

  // Multiply all (1 − wᵢ) together
  const safetyProduct = allWeights.reduce((acc, w) => acc * (1 - w), 1);

  // Risk Score = 100 × (1 − product), rounded up to nearest integer
  const score = Math.min(100, Math.ceil(100 * (1 - safetyProduct)));
  return Math.max(0, score);
}

function scoreBand(score) {
  if (score <= 20) return { label: 'Safe',     color: '#4ade80', bg: 'rgba(74,222,128,.13)' };
  if (score <= 40) return { label: 'Medium',   color: '#fbbf24', bg: 'rgba(251,191,36,.13)' };
  if (score <= 70) return { label: 'High',     color: '#fb923c', bg: 'rgba(251,146,60,.13)' };
  return             { label: 'Critical',  color: '#f43f5e', bg: 'rgba(244,63,94,.13)' };
}

// ==================== CRX FETCH & PARSE ====================

function getChromeVersion() {
  const m = navigator.userAgent.match(/Chrome\/([\d.]+)/);
  return m ? m[1] : '131.0.0.0';
}

function buildCrxUrl(extId) {
  const params = encodeURIComponent(`id=${extId}&installsource=ondemand&uc`);
  return `https://clients2.google.com/service/update2/crx?response=redirect&prod=chromiumcrx&acceptformat=crx2,crx3&prodversion=${getChromeVersion()}&x=${params}`;
}

// Strip the CRX header and return the ZIP portion as Uint8Array
function stripCrxHeader(buffer) {
  const view = new DataView(buffer);
  const magic = String.fromCharCode(...new Uint8Array(buffer.slice(0, 4)));
  if (magic !== 'Cr24') throw new Error('Not a CRX file (missing Cr24 magic)');

  const version = view.getUint32(4, true);
  if (version === 3) {
    const headerSize = view.getUint32(8, true);
    return new Uint8Array(buffer.slice(12 + headerSize));
  } else if (version === 2) {
    const pubKeyLen = view.getUint32(8, true);
    const sigLen = view.getUint32(12, true);
    return new Uint8Array(buffer.slice(16 + pubKeyLen + sigLen));
  }
  throw new Error(`Unsupported CRX version: ${version}`);
}

async function fetchManifest(extId) {
  const url = buildCrxUrl(extId);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`CRX download failed (HTTP ${resp.status})`);

  const buffer = await resp.arrayBuffer();
  const zipBytes = stripCrxHeader(buffer);

  // Extract manifest.json from the ZIP
  const manifestBytes = await ZipReader.extractFile(zipBytes, 'manifest.json');
  if (!manifestBytes) throw new Error('manifest.json not found inside CRX');

  const text = new TextDecoder().decode(manifestBytes);
  return JSON.parse(text);
}

// ==================== UI RENDERERS ====================

function renderRedirectScreen() {
  main.innerHTML = `
    <div class="redirect-screen">
      <div class="redirect-icon">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M3 12C3 7.02944 7.02944 3 12 3C16.9706 3 21 7.02944 21 12C21 16.9706 16.9706 21 12 21C7.02944 21 3 16.9706 3 12Z" stroke="currentColor" stroke-width="1.5"/>
          <path d="M12 8v5M12 16v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
      </div>
      <p>
        Navigate to a Chrome extension page on the
        <a class="redirect-cws-link" href="https://chromewebstore.google.com/category/extensions" target="_blank">
          Chrome Web Store
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" style="display:inline;vertical-align:middle;margin-left:2px"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6M15 3h6v6M10 14L21 3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
        </a>
        to analyze its permissions.
      </p>
    </div>
  `;
}

function renderAnalyzeScreen(extId) {
  main.innerHTML = `
    <div class="analyze-screen">
      <div class="ext-meta">
        <div class="ext-id">${extId}</div>
      </div>
      <button class="btn-analyze" id="btn-do-analyze">Analyze</button>
      <div style="font-size:13px;color:var(--muted);text-align:center;line-height:1.5;">
        Click to fetch permissions<br>from the CRX package
      </div>
    </div>
  `;
  document.getElementById('btn-do-analyze').addEventListener('click', () => {
    doAnalyze(extId);
  });
}

function renderLoading() {
  setDot('loading');
  main.innerHTML = `<div class="loading-msg">Loading & unpacking CRX…</div>`;
}

function renderError(msg) {
  setDot('error');
  main.innerHTML = `<div class="error-msg">${msg}</div>`;
}

function buildRingSVG(score, color) {
  const R = 44;
  const cx = 55, cy = 55;
  // Correct symmetric gauge using SVG coordinate system (y increases downward):
  //   start = 150°  → SVG point (16.9, 77.0)  lower-left  ✓
  //   end   =  30°  → SVG point (93.1, 77.0)  lower-right ✓  (both share y=77, perfectly symmetric)
  //   top   = 270°  → SVG point (55.0, 11.0)  top-center  ✓
  //   sweep = 240° clockwise (150 → 270 → 30)
  const startAngle = 150 * Math.PI / 180;
  const totalArc   = 240 * Math.PI / 180;
  const filledArc  = totalArc * (score / 100);

  function arcPath(start, sweep) {
    const x1 = cx + R * Math.cos(start);
    const y1 = cy + R * Math.sin(start);
    const x2 = cx + R * Math.cos(start + sweep);
    const y2 = cy + R * Math.sin(start + sweep);
    const large = sweep > Math.PI ? 1 : 0;
    return `M ${x1} ${y1} A ${R} ${R} 0 ${large} 1 ${x2} ${y2}`;
  }

  const trackPath = arcPath(startAngle, totalArc);
  const fillPath  = filledArc > 0 ? arcPath(startAngle, filledArc) : '';

  // viewBox: y starts at 5 (arc top is y=11, minus 3.5px stroke cap = 7.5, add 2px padding)
  // height 110 covers arc bottom endpoints at y=77 plus stroke cap (80.5) comfortably
  return `
    <svg width="116" height="116" viewBox="0 5 110 105">
      <path d="${trackPath}" fill="none" stroke="rgba(139,92,246,.18)" stroke-width="7" stroke-linecap="round"/>
      ${fillPath ? `<path d="${fillPath}" fill="none" stroke="${color}" stroke-width="7" stroke-linecap="round"/>` : ''}
    </svg>
  `;
}

function renderResults(manifest, extId) {
  const allPerms = [
    ...(manifest.permissions || []),
    ...(manifest.optional_permissions || []),
  ].filter(p => typeof p === 'string');
  const hostPerms = [
    ...(manifest.host_permissions || []),
    ...(manifest.optional_host_permissions || []),
  ].filter(p => typeof p === 'string');

  const score = calcRiskScore(allPerms, hostPerms);
  const band = scoreBand(score);

  // Sort permissions: high > medium > low > unknown
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, none: 4, unknown: 5 };
  const sortedPerms = [...allPerms].sort((a, b) =>
    riskOrder[permRisk(a)] - riskOrder[permRisk(b)]
  );

  setDot('ok');

  const ringSVG = buildRingSVG(score, band.color);

  // Per-permission Chrome docs URLs (scraped from developer.chrome.com/docs/extensions/reference)
  // Falls back to the permissions-list page for permissions without an individual API page
  const PERM_DOCS = {
    alarms:                           'https://developer.chrome.com/docs/extensions/reference/api/alarms',
    audio:                            'https://developer.chrome.com/docs/extensions/reference/api/audio',
    bookmarks:                        'https://developer.chrome.com/docs/extensions/reference/api/bookmarks',
    browsingData:                     'https://developer.chrome.com/docs/extensions/reference/api/browsingData',
    certificateProvider:              'https://developer.chrome.com/docs/extensions/reference/api/certificateProvider',
    contentSettings:                  'https://developer.chrome.com/docs/extensions/reference/api/contentSettings',
    contextMenus:                     'https://developer.chrome.com/docs/extensions/reference/api/contextMenus',
    cookies:                          'https://developer.chrome.com/docs/extensions/reference/api/cookies',
    debugger:                         'https://developer.chrome.com/docs/extensions/reference/api/debugger',
    declarativeContent:               'https://developer.chrome.com/docs/extensions/reference/api/declarativeContent',
    declarativeNetRequest:            'https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest',
    declarativeNetRequestWithHostAccess: 'https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest',
    declarativeNetRequestFeedback:    'https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest',
    declarativeWebRequest:            'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    desktopCapture:                   'https://developer.chrome.com/docs/extensions/reference/api/desktopCapture',
    dns:                              'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    documentScan:                     'https://developer.chrome.com/docs/extensions/reference/api/documentScan',
    downloads:                        'https://developer.chrome.com/docs/extensions/reference/api/downloads',
    downloadsOpen:                    'https://developer.chrome.com/docs/extensions/reference/api/downloads#method-open',
    enterpriseDeviceAttributes:       'https://developer.chrome.com/docs/extensions/reference/api/enterprise/deviceAttributes',
    enterprisePlatformKeys:           'https://developer.chrome.com/docs/extensions/reference/api/enterprise/platformKeys',
    experimental:                     'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    favicon:                          'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    fileSystemProvider:               'https://developer.chrome.com/docs/extensions/reference/api/fileSystemProvider',
    fontSettings:                     'https://developer.chrome.com/docs/extensions/reference/api/fontSettings',
    gcm:                              'https://developer.chrome.com/docs/extensions/reference/api/gcm',
    geolocation:                      'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    history:                          'https://developer.chrome.com/docs/extensions/reference/api/history',
    identity:                         'https://developer.chrome.com/docs/extensions/reference/api/identity',
    idle:                             'https://developer.chrome.com/docs/extensions/reference/api/idle',
    loginState:                       'https://developer.chrome.com/docs/extensions/reference/api/loginState',
    management:                       'https://developer.chrome.com/docs/extensions/reference/api/management',
    nativeMessaging:                  'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    notifications:                    'https://developer.chrome.com/docs/extensions/reference/api/notifications',
    offscreen:                        'https://developer.chrome.com/docs/extensions/reference/api/offscreen',
    pageCapture:                      'https://developer.chrome.com/docs/extensions/reference/api/pageCapture',
    platformKeys:                     'https://developer.chrome.com/docs/extensions/reference/api/platformKeys',
    power:                            'https://developer.chrome.com/docs/extensions/reference/api/power',
    printing:                         'https://developer.chrome.com/docs/extensions/reference/api/printing',
    printingMetrics:                  'https://developer.chrome.com/docs/extensions/reference/api/printingMetrics',
    privacy:                          'https://developer.chrome.com/docs/extensions/reference/api/privacy',
    processes:                        'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    printerProvider:                  'https://developer.chrome.com/docs/extensions/reference/api/printerProvider',
    proxy:                            'https://developer.chrome.com/docs/extensions/reference/api/proxy',
    readingList:                      'https://developer.chrome.com/docs/extensions/reference/api/readingList',
    runtime:                          'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    scripting:                        'https://developer.chrome.com/docs/extensions/reference/api/scripting',
    search:                           'https://developer.chrome.com/docs/extensions/reference/api/search',
    sessions:                         'https://developer.chrome.com/docs/extensions/reference/api/sessions',
    sidePanel:                        'https://developer.chrome.com/docs/extensions/reference/api/sidePanel',
    storage:                          'https://developer.chrome.com/docs/extensions/reference/api/storage',
    'system.cpu':                     'https://developer.chrome.com/docs/extensions/reference/api/system/cpu',
    'system.display':                 'https://developer.chrome.com/docs/extensions/reference/api/system/display',
    'system.memory':                  'https://developer.chrome.com/docs/extensions/reference/api/system/memory',
    'system.storage':                 'https://developer.chrome.com/docs/extensions/reference/api/system/storage',
    tabCapture:                       'https://developer.chrome.com/docs/extensions/reference/api/tabCapture',
    tabGroups:                        'https://developer.chrome.com/docs/extensions/reference/api/tabGroups',
    tabs:                             'https://developer.chrome.com/docs/extensions/reference/api/tabs',
    topSites:                         'https://developer.chrome.com/docs/extensions/reference/api/topSites',
    tts:                              'https://developer.chrome.com/docs/extensions/reference/api/tts',
    ttsEngine:                        'https://developer.chrome.com/docs/extensions/reference/api/ttsEngine',
    unlimitedStorage:                 'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    userScripts:                      'https://developer.chrome.com/docs/extensions/reference/api/userScripts',
    vpnProvider:                      'https://developer.chrome.com/docs/extensions/reference/api/vpnProvider',
    wallpaper:                        'https://developer.chrome.com/docs/extensions/reference/api/wallpaper',
    webAuthenticationProxy:           'https://developer.chrome.com/docs/extensions/reference/api/webAuthenticationProxy',
    webNavigation:                    'https://developer.chrome.com/docs/extensions/reference/api/webNavigation',
    webRequest:                       'https://developer.chrome.com/docs/extensions/reference/api/webRequest',
    webRequestBlocking:               'https://developer.chrome.com/docs/extensions/reference/api/webRequest',
    background:                       'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    activeTab:                        'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    clipboardRead:                    'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    clipboardWrite:                   'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    displaySource:                    'https://developer.chrome.com/docs/extensions/reference/permissions-list',
    tabCapture:                       'https://developer.chrome.com/docs/extensions/reference/api/tabCapture',
  };
  const DOCS_FALLBACK = 'https://developer.chrome.com/docs/extensions/reference/permissions-list';

  const permItems = sortedPerms.length > 0
    ? sortedPerms.map(p => {
        const risk = permRisk(p);
        const desc = permDesc(p) || 'No description available.';
        const safeDesc = desc.replace(/"/g, '&quot;');
        const docsUrl = PERM_DOCS[p] || DOCS_FALLBACK;
        return `
          <div class="perm-item risk-${risk} has-tooltip"
               data-perm="${p}"
               data-desc="${safeDesc}"
               data-docs="${docsUrl}">
            <div class="perm-risk-dot"></div>
            <a class="perm-name perm-name-link" href="${docsUrl}" title="Open Chrome docs for: ${p}" data-docs="${docsUrl}">${p} <span class="perm-name-arrow">↗</span></a>
            <span class="perm-badge">${risk}</span>
          </div>
        `;
      }).join('')
    : `<div class="no-perms">No explicit permissions declared.</div>`;

  // Escape HTML special chars so patterns like <all_urls> render correctly
  function escHtml(s) {
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  const sortedHostPerms = [...hostPerms].sort((a, b) =>
    riskOrder[hostRisk(a)] - riskOrder[hostRisk(b)]
  );

  const hostItems = sortedHostPerms.length > 0
    ? sortedHostPerms.map(h => {
        const risk = hostRisk(h);
        return `
          <div class="perm-item risk-${risk}">
            <div class="perm-risk-dot"></div>
            <span class="perm-name" title="${escHtml(h)}">${escHtml(h)}</span>
            <span class="perm-badge">${risk}</span>
          </div>`;
      }).join('')
    : `<div class="no-perms" style="font-size:11px">No host permissions declared.</div>`;

  // Resolve display name: manifest may use __MSG_xxx__ locale keys
  // Fall back to the URL slug (human-readable part before the extension ID)
  function resolveExtName(raw, fallbackId) {
    if (!raw || raw.startsWith('__MSG_')) {
      // Try to get the slug from the active tab URL
      try {
        const tabs = []; // resolved async below if needed
        const urlSlug = window._activeTabUrl
          ? decodeURIComponent(new URL(window._activeTabUrl).pathname.split('/detail/')[1]?.split('/')[0] || '')
          : '';
        if (urlSlug) return urlSlug.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      } catch {}
      return fallbackId.slice(0, 22) + '…';
    }
    return raw;
  }
  const extName = manifest.name || manifest.short_name || '';
  const displayName = resolveExtName(extName, extId);

  // ── Breakdown table rows (Feature 4) ──────────────────────────────
  const allItemsForTable = [
    ...sortedPerms.map(p => ({ name: p, tier: permRisk(p), weight: TIER_WEIGHTS[permRisk(p)] ?? 0.05, type: 'perm' })),
    ...sortedHostPerms.map(h => ({ name: escHtml(h), tier: hostRisk(h), weight: TIER_WEIGHTS[hostRisk(h)] ?? 0.05, type: 'host' })),
  ];

  const safetyProduct = allItemsForTable.reduce((acc, item) => acc * (1 - item.weight), 1);

  const breakdownRows = allItemsForTable.map(item => {
    const safety = (1 - item.weight).toFixed(2);
    return `
      <tr>
        <td class="bd-name">${item.name}</td>
        <td class="bd-tier"><span class="perm-badge risk-${item.tier}">${item.tier.toUpperCase()}</span></td>
        <td class="bd-num">${item.weight.toFixed(2)}</td>
        <td class="bd-num">${safety}</td>
      </tr>
    `;
  }).join('');

  const breakdownSection = allItemsForTable.length > 0 ? `
    <div class="breakdown-section">
      <button class="breakdown-toggle" id="btn-breakdown">
        <span id="bd-toggle-label">▸ Risk Score Breakdown</span>
        <span class="bd-formula" id="bd-formula-text" style="display:none">100 × (1 − ∏(1−wᵢ))</span>
      </button>
      <div class="breakdown-body" id="breakdown-body" style="display:none">
        <table class="breakdown-table">
          <thead>
            <tr>
              <th style="width:42%">Permission</th>
              <th style="width:26%">Tier</th>
              <th style="width:16%;text-align:right">w</th>
              <th style="width:16%;text-align:right">(1−w)</th>
            </tr>
          </thead>
          <tbody>${breakdownRows}</tbody>
          <tfoot>
            <tr>
              <td colspan="3" class="bd-foot-label">Safety product</td>
              <td class="bd-num bd-foot-val">${safetyProduct.toFixed(4)}</td>
            </tr>
            <tr>
              <td colspan="3" class="bd-foot-label">Final score</td>
              <td class="bd-num bd-foot-val" style="color:${band.color};white-space:nowrap">${score}<span style="color:var(--muted);font-weight:400"> / 100</span></td>
            </tr>
          </tfoot>
        </table>
      </div>
    </div>
  ` : '';

  main.innerHTML = `
    <div class="results-screen">
      <!-- Score ring -->
      <div class="score-section">
        <div class="ring-container">
          ${ringSVG}
          <div class="ring-score-label">
            <span class="ring-score-number" style="color:${band.color}">${score}</span>
            <span class="ring-score-sub">/ 100</span>
          </div>
        </div>
        <div class="score-band-label" style="color:${band.color};background:${band.bg}">${band.label}</div>
        <div class="ext-name-display">
          ${displayName}<br>
          <span class="ext-id-display">${extId}</span>
        </div>
      </div>

      <div class="divider"></div>

      <!-- Breakdown table (Feature 4) -->
      ${breakdownSection}

      <!-- Permissions -->
      <div class="perms-section">
        <div class="perms-header">
          <span class="perms-title">Permissions</span>
          <span class="perms-count">${sortedPerms.length}</span>
        </div>
        <div class="perms-list" id="perms-list">${permItems}</div>
      </div>

      ${sortedHostPerms.length > 0 ? `
      <div class="host-section">
        <div class="host-header">
          <span class="host-title">Host Permissions</span>
          <span class="perms-count">${sortedHostPerms.length}</span>
        </div>
        <div class="perms-list">${hostItems}</div>
      </div>
      ` : ''}

      <!-- Footer: History | time | Reset -->
      <div style="display:flex;justify-content:space-between;align-items:center;padding-top:2px;gap:6px">
        <button class="btn-history" id="btn-history">⏱ History</button>
        <span class="perf-time" id="perf-time-inline" style="flex:1;text-align:center;opacity:.55;font-size:9px;letter-spacing:.03em">${_cachedElapsed ? `Parse &amp; render: ${_cachedElapsed} ms` : ''}</span>
        <button class="btn-reanalyze" id="btn-reset">↩ Reset</button>
      </div>
    </div>

    <!-- Tooltip (Feature 1) -->
    <div class="perm-tooltip" id="perm-tooltip"></div>
  `;

  // ── Tooltip + docs click wiring (Features 1 & 2) ─────────────────
  const tooltip = document.getElementById('perm-tooltip');
  document.getElementById('perms-list').addEventListener('mouseover', e => {
    const item = e.target.closest('.has-tooltip');
    if (!item) return;
    tooltip.textContent = item.dataset.desc;
    tooltip.classList.add('visible');
  });
  document.getElementById('perms-list').addEventListener('mouseout', e => {
    if (!e.target.closest('.has-tooltip')) return;
    tooltip.classList.remove('visible');
  });
  document.getElementById('perms-list').addEventListener('click', e => {
    const link = e.target.closest('.perm-name-link');
    if (!link) return;
    e.preventDefault();
    chrome.tabs.create({ url: link.dataset.docs });
  });

  // ── Breakdown toggle (Feature 4) ──────────────────────────────────
  const btnBreakdown = document.getElementById('btn-breakdown');
  const breakdownBody = document.getElementById('breakdown-body');
  if (btnBreakdown) {
    btnBreakdown.addEventListener('click', () => {
      const open = breakdownBody.style.display !== 'none';
      breakdownBody.style.display = open ? 'none' : 'block';
      document.getElementById('bd-toggle-label').textContent = (open ? '▸' : '▾') + ' Risk Score Breakdown';
      document.getElementById('bd-formula-text').style.display = open ? 'none' : 'inline';
    });
  }

  // ── Save to history (Feature 3) ───────────────────────────────────
  saveHistory({ name: displayName, id: extId, score, band: band.label });

  // ── History screen (Feature 3) ────────────────────────────────────
  document.getElementById('btn-history').addEventListener('click', renderHistoryScreen);

  document.getElementById('btn-reset').addEventListener('click', () => {
    setDot('idle');
    renderAnalyzeScreen(extId);
  });
}

// ==================== HISTORY (Feature 3) ====================

const HISTORY_KEY = 'pm_history';
const HISTORY_MAX = 10;

async function saveHistory({ name, id, score, band }) {
  const res = await chrome.storage.local.get(HISTORY_KEY);
  const list = res[HISTORY_KEY] || [];
  // Remove duplicate if same ext was analyzed before
  const filtered = list.filter(e => e.id !== id);
  filtered.unshift({ name, id, score, band, ts: Date.now() });
  await chrome.storage.local.set({ [HISTORY_KEY]: filtered.slice(0, HISTORY_MAX) });
}

async function renderHistoryScreen() {
  const res = await chrome.storage.local.get(HISTORY_KEY);
  const list = res[HISTORY_KEY] || [];

  const bandColor = b => {
    if (b === 'Safe')     return '#4ade80';
    if (b === 'Medium')   return '#fbbf24';
    if (b === 'High')     return '#fb923c';
    return '#f43f5e'; // Critical
  };

  const rows = list.length > 0
    ? list.map(e => {
        const color = bandColor(e.band);
        const date = new Date(e.ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
        return `
          <div class="history-item">
            <div class="history-meta">
              <span class="history-name">${e.name}</span>
              <span class="history-date">${date}</span>
            </div>
            <div class="history-score" style="color:${color}">${e.score}
              <span class="history-band" style="color:${color}">${e.band}</span>
            </div>
          </div>
        `;
      }).join('')
    : `<div class="no-perms">No analysis history yet.</div>`;

  main.innerHTML = `
    <div class="results-screen">
      <div class="perms-header" style="margin-bottom:10px">
        <span class="perms-title">Analysis History</span>
        <span class="perms-count">${list.length} / ${HISTORY_MAX}</span>
      </div>
      <div class="history-list">${rows}</div>
      <div style="display:flex;justify-content:center;padding-top:6px">
        <button class="btn-reanalyze" id="btn-back-from-history">↩ Back</button>
      </div>
    </div>
  `;

  document.getElementById('btn-back-from-history').addEventListener('click', () => {
    if (_cachedManifest && _cachedExtId) {
      renderResults(_cachedManifest, _cachedExtId);
    } else {
      init();
    }
  });
}

// ==================== MAIN ANALYZE FLOW ====================

async function doAnalyze(extId) {
  renderLoading();
  try {
    const manifest = await fetchManifest(extId);
    _cachedManifest = manifest;
    _cachedExtId    = extId;
    const t0 = performance.now();
    renderResults(manifest, extId);
    const elapsed = (performance.now() - t0).toFixed(1);
    _cachedElapsed  = elapsed;
    // Inject time into the footer bar
    const timeEl = document.getElementById('perf-time-inline');
    if (timeEl) timeEl.textContent = `Parse & render: ${elapsed} ms`;
  } catch (err) {
    renderError(`Failed to analyze:<br>${err.message}`);
  }
}

// ==================== STATE CACHE ====================
// Stores the last successful analysis so history "Back" can restore it
let _cachedManifest = null;
let _cachedExtId    = null;
let _cachedElapsed  = null;

// ==================== INIT ====================

async function init() {
  setDot('idle');
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const url = tab?.url ?? '';
  window._activeTabUrl = url; // store for name resolution

  if (isExtensionPage(url)) {
    const extId = getExtensionId(url);
    renderAnalyzeScreen(extId);
  } else {
    renderRedirectScreen();
  }
}

init();
