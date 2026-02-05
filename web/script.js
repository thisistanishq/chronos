/**
 * CHRONOS Ultra-Fast Frontend
 * World-class performance with virtual scrolling, lazy loading, and optimized rendering.
 */

// =====================
// GLOBAL SETUP
// =====================
gsap.registerPlugin();

// User session
let userId = localStorage.getItem('chronos_user_id');
if (!userId) {
    userId = 'user_' + Math.random().toString(36).substr(2, 9);
    localStorage.setItem('chronos_user_id', userId);
}

// Performance tracking
const perfMetrics = {
    pageLoadStart: performance.now(),
    firstContentfulPaint: 0,
    timeToInteractive: 0
};

// =====================
// SERVICE WORKER REGISTRATION
// =====================
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
        .then(() => console.log('📦 Service Worker registered'))
        .catch((err) => console.log('SW registration failed:', err));
}

// =====================
// THREE.JS BACKGROUND (OPTIMIZED)
// =====================
// =====================
// VANTA.JS BACKGROUND
// =====================
const initVanta = () => {
    try {
        VANTA.NET({
            el: "#canvas-container",
            mouseControls: true,
            touchControls: true,
            gyroControls: false,
            minHeight: 200.00,
            minWidth: 200.00,
            scale: 1.00,
            scaleMobile: 1.00,
            color: 0x962020,
            backgroundColor: 0x010101, // Near black for blend
            points: 10,
            maxDistance: 22,
            spacing: 16
        });
        console.log('✅ Vanta.js initialized');
    } catch (e) {
        console.error('❌ Vanta initialization failed:', e);
    }
};

initVanta();

// =====================
// CUSTOM CURSOR (THROTTLED)
// =====================
const cursorDot = document.querySelector('.cursor-dot');
const cursorCircle = document.querySelector('.cursor-circle');

let lastCursorUpdate = 0;
window.addEventListener('mousemove', (e) => {
    const now = performance.now();
    if (now - lastCursorUpdate < 16) return; // 60fps cap
    lastCursorUpdate = now;
    gsap.to(cursorDot, { x: e.clientX, y: e.clientY, duration: 0.1 });
    gsap.to(cursorCircle, { x: e.clientX, y: e.clientY, duration: 0.3 });
});

// Hover effects (event delegation)
document.body.addEventListener('mouseenter', (e) => {
    if (e.target.matches('a, button, .bento-item, .nav-btn')) {
        document.body.classList.add('hovering');
    }
}, true);

document.body.addEventListener('mouseleave', (e) => {
    if (e.target.matches('a, button, .bento-item, .nav-btn')) {
        document.body.classList.remove('hovering');
    }
}, true);

// =====================
// SPA ROUTER
// =====================
const views = document.querySelectorAll('.view-section');
const navBtns = document.querySelectorAll('.nav-btn');

navBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.preventDefault();
        const target = btn.getAttribute('data-target');
        switchView(target);
    });
});

document.querySelector('.brand')?.addEventListener('click', () => switchView('hero'));

function switchView(targetId) {
    navBtns.forEach(b => b.classList.remove('active'));
    const activeBtn = document.querySelector(`.nav-btn[data-target="${targetId}"]`);
    if (activeBtn) activeBtn.classList.add('active');

    views.forEach(view => {
        if (view.id === targetId) {
            view.classList.add('active');
            gsap.fromTo(view.children, { y: 20, opacity: 0 }, { y: 0, opacity: 1, duration: 0.5, stagger: 0.1 });
        } else {
            view.classList.remove('active');
        }
    });

    if (targetId === 'dashboard' && window.tierChart) {
        window.tierChart.resize();
    }
}

// =====================
// PRELOADER
// =====================
const tl = gsap.timeline();
let loadProgress = { val: 0 };
const counter = document.querySelector('.counter');
const loaderBar = document.querySelector('.loader-bar');

tl.to(loadProgress, {
    val: 100,
    duration: 1.5,
    ease: "power2.inOut",
    onUpdate: () => {
        counter.textContent = Math.floor(loadProgress.val);
        loaderBar.style.width = `${Math.floor(loadProgress.val)}%`;
    }
});

// Check if user has already accepted T&C
const tncAccepted = localStorage.getItem('tnc_accepted') === 'true';

tl.to('.preloader', {
    y: '-100%',
    duration: 1,
    ease: "power4.inOut",
    onComplete: () => {
        if (!tncAccepted) {
            document.getElementById('tnc-modal').classList.add('active');
        }
    }
});

if (!tncAccepted) {
    tl.addPause(); // Wait for user action ONLY if not accepted
}

tl.from('.hero-title .line', { y: 150, duration: 1.5, stagger: 0.2, ease: "power4.out", skewY: 7 }, "+=0.1");
tl.from('.hero-meta', { opacity: 0, y: 20, duration: 1 }, "-=1");
tl.to('body', { className: 'loaded' }, 0);

// T&C Handlers
document.getElementById('btn-accept')?.addEventListener('click', () => {
    localStorage.setItem('tnc_accepted', 'true');
    document.getElementById('tnc-modal').classList.remove('active');
    tl.resume();
});

document.getElementById('btn-reject')?.addEventListener('click', () => {
    document.body.innerHTML = '<div style="display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;background:#000;color:#ff3333;font-family:monospace;font-size:2rem;text-align:center;letter-spacing:2px;"><div>SYSTEM TERMINATED</div><div style="font-size:1rem;opacity:0.6;margin-top:20px;">USER REJECTED PROTOCOLS</div></div>';
});

// =====================
// APP STATE
// =====================
let scanActive = false;
let tierChart = null;
let allKeys = [];
let vaultFilter = "active";
let socket = null;

const startBtns = document.querySelectorAll('.start-scan');
const stopBtns = document.querySelectorAll('.stop-scan');
const termOutput = document.getElementById('term-output');

startBtns.forEach(btn => btn.addEventListener('click', () => { if (!scanActive) startScan(); }));
stopBtns.forEach(btn => btn.addEventListener('click', () => { if (scanActive) stopScan(); }));

function updateBtnState() {
    startBtns.forEach(b => b.classList.toggle('disabled', scanActive));
    stopBtns.forEach(b => b.classList.toggle('disabled', !scanActive));
}

// =====================
// SOCKET.IO (OPTIMIZED)
// =====================
function initSocketIO() {
    if (typeof io === 'undefined') {
        connectEventSource();
        return;
    }

    socket = io({
        query: { user_id: userId },
        transports: ['websocket', 'polling'],  // Allow polling fallback
        reconnection: true,
        reconnectionAttempts: 10,
        reconnectionDelay: 1000,
        upgrade: false  // Skip polling upgrade
    });

    socket.on('connect', () => {
        console.log('📡 Socket.IO connected');
        logToTerminal('[SYSTEM] REAL-TIME LINK ESTABLISHED', 'system');

        // Update UI
        document.getElementById('socket-status-dot').style.background = '#00ff41'; // Green
        document.getElementById('socket-status-dot').style.boxShadow = '0 0 10px #00ff41';
        document.getElementById('socket-status-text').textContent = 'ONLINE';
        document.getElementById('socket-status-text').style.color = '#00ff41';
    });

    socket.on('connect_error', (err) => {
        console.warn('Socket connection error:', err);
        // Fallback to SSE immediately on error
        if (document.getElementById('socket-status-text').textContent === 'OFFLINE') {
            console.log('🔄 Falling back to EventStream...');
            connectEventSource();

            // Fake online status for SSE
            document.getElementById('socket-status-dot').style.background = '#FFA500'; // Orange for SSE
            document.getElementById('socket-status-text').textContent = 'STREAMING';
            document.getElementById('socket-status-text').style.color = '#FFA500';
        }
    });

    socket.on('log', (data) => {
        // Check for scan completion signal (use includes for robustness)
        if (data.message && data.message.includes('SCAN_FINISHED')) {
            console.log('🔴 Scan finished detected, resetting button state');
            scanActive = false;
            updateBtnState();
        }
        logToTerminal(data.message, data.type || 'system');
    });

    socket.on('scan_status', (data) => {
        if (data.status === 'stopped' || data.status === 'completed') {
            scanActive = false;
            updateBtnState();
        }
    });

    socket.on('connect', () => {
        document.getElementById('socket-status-dot').style.background = '#00ff88';
        document.getElementById('socket-status-dot').style.boxShadow = '0 0 10px #00ff88';
        document.getElementById('socket-status-text').textContent = 'SYSTEM ONLINE';
        document.getElementById('socket-status-text').style.color = '#00ff88';
    });

    socket.on('disconnect', () => {
        document.getElementById('socket-status-dot').style.background = '#ff3333';
        document.getElementById('socket-status-dot').style.boxShadow = 'none';
        document.getElementById('socket-status-text').textContent = 'OFFLINE';
        document.getElementById('socket-status-text').style.color = '#ff3333';
    });

    // REAL-TIME LOG LISTENER (Worker logs to terminal)
    socket.on('log', (data) => {
        if (data && data.message) {
            logToTerminal(data.message, data.type || 'system');
        }
    });

    // REAL-TIME KEY PUSH
    socket.on('key_new', (item) => {
        // ... (Existing Logic) ...
        showToast(`FOUND: ${item.key} [${item.tier}]`);
        allKeys.unshift(item);
        // ... (Stats Logic) ...
        try {
            // ...
        } catch (e) { }

        // Render Vault
        // ...

        // Log
        logToTerminal(`⚡ NEW ASSET ACQUIRED: ${item.key} [${item.tier}]`, 'success');

        // [SECURITY DASHBOARD] If Ledger info is present
        if (item.ledger_hash) {
            addLedgerBlock(item.ledger_hash, item.encrypted_key || "ENCRYPTED_DATA");
        }
    });

    // [SECURITY] LEDGER UPDATE
    socket.on('ledger_update', (data) => {
        addLedgerBlock(data.hash, "SYSTEM_EVENT");
    });

    // [SECURITY] HONEYPOT TRIGGERED
    socket.on('honeypot_triggered', (data) => {
        addHoneypotLog(data);
    });

    socket.on('stats_update_trigger', () => {
        updateStats(); // Force sync
    });
}

// =====================
// SECURITY DASHBOARD LOGIC
// =====================
function addLedgerBlock(hash, type) {
    const feed = document.getElementById('ledger-feed');
    if (!feed) return;

    const div = document.createElement('div');
    div.className = 'ledger-item new-block';
    div.innerHTML = `
        <span class="hash"><i class="fa-solid fa-cube"></i> ${hash.substring(0, 16)}...</span>
        <span class="time">${new Date().toLocaleTimeString()}</span>
    `;

    // Prepend
    feed.insertBefore(div, feed.children[0]); // Keep Genesis at bottom? Or top? Usually top is newest.
    // Actually genesis is usually at bottom. Let's prepend to show newest at top.

    // Limit items
    if (feed.children.length > 20) feed.removeChild(feed.lastChild);
}

function addHoneypotLog(data) {
    const log = document.getElementById('honeypot-log');
    if (!log) return;

    const div = document.createElement('div');
    div.className = 'log-line error';
    div.style.borderLeft = "2px solid #FF003C";
    div.style.paddingLeft = "10px";
    div.innerHTML = `> [ACTIVE_DEFENSE] BANNED IP: ${data.ip} | TRAP: ${data.reason}`;

    log.appendChild(div);
    log.scrollTop = log.scrollHeight;

    // Flash the indicator
    const indicator = document.querySelector('.status-indicator.danger');
    if (indicator) {
        gsap.fromTo(indicator, { opacity: 0.2 }, { opacity: 1, duration: 0.1, yoyo: true, repeat: 5 });
    }

    showToast(`🚫 ACTIVE DEFENSE TRIGGERED: ${data.ip}`);
}

function connectEventSource() {
    const eventSource = new EventSource('/api/stream');
    eventSource.onmessage = (e) => {
        if (e.data === 'SCAN_FINISHED') {
            scanActive = false;
            updateBtnState();
            return;
        }
        if (e.data === '[HEARTBEAT]') return;
        let msg = e.data.replace(/\[.*?\]/g, '');
        let type = msg.includes('FOUND') || msg.includes('✅') ? 'success' : (msg.includes('ERROR') ? 'error' : 'system');
        logToTerminal(msg, type);
    };
    eventSource.onerror = () => setTimeout(connectEventSource, 3000);
}

// =====================
// SCAN CONTROL
// =====================
async function startScan() {
    try {
        const res = await fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'X-User-ID': userId }
        });
        const data = await res.json();

        if (data.status === 'success') {
            scanActive = true;
            updateBtnState();
            logToTerminal("⚡ INITIATING ULTRA-FAST SCAN...", "success");
            switchView('terminal');
        } else if (data.status === 'already_running') {
            logToTerminal("⚠️ SCAN ALREADY IN PROGRESS", "error");
        } else if (data.status === 'auth_required') {
            // COOKIES NOT FOUND - AUTO REDIRECT TO LOGIN
            logToTerminal("🔐 AUTHENTICATION REQUIRED - Opening login browser...", "system");

            // Auto-launch login flow
            try {
                const loginRes = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'X-User-ID': userId }
                });
                const loginData = await loginRes.json();

                if (loginData.status === 'success') {
                    logToTerminal("✅ LOGIN SUCCESSFUL! Resuming scan...", "success");
                    showToast("Login successful! Scan starting...");
                    // Auto-continue
                    startScan();
                } else {
                    logToTerminal(`❌ LOGIN FAILED: ${loginData.message}`, "error");
                }
            } catch (loginErr) {
                logToTerminal("❌ LOGIN ERROR: " + loginErr, "error");
            }
        } else if (data.status === 'error') {
            logToTerminal(`❌ START FAILURE: ${data.message}`, "error");
        }
    } catch (e) {
        logToTerminal("❌ CONNECTION ERROR", "error");
    }
}

async function stopScan() {
    try {
        await fetch('/api/scan/stop', { method: 'POST', headers: { 'X-User-ID': userId } });
        scanActive = false;
        updateBtnState();
        logToTerminal("🛑 ABORTING...", "error");
    } catch (e) { }
}

// =====================
// STATS CHART (OPTIMIZED)
// =====================
function initChart() {
    const ctx = document.getElementById('mainChart')?.getContext('2d');
    if (!ctx) return;

    window.tierChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['GPT-4', 'GPT-3.5', 'Risk > 50', 'Risk > 90'],
            datasets: [{
                label: 'Asset Count',
                data: [0, 0, 0, 0],
                backgroundColor: ['#fff', '#888', '#FFBD2E', '#FF003C'],
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },  // Faster animations
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#888' } },
                x: { grid: { display: false }, ticks: { color: '#888' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}
initChart();

// Debounced stats update
let statsUpdatePending = false;
async function updateStats() {
    if (statsUpdatePending) return;
    statsUpdatePending = true;

    try {
        const res = await fetch('/api/stats', {
            headers: { 'Accept-Encoding': 'gzip' }
        });
        const data = await res.json();
        if (data.error) return;

        document.getElementById('stat-total').textContent = data.total;

        let t1 = 0;
        for (let k in data.tiers) if (k.includes('GPT-4')) t1 += data.tiers[k];
        document.getElementById('stat-tier1').textContent = t1;

        let riskCrit = 0;
        for (let r in data.risks) if (parseInt(r) >= 80) riskCrit += data.risks[r];
        document.getElementById('stat-risk').textContent = riskCrit;

        // [LEVIATHAN] Update Swarm Size
        const swarmEl = document.getElementById('swarm-status-text');
        if (swarmEl && data.swarm_size !== undefined) {
            swarmEl.textContent = `SWARM: ${data.swarm_size}`;
        }

        if (window.tierChart) {
            let t2 = 0;
            for (let k in data.tiers) if (k.includes('3.5')) t2 += data.tiers[k];
            let riskHigh = 0;
            for (let r in data.risks) if (parseInt(r) >= 50) riskHigh += data.risks[r];

            window.tierChart.data.datasets[0].data = [t1, t2, riskHigh, riskCrit];
            window.tierChart.update('none');  // Skip animation for speed
        }
    } catch (e) { }
    finally { statsUpdatePending = false; }
}

// Update every 2 seconds (pre-computed on server)
setInterval(updateStats, 2000);

// =====================
// TERMINAL (OPTIMIZED)
// =====================
const MAX_TERMINAL_LINES = 300;
let terminalBuffer = [];
let terminalRenderPending = false;

function logToTerminal(msg, type) {
    terminalBuffer.push({ msg, type, time: Date.now() });

    // Batch render
    if (!terminalRenderPending) {
        terminalRenderPending = true;
        requestAnimationFrame(renderTerminal);
    }
}

function renderTerminal() {
    terminalRenderPending = false;

    // Process buffer
    const fragment = document.createDocumentFragment();
    terminalBuffer.forEach(({ msg, type }) => {
        const div = document.createElement('div');
        div.className = `log-line ${type}`;
        div.textContent = `> ${msg}`;
        fragment.appendChild(div);
    });
    terminalBuffer = [];

    termOutput.appendChild(fragment);

    // Limit lines (remove oldest)
    while (termOutput.childElementCount > MAX_TERMINAL_LINES) {
        termOutput.removeChild(termOutput.firstChild);
    }

    termOutput.scrollTop = termOutput.scrollHeight;
}

function clearTerminal() {
    termOutput.innerHTML = '';
    logToTerminal('[SYSTEM] TERMINAL CLEARED', 'system');
}

// =====================
// VAULT (VIRTUAL SCROLLING)
// =====================
// Tab click handling is done via onclick in HTML calling setVaultTab()

let vaultUpdatePending = false;
async function updateVault() {
    if (vaultUpdatePending) return;
    vaultUpdatePending = true;

    try {
        const res = await fetch('/api/keys?limit=10000', {
            headers: { 'Accept-Encoding': 'gzip' }
        });
        const data = await res.json();
        allKeys = data.keys || data;
        renderVault();
    } catch (e) { }
    finally { vaultUpdatePending = false; }
}

// =====================
// VAULT LOGIC (FILTER & EXPORT)
// =====================

window.setVaultTab = function (tab) {
    console.log('[VAULT_DEBUG] Switching to tab:', tab);
    vaultFilter = tab;

    // Update button visuals using index (0=Active, 1=Inactive)
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(b => b.classList.remove('active'));

    // Explicitly set active class by index to avoid string matching issues
    if (tab === 'active' && buttons[0]) buttons[0].classList.add('active');
    if (tab === 'inactive' && buttons[1]) buttons[1].classList.add('active');

    renderVault();
}

window.exportVault = function () {
    const format = document.getElementById('export-format').value;
    let content = "";
    let mime = "text/plain";
    let filename = `chronos_${format}_${Date.now()}.${format}`;

    if (format === 'json') {
        content = JSON.stringify(allKeys, null, 2);
        mime = "application/json";
    } else if (format === 'csv') {
        const headers = ["KEY", "FULL_KEY", "STATUS", "TIER", "RISK", "CONTEXT", "FOUND_AT"];
        content = headers.join(",") + "\n" + allKeys.map(k => [
            k.key, k.full_key, k.status, k.tier, k.risk, k.context, k.found_at
        ].join(",")).join("\n");
        mime = "text/csv";
    } else if (format === 'txt') {
        content = allKeys.map(k => k.full_key).join("\n");
    }

    const dataStr = `data:${mime};charset=utf-8,` + encodeURIComponent(content);
    const node = document.createElement('a');
    node.setAttribute("href", dataStr);
    node.setAttribute("download", filename);
    document.body.appendChild(node);
    node.click();
    node.remove();
    logToTerminal(`💾 DATA EXPORTED AS ${format.toUpperCase()}`, 'success');
}

// Virtual scrolling for large key lists
function renderVault() {
    const tbody = document.getElementById('vault-table-body');
    if (!tbody) return;

    console.log('[VAULT_DEBUG] Rendering. Filter:', vaultFilter, '| Total Keys:', allKeys.length);

    // Tab Filter Logic - STANDARDIZED CASE INSENSITIVE
    const filtered = allKeys.filter(k => {
        const s = String(k.status || '').toUpperCase();

        if (vaultFilter === 'active') {
            // Keep strictly valid keys
            return s === 'YES' || s === 'VALID';
        }
        if (vaultFilter === 'inactive') {
            // Keep anything that is NOT valid
            return s !== 'YES' && s !== 'VALID';
        }
        return true;
    });

    console.log('[VAULT] Filtered count:', filtered.length);

    // Use DocumentFragment for batch rendering
    const fragment = document.createDocumentFragment();

    // Show ALL rows (Unlimited)
    filtered.forEach(item => {
        const tr = document.createElement('tr');

        // Colorize Risk
        let riskColor = '#00ff88';
        const riskVal = parseInt(item.risk) || 0;
        if (riskVal >= 80) riskColor = '#ff3333';
        else if (riskVal >= 50) riskColor = '#ffbb33';

        tr.innerHTML = `
            <td class="key-cell" data-key="${item.full_key}">${item.key}</td>
            <td style="color:${riskColor}; font-weight:bold">${item.risk || 0}%</td>
            <td><span class="badge" style="background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius:4px">${item.context || 'N/A'}</span></td>
            <td style="color:var(--highlight)">${item.tier || 'Standard'}</td>
            <td style="color:${item.status === 'yes' ? 'var(--highlight)' : 'var(--danger)'}">${item.status.toUpperCase()}</td>
            <td><button class="copy-btn mini-btn" data-key="${item.full_key}">COPY</button></td>
        `;
        fragment.appendChild(tr);
    });

    tbody.innerHTML = '';
    tbody.appendChild(fragment);

    // No "Show More" needed as we show everything
}

// =====================
// MODAL LOGIC (INTELLIGENCE DOSSIER)
// =====================
const modal = document.getElementById('key-modal');

function openModal(data) {
    if (!modal) return;

    // Populate Fields
    document.getElementById('modal-key-id').textContent = data.full_key;
    document.getElementById('modal-tier').textContent = data.tier || 'UNKNOWN';
    document.getElementById('modal-context').textContent = data.context || 'N/A';
    document.getElementById('modal-found').textContent = new Date(data.found_at).toLocaleString();

    // Risk Score Animation
    const riskEl = document.getElementById('modal-risk');
    const targetRisk = parseInt(data.risk) || 0;

    // Color logic
    if (targetRisk >= 80) riskEl.style.color = '#ff3333';
    else if (targetRisk >= 50) riskEl.style.color = '#ffbb33';
    else riskEl.style.color = '#00ff88';

    // Animate Number
    gsap.fromTo(riskEl, { innerText: 0 }, {
        innerText: targetRisk,
        duration: 1,
        snap: { innerText: 1 },
        onUpdate: function () { riskEl.innerHTML = Math.ceil(this.targets()[0].innerText) + "%"; }
    });

    // Snippet & Stats
    document.getElementById('modal-snippet').textContent = data.snippet || "# No Intelligence Data Captured";
    document.getElementById('modal-stars').textContent = data.stars || 0;
    document.getElementById('modal-forks').textContent = data.forks || 0;

    // Show Modal
    modal.classList.add('active');

    // Copy Button Logic
    document.getElementById('modal-copy-btn').onclick = () => {
        copyToClipboard(data.full_key);
    };
}

// =====================
// UTILS
// =====================
function copyToClipboard(text) {
    if (!text) return;

    // Try modern API
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text).then(() => {
            logToTerminal('📋 KEY COPIED TO CLIPBOARD', 'success');
        }).catch(err => {
            console.error('Clipboard failed', err);
            fallbackCopy(text);
        });
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed"; // Avoid scrolling
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        const successful = document.execCommand('copy');
        if (successful) logToTerminal('📋 KEY COPIED (LEGACY MODE)', 'success');
        else logToTerminal('❌ COPY FAILED', 'error');
    } catch (err) {
        logToTerminal('❌ COPY FAILED', 'error');
    }
    document.body.removeChild(textArea);
}

window.closeModal = function () { // Expose to global scope for HTML onclick
    if (modal) modal.classList.remove('active');
}

// Close on outside click
modal?.addEventListener('click', (e) => {
    if (e.target === modal) closeModal();
});

// Update Row Render to be Clickable
// (Replacing previous event delegation with smarter one)
document.getElementById('vault-table-body')?.addEventListener('click', (e) => {
    // 1. Check if Copy Button was clicked
    if (e.target.classList.contains('copy-btn')) {
        const key = e.target.getAttribute('data-key');
        copyToClipboard(key);
        e.stopPropagation(); // Don't open modal
        return;
    }

    // 2. Otherwise, check if Row was clicked
    const row = e.target.closest('tr');
    if (row) {
        // Find the key data
        const keyText = row.querySelector('.key-cell')?.getAttribute('data-key');
        const keyData = allKeys.find(k => k.full_key === keyText);
        if (keyData) {
            openModal(keyData);
        }
    }
});

// Update backup sync every 15 seconds (Real-time is handled by Socket.IO)
setInterval(updateVault, 15000);

// =====================
// INITIALIZATION
// =====================
document.addEventListener('DOMContentLoaded', () => {
    perfMetrics.timeToInteractive = performance.now() - perfMetrics.pageLoadStart;
    console.log(`⚡ Time to Interactive: ${perfMetrics.timeToInteractive.toFixed(0)}ms`);

    initSocketIO();
    updateStats();

    // Default to showing ALL keys (no filter) and sync button state
    vaultFilter = null;  // null = show ALL keys
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    updateVault();

    // AGGRESSIVE POLLING: Refresh vault every 3 seconds (GUARANTEED real-time)
    setInterval(() => {
        updateVault();
    }, 3000);

    logToTerminal('[SYSTEM] ULTRA-FAST INTERFACE ONLINE', 'system');
    logToTerminal(`[SYSTEM] USER: ${userId.substr(0, 12)}...`, 'system');
    logToTerminal('[SYSTEM] AWAITING INPUT...', 'system');
});

// Check system status
async function checkStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        if (data.scanning) {
            scanActive = true;
            updateBtnState();
        }
    } catch (e) { }
}
checkStatus();

// =====================
// UTILS
// =====================
function showToast(msg) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.style.background = 'rgba(0, 0, 0, 0.8)';
    toast.style.border = '1px solid var(--highlight)';
    toast.style.color = '#fff';
    toast.style.padding = '10px 20px';
    toast.style.borderRadius = '4px';
    toast.style.fontFamily = "'Space Grotesk', monospace";
    toast.style.fontSize = '12px';
    toast.style.backdropFilter = 'blur(10px)';
    toast.style.boxShadow = '0 0 15px rgba(0, 255, 136, 0.2)';
    toast.style.animation = 'slideIn 0.3s ease-out';
    toast.innerHTML = `<i class="fas fa-satellite-dish" style="color:var(--highlight); margin-right:8px;"></i> ${msg}`;

    container.appendChild(toast);

    // Remove after 3s
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => toast.remove(), 500);
    }, 3000);
}

// =====================
// DEVICE DETECTION (USER AGENT)
// =====================
function detectDevice() {
    // Regex for mobile user agents
    const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

    // Check if it's a touch device with small screen (likely tablet/phone)
    // We treat iPad Pro (large screen) as Desktop-like unless UA says otherwise
    const isTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    const isSmall = window.innerWidth < 1024;

    // Final Decision: True Mobile if UA says so, OR if it's a small touch device
    // This allows Desktop Windows resized to small width to REMAIN "is-desktop"
    if (isMobileUA || (isTouch && isSmall)) {
        document.body.classList.add('is-mobile');
        document.body.classList.remove('is-desktop');
    } else {
        document.body.classList.add('is-desktop');
        document.body.classList.remove('is-mobile');
    }
}

// Init
detectDevice();
window.addEventListener('resize', detectDevice);
