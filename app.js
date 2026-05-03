// ── Helpers ──────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Clock ────────────────────────────────────────────
function updateClock() {
  $('clock').textContent =
    new Date().toLocaleTimeString('en-US', { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── Data Arrays ──────────────────────────────────────
let trafficData = Array(60).fill(0).map(() =>
  Math.floor(Math.random() * 300 + 100)
);
let threatData = Array(60).fill(0).map(() =>
  Math.floor(Math.random() * 30)
);

// ── Stat counters ────────────────────────────────────
let packetCount = 1_280_000;
let threatCount = 147;
let respTime    = 42;
let gaugeVal    = 62;
let paused      = false;
let tick        = 0;
let allLogs     = [];

// ── Animate number from 0 to target ──────────────────
function animateTo(el, target, suffix = '') {
  let cur = 0;
  const step = Math.ceil(target / 40);
  const interval = setInterval(() => {
    cur = Math.min(cur + step, target);
    el.textContent = cur.toLocaleString() + suffix;
    if (cur >= target) clearInterval(interval);
  }, 30);
}

// ── Traffic Canvas ────────────────────────────────────
const tc  = $('trafficCanvas');
const ctx = tc.getContext('2d');

function drawTraffic() {
  tc.width  = tc.parentElement.offsetWidth;
  tc.height = tc.parentElement.offsetHeight - 36;
  const w   = tc.width;
  const h   = tc.height;

  ctx.clearRect(0, 0, w, h);

  const max  = Math.max(...trafficData, 500);
  const step = w / (trafficData.length - 1);

  // Grid lines
  ctx.strokeStyle = 'rgba(0,200,120,0.06)';
  ctx.lineWidth   = 0.5;
  for (let i = 0; i <= 4; i++) {
    const y = (h / 4) * i;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }

  // Threat area
  ctx.beginPath();
  ctx.moveTo(0, h - (threatData[0] / max) * (h - 20));
  for (let i = 1; i < threatData.length; i++) {
    ctx.lineTo(i * step, h - (threatData[i] / max) * (h - 20));
  }
  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.fillStyle = 'rgba(255,68,68,0.08)';
  ctx.fill();

  // Threat line
  ctx.beginPath();
  ctx.moveTo(0, h - (threatData[0] / max) * (h - 20));
  for (let i = 1; i < threatData.length; i++) {
    ctx.lineTo(i * step, h - (threatData[i] / max) * (h - 20));
  }
  ctx.strokeStyle = 'rgba(255,68,68,0.5)';
  ctx.lineWidth   = 1;
  ctx.stroke();

  // Traffic area
  ctx.beginPath();
  ctx.moveTo(0, h - (trafficData[0] / max) * (h - 20));
  for (let i = 1; i < trafficData.length; i++) {
    ctx.lineTo(i * step, h - (trafficData[i] / max) * (h - 20));
  }
  ctx.lineTo(w, h);
  ctx.lineTo(0, h);
  ctx.fillStyle = 'rgba(0,200,120,0.07)';
  ctx.fill();

  // Traffic line
  ctx.beginPath();
  ctx.moveTo(0, h - (trafficData[0] / max) * (h - 20));
  for (let i = 1; i < trafficData.length; i++) {
    ctx.lineTo(i * step, h - (trafficData[i] / max) * (h - 20));
  }
  ctx.strokeStyle = '#00C878';
  ctx.lineWidth   = 1.5;
  ctx.stroke();

  // Labels
  ctx.fillStyle = 'rgba(232,244,240,0.25)';
  ctx.font      = '10px JetBrains Mono';
  ctx.fillText(Math.round(max) + ' pkt/s', 8, 14);
  ctx.fillText('— traffic   — threats', w - 130, 14);
}

// ── Gauge ─────────────────────────────────────────────
function updateGauge(val) {
  const arc   = $('gauge-arc');
  const total = 220;
  const fill  = (val / 100) * total;
  arc.setAttribute('stroke-dashoffset', String(total - fill));

  const color =
    val > 75 ? '#FF4444' :
    val > 45 ? '#FFB800' : '#00C878';

  arc.setAttribute('stroke', color);
  $('gauge-val').textContent = Math.round(val);
  $('gauge-val').style.color = color;

  const label =
    val > 75 ? ['CRITICAL', 'badge-red']   :
    val > 45 ? ['ELEVATED', 'badge-amber'] :
               ['NORMAL',   'badge-green'];

  $('threat-label').textContent = label[0];
  $('threat-label').className   = 'badge ' + label[1];
}

// ── IP Threat Sources ─────────────────────────────────
const topIPs = [
  { flag: '🇨🇳', ip: '218.93.148.22',  country: 'China',     count: 847, pct: 100 },
  { flag: '🇷🇺', ip: '91.108.56.199',  country: 'Russia',    count: 612, pct: 72  },
  { flag: '🇰🇵', ip: '175.45.176.44',  country: 'N. Korea',  count: 489, pct: 58  },
  { flag: '🇧🇷', ip: '177.93.14.132',  country: 'Brazil',    count: 234, pct: 28  },
  { flag: '🇺🇸', ip: '104.21.55.78',   country: 'USA (TOR)', count: 198, pct: 23  },
  { flag: '🇮🇷', ip: '5.61.38.211',    country: 'Iran',      count: 156, pct: 18  },
];

function renderIPs() {
  $('ip-list').innerHTML = topIPs.map(ip => `
    <div class="ip-row">
      <span class="ip-flag">${ip.flag}</span>
      <span class="ip-addr">${ip.ip}</span>
      <span class="ip-country">${ip.country}</span>
      <div class="ip-bar">
        <div class="ip-bar-fill" style="width:${ip.pct}%"></div>
      </div>
      <span class="ip-count">${ip.count}</span>
    </div>
  `).join('');
}

// ── Event Log Templates ───────────────────────────────
const evtTemplates = [
  { sev: 'CRIT', msgs: [
    'Port scan detected — 65535 ports swept',
    'Reverse shell attempt blocked',
    'SQL injection payload in HTTP POST',
    'Zero-day exploit signature matched',
  ]},
  { sev: 'HIGH', msgs: [
    'SSH brute force — 847 attempts/min',
    'DDoS flood detected — 18k pkt/s',
    'Privilege escalation attempt',
    'Malformed packet header anomaly',
  ]},
  { sev: 'MED', msgs: [
    'Unusual outbound DNS query volume',
    'ICMP flood from single source',
    'HTTP 4xx burst — possible scanner',
    'ARP spoofing pattern detected',
  ]},
  { sev: 'LOW', msgs: [
    'New device joined network segment',
    'Single port 22 probe detected',
    'TLS certificate mismatch warning',
    'Login attempt outside business hours',
  ]},
];

function randomIP() {
  const pools = [
    '218.93', '91.108', '175.45',
    '177.93', '5.61',   '103.22',
    '45.89',  '195.82',
  ];
  const pool = pools[Math.floor(Math.random() * pools.length)];
  return pool + '.'
    + Math.floor(Math.random() * 255) + '.'
    + Math.floor(Math.random() * 255);
}

function addLogEntry(forceCritical = false) {
  const now    = new Date();
  const time   = now.toTimeString().split(' ')[0];
  const sevIdx = forceCritical ? 0 : Math.floor(Math.random() * 4);
  const { sev, msgs } = evtTemplates[sevIdx];
  const msg = msgs[Math.floor(Math.random() * msgs.length)];
  const src = randomIP();

  allLogs.unshift({ time, sev, src, msg });
  if (allLogs.length > 200) allLogs.pop();

  if (sev === 'CRIT' || sev === 'HIGH') {
    threatCount++;
    $('stat-threats').textContent = threatCount.toLocaleString();
    gaugeVal = Math.min(100, gaugeVal + (sev === 'CRIT' ? 4 : 1.5));
    updateGauge(gaugeVal);
    const ac = parseInt($('alert-count').textContent);
    $('alert-count').textContent = ac + 1;
  }

  renderLog();
}

function renderLog() {
  const search   = $('search-input').value.toLowerCase();
  const filter   = $('sev-filter').value;
  const sevOrder = { CRIT: 0, HIGH: 1, MED: 2, LOW: 3 };
  const maxFilter =
    filter === 'CRIT' ? 0 :
    filter === 'HIGH' ? 1 :
    filter === 'MED'  ? 2 : 3;

  const visible = allLogs.filter(e => {
    const matchSev    = sevOrder[e.sev] <= maxFilter;
    const matchSearch = !search
      || e.src.includes(search)
      || e.msg.toLowerCase().includes(search);
    return matchSev && matchSearch;
  });

  const container = $('log-container');
  const header    = container.firstElementChild;
  container.innerHTML = '';
  container.appendChild(header);

  visible.slice(0, 30).forEach((e, i) => {
    const div     = document.createElement('div');
    div.className = 'log-entry';
    if (i === 0) div.style.animation = 'fadeIn 0.35s ease';
    div.innerHTML = `
      <span class="log-time">${e.time}</span>
      <span class="log-sev ${e.sev}">${e.sev}</span>
      <span class="log-src">${e.src}</span>
      <span class="log-msg">${e.msg}</span>
    `;
    container.appendChild(div);
  });
}

// ── Controls ──────────────────────────────────────────
function applyFilter() { renderLog(); }

function togglePause() {
  paused = !paused;
  const btn = $('pause-btn');
  if (paused) {
    btn.textContent            = '▶ Resume Feed';
    btn.className              = 'btn btn-green';
    $('log-badge').textContent = '■ PAUSED';
  } else {
    btn.textContent            = '⏸ Pause Feed';
    btn.className              = 'btn btn-red';
    $('log-badge').textContent = '● STREAMING';
  }
}

function clearAlerts() {
  allLogs = [];
  $('alert-count').textContent = '0';
  gaugeVal = Math.max(20, gaugeVal - 30);
  updateGauge(gaugeVal);
  renderLog();
}

function simulateAttack() {
  for (let i = 0; i < 6; i++) {
    setTimeout(() => addLogEntry(true), i * 200);
  }
  const spike = Array(12).fill(0).map(() =>
    Math.floor(Math.random() * 400 + 600)
  );
  trafficData = [...trafficData.slice(12), ...spike];
  threatData  = [...threatData.slice(12),
    ...Array(12).fill(0).map(() =>
      Math.floor(Math.random() * 80 + 60)
    )
  ];
  drawTraffic();
}

// ── Main Loop ─────────────────────────────────────────
function mainLoop() {
  tick++;

  if (!paused) {
    const newPkt = Math.floor(
      Math.random() * 200 + 50 + Math.sin(tick * 0.1) * 80
    );

    trafficData.shift();
    trafficData.push(newPkt);
    threatData.shift();
    threatData.push(Math.floor(Math.random() * 20));

    packetCount += newPkt;
    $('stat-packets').textContent =
      (packetCount / 1_000_000).toFixed(2) + 'M';

    respTime = Math.max(18, Math.min(80,
      respTime + (Math.random() - 0.5) * 8
    ));
    $('stat-resp').textContent = Math.round(respTime) + 'ms';

    gaugeVal = Math.max(20, Math.min(95,
      gaugeVal + (Math.random() - 0.52) * 2
    ));
    updateGauge(gaugeVal);

    drawTraffic();

    if (tick % 20 === 0) addLogEntry(false);
  }

  setTimeout(mainLoop, 100);
}

// ── Start ─────────────────────────────────────────────
window.addEventListener('resize', drawTraffic);

setTimeout(() => {
  updateGauge(gaugeVal);
  animateTo($('stat-threats'), threatCount);
  animateTo($('stat-packets'), packetCount);
  $('stat-resp').textContent = respTime + 'ms';
  drawTraffic();
  renderIPs();
  for (let i = 0; i < 10; i++) addLogEntry(false);
  mainLoop();
}, 200);
// ── WebSocket connection to Python backend ────────────
function connectBackend() {
    const ws = new WebSocket('ws://localhost:8765');
  
    ws.onopen = () => {
      console.log('[NetWatch] Connected to Python backend');
    };
  
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
  
      // Feed real packet into the log (reuse your existing function)
      const now = new Date();
      allLogs.unshift({
        time: data.time,
        sev:  data.sev,
        src:  data.src,
        msg:  data.msg,
      });
      if (allLogs.length > 200) allLogs.pop();
  
      // Update threat counter and gauge for real HIGH/CRIT events
      if (data.sev === 'CRIT' || data.sev === 'HIGH') {
        threatCount++;
        $('stat-threats').textContent = threatCount.toLocaleString();
        gaugeVal = Math.min(100, gaugeVal + (data.sev === 'CRIT' ? 4 : 1.5));
        updateGauge(gaugeVal);
        const ac = parseInt($('alert-count').textContent);
        $('alert-count').textContent = ac + 1;
      }
  
      if (!paused) renderLog();
    };
  
    ws.onclose = () => {
      console.log('[NetWatch] Backend disconnected — retrying in 3s');
      setTimeout(connectBackend, 3000); // auto-reconnect
    };
  
    ws.onerror = (err) => {
      console.warn('[NetWatch] WebSocket error', err);
    };
  }
  
  connectBackend();