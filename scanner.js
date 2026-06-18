const API = 'http://localhost:8080';

// stores last scan result so all sections can use it
let lastScan = JSON.parse(sessionStorage.getItem('scanResult') || 'null');

// chart instances — keep references so we can destroy before re-creating
let categoryChartInst = null;
let groverChartInst   = null;
let shorChartInst     = null;
let hndlChartInst     = null;
let attackChartInst   = null;

// SECTION NAVIGATION

function showSection(name) {
  document.querySelectorAll('.section-page').forEach(s => s.style.display = 'none');
  document.querySelectorAll('.nav-tab-btn').forEach(b => b.classList.remove('active'));

  document.getElementById('section-' + name).style.display = 'block';

  const btn = document.getElementById('tab-' + name);
  if (btn) btn.classList.add('active');

  if (name === 'results')   renderResultsSection();
  if (name === 'dashboard') renderDashboard();
  if (name === 'quantum')   initQuantumSection();
  if (name === 'report')    renderReport();

  window.scrollTo(0, 0);
}

// INPUT VALIDATION


function looksLikeCode(text) {
  const codePatterns = [
    // common code keywords
    /\b(function|class|import|export|return|if|else|for|while|def|void|public|private|static|const|let|var|int|string|bool)\b/i,
    // line ending with ; or { or }
    /[;{}]/,
    // function call pattern
    /\w+\s*\(/,
    // assignment
    /\w+\s*=\s*\w+/,
    // comment syntax
    /\/\/|\/\*|#\s+\w|<!--/,
    // typical code structure like :: or -> or =>
    /::|-\s*>|=>/,
  ];

  let matches = 0;
  for (const pat of codePatterns) {
    if (pat.test(text)) matches++;
  }

  // need at least 2 code-like patterns to be considered valid code
  return matches >= 2;
}

function countCodeLines(text) {
  const lines = text.split('\n');
  let codeLines = 0;
  for (const line of lines) {
    const t = line.trim();
    if (t.length === 0) continue;
    if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*') || t.startsWith('<!--')) continue;
    codeLines++;
  }
  return codeLines;
}

// SCAN LOGIC

function startScan() {
  const code   = document.getElementById('codeInput').value.trim();
  const sector = document.getElementById('sectorSelect').value;

  if (!code) {
    alert('Please paste some code first, or click one of the sample buttons.');
    return;
  }

  // check that input looks like real source code
  if (!looksLikeCode(code)) {
    alert(
      'This doesn\'t look like source code.\n\n' +
      'QuantumGuard scans programming code (Java, Python, PHP, JS etc.).\n' +
      'Try loading one of the sample buttons to see how it works.\n\n' +
      'If you pasted code and still see this, make sure the code has functions, imports, or statements.'
    );
    return;
  }

  if (code.length < 20) {
    alert('Code is too short to scan. Paste at least a few lines of code.');
    return;
  }

  showProgress();

  const messages = [
    'Computing SHA-3-256 hash...',
    'Detecting programming language...',
    'Scanning for present-day vulnerabilities...',
    'Scanning for quantum-future threats...',
    'Calculating security score...',
    'Generating results...'
  ];
  let step = 0;
  const msgEl = document.getElementById('progressMsg');
  const barEl = document.getElementById('progressBar');
  const interval = setInterval(() => {
    if (step < messages.length) {
      msgEl.textContent = messages[step];
      barEl.style.width = Math.round(((step + 1) / messages.length) * 80) + '%';
      step++;
    }
  }, 300);

  fetch(API + '/api/scan', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ code, sector })
  })
  .then(r => r.json())
  .then(data => {
    clearInterval(interval);
    barEl.style.width = '100%';
    msgEl.textContent = 'Scan complete!';

    if (data.error) {
      hideProgress();
      alert('Scan error: ' + data.error);
      return;
    }

    // show SHA-3 hash on scan page
    const hashSec = document.getElementById('hashSection');
    if (hashSec) {
      hashSec.style.display = 'block';
      document.getElementById('sha3Display').textContent = data.sha3Hash;
    }

    lastScan = data;
    sessionStorage.setItem('scanResult', JSON.stringify(data));

    setTimeout(() => {
      hideProgress();
      showSection('results');
    }, 700);
  })
  .catch(() => {
    clearInterval(interval);
    hideProgress();
    alert(
      'Could not connect to the Java server.\n\n' +
      'Make sure QuantumGuardServer is running:\n' +
      '  Windows: double-click run.bat\n' +
      '  Mac/Linux: ./run.sh\n\n' +
      'Then open http://localhost:8080 (NOT localhost:5500)\n\n' +
      'See the Help tab for full setup instructions.'
    );
  });
}

function showProgress() {
  document.getElementById('progressSection').style.display = 'block';
  const sb = document.getElementById('scanBtn');
  if (sb) { sb.disabled = true; sb.textContent = 'Scanning...'; }
}

function hideProgress() {
  document.getElementById('progressSection').style.display = 'none';
  const sb = document.getElementById('scanBtn');
  if (sb) { sb.disabled = false; sb.textContent = '🔍 Scan My Code Now'; }
}


// ══════════════════════════════════════════════════════════════════
// SAMPLE CODE SNIPPETS
// ══════════════════════════════════════════════════════════════════

const SAMPLES = {
  'java-bad': `import java.security.MessageDigest;
import java.util.Random;
import java.sql.*;

public class BankingApp {
    // TODO: move these to env variables before production!
    static String DB_PASSWORD = "admin@bank2024";
    static String API_SECRET  = "sk-bank-live-key-9f8e7d6c5b4a";

    public String hashPassword(String p) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(p.getBytes()));
    }

    public String generateToken() {
        Random rand = new Random();  // not secure but works for now
        return String.valueOf(rand.nextInt(9999));
    }

    public void getUser(String userId) throws Exception {
        String query = "SELECT * FROM users WHERE id=" + userId;
        String url   = "http://api.mybank.com/login";
        System.out.println("Connecting with password: " + DB_PASSWORD);
    }
}`,

  'java-good': `import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;

public class SecureApp {
    // passwords loaded from environment variables — never hardcode!
    String dbPass = System.getenv("DB_PASSWORD");
    String apiKey = System.getenv("API_KEY");

    public String hashPassword(String p) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        StringBuilder sb = new StringBuilder();
        for (byte b : md.digest(p.getBytes())) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public String generateToken() {
        SecureRandom rand = new SecureRandom(); // cryptographically secure RNG
        return String.valueOf(rand.nextInt(999999));
    }

    public void getUser(String userId, Connection conn) throws Exception {
        // parameterised query — no SQL injection possible
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE id=?"
        );
        ps.setString(1, userId);
    }
}`,

  'python-bad': `import random
import hashlib

# TODO: move to .env file
password = "mypassword123"
api_key  = "sk-python-secret-key-abc123"

def hash_password(p):
    return hashlib.md5(p.encode()).hexdigest()

def hash_data(data):
    return hashlib.sha1(data.encode()).hexdigest()

def get_token():
    return random.randint(1000, 9999)  # not secure

url   = "http://api.hospital.com/patients"
query = "SELECT * FROM patients WHERE id=" + patient_id
print("Using password: " + password)`,

  'php-bad': `<?php
// hospital patient database connection
$conn = mysqli_connect("localhost", "root", "hospital@123");

// get patient by ID from URL
$patient_id = $_GET['id'];
$query = "SELECT * FROM patients WHERE id=" . $patient_id;
$result = mysqli_query($conn, $query);

// hash the password with MD5
$password = md5($_POST['password']);
$token = rand(1000, 9999);

$api = "http://hospital-api.example.com/records";
$secret = "sk-hospital-key-abc789xyz";

echo "Password hash: " . $password;
?>`
};

function loadSample(name) {
  document.getElementById('codeInput').value = SAMPLES[name] || '';
}

function loadFile(input) {
  const file = input.files[0];
  if (!file) return;
  if (file.size > 51200) { alert('File too large. Max 50KB.'); return; }
  const reader = new FileReader();
  reader.onload = e => document.getElementById('codeInput').value = e.target.result;
  reader.readAsText(file);
}


// ══════════════════════════════════════════════════════════════════
// RESULTS SECTION
// ══════════════════════════════════════════════════════════════════

function renderResultsSection() {
  if (!lastScan || lastScan.error) {
    document.getElementById('noResults').style.display    = 'block';
    document.getElementById('resultsContent').style.display = 'none';
    return;
  }
  document.getElementById('noResults').style.display    = 'none';
  document.getElementById('resultsContent').style.display = 'block';
  renderResults(lastScan);
}

function renderResults(d) {
  const gc = { A:'success', B:'primary', C:'warning', D:'danger', F:'danger' };
  document.getElementById('scoreHeader').innerHTML = `
    <div class="col-sm-2">
      <div class="qg-metric">
        <div class="qg-grade-circle grade-${d.grade}">${d.grade}</div>
        <div class="small text-muted mt-2">Grade</div>
        <div class="text-muted" style="font-size:0.72rem">A=best, F=worst</div>
      </div>
    </div>
    <div class="col-sm-2">
      <div class="qg-metric">
        <div class="qg-big-num text-${gc[d.grade]||'danger'}">${d.score}<span class="fs-6">/100</span></div>
        <div class="small text-muted">Security Score</div>
      </div>
    </div>
    <div class="col-sm-2">
      <div class="qg-metric">
        <div class="qg-big-num text-primary">${d.agilityScore}<span class="fs-6">/10</span></div>
        <div class="small text-muted">Crypto Agility</div>
      </div>
    </div>
    <div class="col-sm-2">
      <div class="qg-metric">
        <div class="qg-big-num text-secondary" style="font-size:1.2rem">${d.migrationEffort}</div>
        <div class="small text-muted">Est. Fix Time</div>
      </div>
    </div>
    <div class="col-sm-4">
      <div class="qg-metric text-start">
        <div class="small mb-1"><strong>Language:</strong> ${d.language}</div>
        <div class="small mb-1"><strong>Lines scanned:</strong> ${d.totalLines}</div>
        <div class="small mb-1"><strong>Total findings:</strong> ${d.totalFindings}</div>
        <div class="small"><strong>Sector:</strong> ${d.sector}</div>
      </div>
    </div>`;

  if (d.sha3Hash) {
    document.getElementById('resultsHashSection').style.display = 'block';
    document.getElementById('resultsHashDisplay').textContent   = d.sha3Hash;
  }

  const all     = d.findings || [];
  const present = all.filter(f => f.layer === 'PRESENT' || f.layer === 'BOTH');
  const quantum = all.filter(f => f.layer === 'QUANTUM' || f.layer === 'BOTH');

  document.getElementById('presentCount').textContent   = present.length;
  document.getElementById('quantumCount').textContent   = quantum.length;
  document.getElementById('checklistCount').textContent = all.length;

  if (present.length === 0) {
    document.getElementById('noPresentMsg').style.display = 'block';
    document.getElementById('presentFindings').innerHTML  = '';
  } else {
    document.getElementById('noPresentMsg').style.display = 'none';
    document.getElementById('presentFindings').innerHTML  = present.map(f => findingCard(f)).join('');
  }

  if (quantum.length === 0) {
    document.getElementById('noQuantumMsg').style.display = 'block';
    document.getElementById('quantumFindings').innerHTML  = '';
  } else {
    document.getElementById('noQuantumMsg').style.display = 'none';
    document.getElementById('quantumFindings').innerHTML  = quantum.map(f => findingCard(f)).join('');
  }

  document.getElementById('checklistItems').innerHTML = all.length === 0
    ? '<div class="alert alert-success">🎉 No fixes needed — code is clean!</div>'
    : all.map((f, i) => checklistItem(f, i)).join('');
}

function findingCard(f) {
  const sc = f.severity === 'CRITICAL' ? 'danger' : 'warning';
  return `
    <div class="card qg-finding-card mb-3 border-${sc} finding-card" data-severity="${f.severity}">
      <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2 bg-${sc} bg-opacity-10">
        <div>
          <span class="badge bg-${sc} me-2">${f.severity}</span>
          <strong>${esc(f.name)}</strong>
          <span class="text-muted ms-2 small">${f.cveId}</span>
        </div>
        <div class="d-flex gap-2 align-items-center">
          <span class="badge bg-secondary">Line ${f.lineNumber}</span>
          <span class="badge bg-light text-dark border">${f.category}</span>
          <button class="btn btn-sm btn-outline-secondary py-0" onclick="this.closest('.qg-finding-card').style.display='none'">Dismiss</button>
        </div>
      </div>
      <div class="card-body">
        <code class="d-block p-2 bg-light rounded small mb-2">${esc(f.lineContent)}</code>
        <div class="row g-2">
          <div class="col-md-6">
            <div class="small fw-bold text-danger mb-1">🔴 What's wrong right now?</div>
            <div class="small">${esc(f.presentRisk)}</div>
          </div>
          <div class="col-md-6">
            <div class="small fw-bold qg-quantum-impact mb-1">⚡ How does quantum make it worse?</div>
            <div class="small">${esc(f.quantumImpact)}</div>
          </div>
        </div>
        <div class="mt-2 small">
          <span class="fw-bold text-success">✅ Fix: </span>${esc(f.fix)}
          <span class="text-muted ms-2">| NIST: ${f.nistRef}</span>
        </div>
      </div>
    </div>`;
}

function checklistItem(f, i) {
  const sc = f.severity === 'CRITICAL' ? 'danger' : 'warning';
  return `
    <div class="qg-checklist-item mb-4">
      <div class="form-check mb-2">
        <input class="form-check-input" type="checkbox" id="chk${i}">
        <label class="form-check-label fw-semibold" for="chk${i}">
          <span class="badge bg-${sc} me-2">${f.severity}</span>
          ${esc(f.name)} — Line ${f.lineNumber}
        </label>
      </div>
      <div class="ms-4">
        <div class="row g-2 mt-1">
          <div class="col-md-6">
            <div class="small fw-bold text-danger mb-1">❌ Before (insecure)</div>
            <pre class="qg-code-block bg-danger bg-opacity-10 border border-danger p-2 small">${esc(f.beforeCode)}</pre>
          </div>
          <div class="col-md-6">
            <div class="small fw-bold text-success mb-1">✅ After (secure fix)</div>
            <pre class="qg-code-block bg-success bg-opacity-10 border border-success p-2 small">${esc(f.afterCode)}</pre>
          </div>
        </div>
        <div class="small text-muted mt-1">NIST: ${f.nistRef} | Est. fix time: ${f.fixTimeMinutes} min</div>
      </div>
    </div>`;
}

function showRTab(tab, btn) {
  ['present','quantum','checklist'].forEach(t =>
    document.getElementById(t+'Tab').style.display = t === tab ? 'block' : 'none');
  document.querySelectorAll('#resultTabs .nav-link').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}

function filterSev(sev, btn) {
  document.querySelectorAll('.finding-card').forEach(c =>
    c.style.display = (sev === 'all' || c.dataset.severity === sev) ? 'block' : 'none');
  document.querySelectorAll('#filterBtns button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}


// ══════════════════════════════════════════════════════════════════
// DASHBOARD
// ══════════════════════════════════════════════════════════════════

function renderDashboard() {
  if (!lastScan || lastScan.error) {
    document.getElementById('noDashData').style.display = 'block';
    document.getElementById('dashContent').style.display = 'none';
    return;
  }
  document.getElementById('noDashData').style.display  = 'none';
  document.getElementById('dashContent').style.display = 'block';

  const d = lastScan;
  document.getElementById('dScore').textContent    = d.score + '/100';
  document.getElementById('dFindings').textContent = d.totalFindings;
  document.getElementById('dAgility').textContent  = d.agilityScore + '/10';
  const gEl = document.getElementById('dGrade');
  gEl.textContent = d.grade;
  gEl.className   = 'qg-grade-circle grade-' + d.grade;
  gEl.style.cssText = 'width:56px;height:56px;font-size:1.4rem;margin:0 auto';

  if (categoryChartInst) categoryChartInst.destroy();
  const cats = {};
  (d.findings || []).forEach(f => { cats[f.category] = (cats[f.category]||0)+1; });
  const catCanvas = document.getElementById('categoryChart');
  if (Object.keys(cats).length > 0) {
    categoryChartInst = new Chart(catCanvas, {
      type: 'doughnut',
      data: {
        labels: Object.keys(cats),
        datasets: [{ data: Object.values(cats),
          backgroundColor: ['#dc2626','#d97706','#2563eb','#16a34a','#7c3aed','#64748b'] }]
      },
      options: { responsive:true, maintainAspectRatio:false, plugins:{ legend:{ position:'right' } } }
    });
  } else {
    catCanvas.parentElement.innerHTML =
      '<div class="text-center text-success py-5 fw-bold">✅ No findings — code is clean!</div>';
  }

  new Chart(document.getElementById('timelineChart'), {
    type: 'bar',
    data: {
      labels: ['MD5','SHA-1','DES','TLS 1.0','AES-128','RSA-2048','ECC-256','SHA-256','AES-256'],
      datasets: [
        { label:'Broken classically (year)', data:[2004,2017,1999,2011,0,0,0,0,0],  backgroundColor:'#dc2626' },
        { label:'Broken by quantum (est.)',  data:[0,0,0,0,2030,2032,2030,2035,0],  backgroundColor:'#d97706' },
        { label:'Quantum-safe ✓',            data:[0,0,0,0,0,0,0,0,1],             backgroundColor:'#16a34a' }
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ position:'top' } },
      scales:{ y:{ beginAtZero:true,
        ticks:{ callback: v => v > 0 && v < 9999 ? v : v===1 ? 'Safe ✓' : '' },
        title:{ display:true, text:'Year broken (estimated)' }
      }}
    }
  });
}

function calculateHNDL() {
  const payload = {
    dataType:       document.getElementById('hndlData').value,
    sector:         document.getElementById('hndlSector').value,
    worstAlgorithm: document.getElementById('hndlAlgo').value
  };

  const calc = () => {
    const ds = { health:10, financial:9, government:8, personal:6 }[payload.dataType] || 3;
    const qv = { rsa:10, ecc:9, des:8, aes128:6, sha1:5, md5:4 }[payload.worstAlgorithm] || 1;
    const su = { government:10, banking:10, healthcare:8, education:5 }[payload.sector] || 3;
    const raw = (ds*0.4)+(qv*0.4)+(su*0.2);
    const score = Math.round(raw*10);
    const risk  = score>=75?'CRITICAL':score>=50?'HIGH':score>=25?'MEDIUM':'LOW';
    const action = score>=75
      ? 'Immediate migration to CRYSTALS-Kyber + SHA-3 required. Your data is actively being recorded for future decryption.'
      : score>=50 ? 'Plan migration within 12 months — quantum computers may arrive before 2030.'
      : score>=25 ? 'Schedule migration within 2 years. Evaluate NIST PQC standards now.'
      : 'Low risk. Review cryptography annually.';
    return { score, riskLevel:risk, action, formula:`(${ds}×0.4) + (${qv}×0.4) + (${su}×0.2) = ${raw.toFixed(1)}`, ds, qv, su };
  };

  const render = d => {
    document.getElementById('hndlResult').style.display = 'block';
    const sc = document.getElementById('hndlScore');
    const lv = document.getElementById('hndlLevel');
    const ac = document.getElementById('hndlAction');
    sc.textContent = d.score;
    sc.className   = 'qg-big-num text-'+(d.riskLevel==='CRITICAL'?'danger':d.riskLevel==='HIGH'?'warning':'success');
    lv.textContent = d.riskLevel;
    lv.className   = 'badge fs-6 mt-1 bg-'+(d.riskLevel==='CRITICAL'?'danger':d.riskLevel==='HIGH'?'warning':'success');
    ac.textContent = d.action;
    ac.className   = 'alert alert-'+(d.riskLevel==='CRITICAL'?'danger':d.riskLevel==='HIGH'?'warning':'success')+' mb-2';
    document.getElementById('hndlFormula').textContent = d.formula||'';

    if (hndlChartInst) hndlChartInst.destroy();
    hndlChartInst = new Chart(document.getElementById('hndlChart'), {
      type: 'bar',
      data: {
        labels: ['Data Sensitivity (×0.4)','Quantum Vulnerability (×0.4)','Sector Urgency (×0.2)','Final Score'],
        datasets: [{
          label: 'Score',
          data: [(d.ds||0)*4, (d.qv||0)*4, (d.su||0)*2, d.score],
          backgroundColor: ['#2563eb','#dc2626','#d97706','#16a34a']
        }]
      },
      options: { responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ display:false } },
        scales:{ y:{ beginAtZero:true, max:100 } }
      }
    });
  };

  fetch(API+'/api/hndl', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) })
    .then(r=>r.json()).then(render).catch(()=>render(calc()));
}


// ══════════════════════════════════════════════════════════════════
// QUANTUM SECTION — VISUALIZERS
// ══════════════════════════════════════════════════════════════════

function initQuantumSection() {
  updateGrover();
  runShor();
  fetchAttacks();
  // Pre-populate Grover sim defaults
  const gq = document.getElementById('groverSimQubits');
  const gt = document.getElementById('groverSimTarget');
  if (gq && !gq.value) gq.value = '3';
  if (gt && !gt.value) gt.value = '5';
}

// ── QUBIT VISUALIZER ──────────────────────────────────────────────
function setQubit(state) {
  const circle = document.getElementById('qubitCircle');
  const label  = document.getElementById('qubitStateLabel');

  circle.className = 'qubit-circle';

  const states = {
    '0':   { cls:'qubit-state-0',   text:'|0⟩',  desc:'Definite zero — classical bit (0)' },
    '1':   { cls:'qubit-state-1',   text:'|1⟩',  desc:'Definite one — classical bit (1)' },
    'sup': { cls:'qubit-state-sup', text:'|+⟩',  desc:'Superposition = (|0⟩ + |1⟩) / √2 — 0 and 1 simultaneously' },
    'ent': { cls:'qubit-state-ent', text:'|Φ+⟩', desc:'Entangled Bell state — measuring one qubit instantly determines the other' }
  };
  const s = states[state] || states['sup'];
  circle.classList.add(s.cls);
  circle.textContent = s.text;
  label.textContent  = s.desc;
}

// ── SHOR'S ALGORITHM VISUALIZER ───────────────────────────────────
const SHOR_DATA = {
  '15': { r:4,  steps:[
    { type:'classical', text:'N=15. Choose random a=2. Check GCD(2,15)=1 — not a trivial factor, proceed.' },
    { type:'quantum',   text:'QUANTUM STEP: Create superposition of all x values. Compute f(x) = 2ˣ mod 15 for ALL x simultaneously. A classical computer must do this one by one.' },
    { type:'quantum',   text:'QUANTUM STEP: Apply Quantum Fourier Transform (QFT). This reveals periodic peaks. The peaks occur at multiples of N/r, exposing period r=4.' },
    { type:'classical', text:'r=4 is even. Compute a^(r/2) = 2² = 4. Then: GCD(5,15)=5 and GCD(3,15)=3.' },
    { type:'result',    text:'15 = 3 × 5 ✓  At RSA-2048 scale: same algorithm, 4,099 logical qubits, ~8 hours (Gidney & Ekerå 2021).' }
  ]},
  '21': { r:6, steps:[
    { type:'classical', text:'N=21. Choose a=2. GCD(2,21)=1 — proceed.' },
    { type:'quantum',   text:'QUANTUM STEP: Superpose register. f(x)=2ˣ mod 21 for all x simultaneously.' },
    { type:'quantum',   text:'QUANTUM STEP: QFT extracts period r=6 from interference peaks.' },
    { type:'classical', text:'r=6 is even. a^(r/2)=8. GCD(9,21)=3, GCD(7,21)=7.' },
    { type:'result',    text:'21 = 3 × 7 ✓' }
  ]},
  '35': { r:12, steps:[
    { type:'classical', text:'N=35. Choose a=2. GCD(2,35)=1 — proceed.' },
    { type:'quantum',   text:'QUANTUM STEP: Superpose register. f(x)=2ˣ mod 35 for all x simultaneously.' },
    { type:'quantum',   text:'QUANTUM STEP: QFT extracts period r=12.' },
    { type:'classical', text:'r=12 is even. Compute GCDs to find factors.' },
    { type:'result',    text:'35 = 5 × 7 ✓' }
  ]},
  '77': { r:30, steps:[
    { type:'classical', text:'N=77. Choose a=2. GCD(2,77)=1 — proceed.' },
    { type:'quantum',   text:'QUANTUM STEP: Superpose register. f(x)=2ˣ mod 77 for all x simultaneously.' },
    { type:'quantum',   text:'QUANTUM STEP: QFT extracts period r=30 from peaked probability distribution.' },
    { type:'classical', text:'r=30 is even. GCD steps yield prime factors.' },
    { type:'result',    text:'77 = 7 × 11 ✓' }
  ]}
};

function runShor() {
  const N = document.getElementById('shorN').value;
  const d = SHOR_DATA[N] || SHOR_DATA['15'];

  const typeMap = {
    classical: { cls:'shor-classical', icon:'💻' },
    quantum:   { cls:'shor-quantum',   icon:'⚛️' },
    result:    { cls:'shor-result',    icon:'✓' }
  };
  document.getElementById('shorSteps').innerHTML = d.steps.map((s,i) => {
    const t = typeMap[s.type] || typeMap.classical;
    return `<div class="shor-step ${t.cls}"><span class="fw-bold">${t.icon} Step ${i+1}:</span> ${s.text}</div>`;
  }).join('');

  const labels=[], classical=[], quantum=[];
  for (let x=0; x < d.r*4; x++) {
    labels.push(x);
    classical.push(parseFloat((1/(d.r*4)).toFixed(4)));
    quantum.push(x % d.r === 0 ? 0.75 + Math.random()*0.08 : Math.random()*0.03);
  }

  if (shorChartInst) shorChartInst.destroy();
  shorChartInst = new Chart(document.getElementById('shorChart'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label:'Classical (uniform — no period info)',
          data:classical, borderColor:'#64748b', borderWidth:1.5, pointRadius:0, fill:false },
        { label:`Quantum peaks at period r=${d.r} → reveals prime factors`,
          data:quantum, borderColor:'#dc2626', backgroundColor:'rgba(220,53,69,0.1)',
          borderWidth:2, pointRadius:0, fill:true, tension:0.3 }
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{ position:'top' },
        title:{ display:true, text:`QFT output — N=${N}, period r=${d.r}. Peaks expose prime factors.` }
      }
    }
  });
}

// ── GROVER'S ALGORITHM VISUALIZER ────────────────────────────────
function updateGrover() {
  const bits = parseInt(document.getElementById('keySlider').value);
  const half = Math.round(bits/2);
  document.getElementById('keyVal').textContent     = bits + ' bits';
  document.getElementById('gClassical').textContent = `2^${bits}`;
  document.getElementById('gQuantum').textContent   = `2^${half}`;
  document.getElementById('gSpeedup').textContent   = `√(2^${bits})`;

  const labs=[], cls=[], qnt=[];
  for (let b=64; b<=256; b+=16) {
    labs.push(b+'bit'); cls.push(b); qnt.push(Math.round(b/2));
  }

  if (groverChartInst) groverChartInst.destroy();
  groverChartInst = new Chart(document.getElementById('groverChart'), {
    type:'bar',
    data:{
      labels:labs,
      datasets:[
        { label:'Classical security (bits)', data:cls, backgroundColor:'rgba(22,163,74,0.7)', borderColor:'#16a34a', borderWidth:1 },
        { label:"After Grover's attack (bits)", data:qnt, backgroundColor:'rgba(220,38,38,0.7)', borderColor:'#dc2626', borderWidth:1 }
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{ position:'top' }, title:{ display:true, text:"Grover's algorithm halves effective key length — AES-128 → AES-64" } },
      scales:{ y:{ beginAtZero:true, title:{ display:true, text:'Effective security bits' } } }
    }
  });
}

// ── LIVE ATTACK MONITOR ───────────────────────────────────────────
function fetchAttacks() {
  fetch(API+'/api/attacks')
    .then(r=>r.json())
    .then(attacks => {
      const countEl = document.getElementById('attackCount');
      if (countEl) countEl.textContent = attacks.length;
      const logEl = document.getElementById('attackLog');
      if (!logEl) return;
      if (attacks.length === 0) {
        logEl.innerHTML = '<div class="text-muted small p-2">No attacks blocked yet — server is running clean.</div>';
        return;
      }
      logEl.innerHTML = attacks.slice(0,10).map(a =>
        `<div class="d-flex justify-content-between align-items-center border-bottom py-1 small">
          <span class="badge bg-danger me-2">${a.type}</span>
          <span class="text-muted">${a.ip}</span>
          <span class="text-muted">${a.path}</span>
          <span class="text-muted">${new Date(a.time).toLocaleTimeString()}</span>
        </div>`
      ).join('');

      const now = new Date().toLocaleTimeString();
      if (!window.atkLabels) { window.atkLabels=[]; window.atkCounts=[]; }
      if (window.atkLabels.length > 10) { window.atkLabels.shift(); window.atkCounts.shift(); }
      window.atkLabels.push(now); window.atkCounts.push(attacks.length);

      if (attackChartInst) {
        attackChartInst.data.labels = [...window.atkLabels];
        attackChartInst.data.datasets[0].data = [...window.atkCounts];
        attackChartInst.update();
      } else {
        const canvas = document.getElementById('attackChart');
        if (canvas) {
          attackChartInst = new Chart(canvas, {
            type:'line',
            data:{ labels:window.atkLabels, datasets:[{
              label:'Attacks blocked', data:window.atkCounts,
              borderColor:'#dc2626', backgroundColor:'rgba(220,38,38,0.1)', fill:true, tension:0.4
            }]},
            options:{ responsive:true, maintainAspectRatio:false,
              plugins:{ legend:{ display:false } }, scales:{ y:{ beginAtZero:true } }
            }
          });
        }
      }
    })
    .catch(()=>{
      const logEl = document.getElementById('attackLog');
      if (logEl) logEl.innerHTML = '<div class="text-muted small p-2">Java server not running — start run.bat first.</div>';
    });
}

// poll every 5 seconds when on quantum page
setInterval(()=>{
  const qSection = document.getElementById('section-quantum');
  if (qSection && qSection.style.display !== 'none') fetchAttacks();
}, 5000);


// ══════════════════════════════════════════════════════════════════
// REPORT + PDF
// ══════════════════════════════════════════════════════════════════

function renderReport() {
  if (!lastScan || lastScan.error) {
    document.getElementById('noReportData').style.display = 'block';
    document.getElementById('reportPreview').style.display = 'none';
    return;
  }
  document.getElementById('noReportData').style.display  = 'none';
  document.getElementById('reportPreview').style.display = 'block';

  const d = lastScan;
  document.getElementById('rptDate').textContent = 'Generated: ' + new Date().toLocaleString() + ' | QuantumGuard v1.0';

  const g = document.getElementById('rptGrade');
  g.textContent = d.grade; g.className = 'qg-grade-circle-lg grade-' + d.grade;

  document.getElementById('rptSummary').innerHTML = [
    ['Security Score',        d.score + ' / 100'],
    ['Grade',                 d.grade + ' (A=best, F=worst)'],
    ['Language Detected',     d.language],
    ['Lines Scanned',         d.totalLines],
    ['Total Findings',        d.totalFindings],
    ['Sector',                d.sector],
    ['Crypto Agility Score',  d.agilityScore + ' / 10'],
    ['Est. Fix Time',         d.migrationEffort],
    ['SHA-3-256 Hash',        (d.sha3Hash||'').substring(0,40)+'...']
  ].map(([k,v])=>`<tr><td><strong>${k}</strong></td><td>${esc(String(v))}</td></tr>`).join('');

  const ff = d.findings || [];
  document.getElementById('rptFindings').innerHTML = ff.length===0
    ? '<div class="alert alert-success">✅ No vulnerabilities found. Passed all 15 checks.</div>'
    : ff.map((f,i)=>`
      <div class="border rounded p-3 mb-3">
        <div class="d-flex justify-content-between align-items-start mb-2 flex-wrap gap-2">
          <strong>${i+1}. ${esc(f.name)}</strong>
          <div>
            <span class="badge bg-${f.severity==='CRITICAL'?'danger':'warning'} me-1">${f.severity}</span>
            <span class="badge bg-secondary me-1">${f.cveId}</span>
            <span class="badge bg-dark">Line ${f.lineNumber}</span>
          </div>
        </div>
        <code class="d-block bg-light p-2 rounded small mb-2">${esc(f.lineContent)}</code>
        <div class="small mb-1"><strong>🔴 Present risk:</strong> ${esc(f.presentRisk)}</div>
        <div class="small mb-1 qg-quantum-impact"><strong>⚡ Quantum impact:</strong> ${esc(f.quantumImpact)}</div>
        <div class="small mb-1 text-success"><strong>✅ Fix:</strong> ${esc(f.fix)}</div>
        <div class="small text-muted">NIST: ${esc(f.nistRef)} | Est. ${f.fixTimeMinutes} min</div>
      </div>`).join('');
}

function downloadPDF() {
  if (!lastScan || lastScan.error) { alert('No scan data. Run a scan first.'); return; }
  if (!window.jspdf) { alert('PDF library not loaded. Check internet connection.'); return; }

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();
  let y = 20;

  const ln = (txt, sz=10, bold=false, col=[0,0,0]) => {
    doc.setFontSize(sz);
    doc.setFont('helvetica', bold?'bold':'normal');
    doc.setTextColor(...col);
    doc.splitTextToSize(String(txt||''),170).forEach(l=>{
      if(y>280){doc.addPage();y=20;}
      doc.text(l,20,y); y += sz*0.5+2;
    });
    y += 2;
  };

  ln('QuantumGuard Security Report', 18, true, [37,99,235]);
  ln('Quantum-Ready Code Security Analysis', 11, false, [100,100,100]);
  ln('Generated: '+new Date().toLocaleString(), 9, false, [120,120,120]); y+=4;
  ln('India NQM 2027: Critical sector PQC migration required. Budget: Rs 6003 crore.', 9, false, [180,100,0]); y+=4;
  ln('Summary', 13, true);
  [['Score',lastScan.score+'/100'],['Grade',lastScan.grade],['Language',lastScan.language],
   ['Lines',lastScan.totalLines],['Findings',lastScan.totalFindings],['Sector',lastScan.sector],
   ['Crypto Agility',lastScan.agilityScore+'/10'],['Fix Time',lastScan.migrationEffort]
  ].forEach(([k,v])=>ln(k+': '+v,10));
  y+=4;
  ln('Detailed Findings', 13, true);
  (lastScan.findings||[]).forEach((f,i)=>{
    if(y>260){doc.addPage();y=20;}
    ln(`${i+1}. ${f.name} [${f.severity}] — ${f.cveId} — Line ${f.lineNumber}`,10,true,
       f.severity==='CRITICAL'?[200,30,30]:[180,120,0]);
    ln('Present Risk: '+f.presentRisk,9);
    ln('Quantum Impact: '+f.quantumImpact,9,false,[180,100,0]);
    ln('Fix: '+f.fix,9,false,[0,120,0]);
    ln('NIST: '+f.nistRef+' | Est. '+f.fixTimeMinutes+' min',9,false,[100,100,100]);
    y+=2;
  });
  y+=4;
  ln('Standards: NIST FIPS 202, 203, 204 | Tool: QuantumGuard | Rule-based — no AI',8,false,[120,120,120]);
  doc.save('QuantumGuard_Report_'+Date.now()+'.pdf');
}


// ══════════════════════════════════════════════════════════════════
// HELP SECTION — OS TAB SWITCHER
// ══════════════════════════════════════════════════════════════════

function showOS(id, btn) {
  ['win','mac','manual'].forEach(o => {
    const el = document.getElementById('os-'+o);
    if (el) el.style.display = o===id ? 'block' : 'none';
  });
  document.querySelectorAll('#osTabs .nav-link').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
}


// ══════════════════════════════════════════════════════════════════
// DARK MODE
// ══════════════════════════════════════════════════════════════════

function toggleDark() {
  const html = document.documentElement;
  const isDark = html.getAttribute('data-bs-theme') === 'dark';
  html.setAttribute('data-bs-theme', isDark ? 'light' : 'dark');
  localStorage.setItem('qg-theme', isDark ? 'light' : 'dark');
  const btn = document.getElementById('darkToggle');
  if (btn) btn.textContent = isDark ? '🌙' : '☀️';
}

// apply saved theme on page load
(function() {
  const saved = localStorage.getItem('qg-theme');
  if (saved) document.documentElement.setAttribute('data-bs-theme', saved);
})();


// ══════════════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════════════

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

// ══════════════════════════════════════════════════════════════════
// QUANTUM COMPUTING — LIVE BACKEND INTEGRATION
// These functions call the new quantum simulation endpoints:
//   /api/qrng   — Quantum Random Number Generator (Hadamard + Born rule)
//   /api/grover — Grover's algorithm state-vector simulation
//   /api/shor   — Shor's algorithm with QFT amplitude output
// ══════════════════════════════════════════════════════════════════

let qrngChartInst   = null;
let groverSimChart  = null;

// ── QUANTUM RANDOM NUMBER GENERATOR ──────────────────────────────
// Called when user clicks "Generate Quantum Random Number" button
// Calls /api/qrng which runs real Hadamard + Born-rule collapse in Java
function runQRNG() {
  const nBits = parseInt(document.getElementById('qrngBits')?.value || '16');
  const btn   = document.getElementById('qrngBtn');
  const out   = document.getElementById('qrngOutput');
  const spin  = document.getElementById('qrngSpinner');

  if (btn)  { btn.disabled = true; btn.textContent = '⚛️ Collapsing qubits...'; }
  if (spin) spin.style.display = 'inline-block';
  if (out)  out.innerHTML = '<div class="text-muted small">Running quantum circuit on server...</div>';

  fetch(API + '/api/qrng', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ nBits })
  })
  .then(r => r.json())
  .then(d => {
    if (btn)  { btn.disabled = false; btn.textContent = '⚛️ Generate Quantum Random Number'; }
    if (spin) spin.style.display = 'none';
    if (d.error) { if (out) out.innerHTML = `<div class="alert alert-danger">${esc(d.error)}</div>`; return; }
    renderQRNGResult(d);
  })
  .catch(() => {
    if (btn)  { btn.disabled = false; btn.textContent = '⚛️ Generate Quantum Random Number'; }
    if (spin) spin.style.display = 'none';
    // Fallback: run quantum simulation in browser using same algorithm
    if (out) out.innerHTML = '<div class="alert alert-warning small">Java server not running. Using browser-side quantum simulation.</div>';
    renderQRNGResult(browserQRNG(nBits));
  });
}

// Browser-side fallback quantum simulation (same Hadamard + Born-rule logic)
function browserQRNG(nBits) {
  const bits = [];
  const qubitStates = [];
  for (let i = 0; i < nBits; i++) {
    // Hadamard: |0⟩ → (|0⟩+|1⟩)/√2, α=β=1/√2
    const inv = 1 / Math.sqrt(2);
    const prob1 = inv * inv; // = 0.5
    const r = Math.random();
    const measured = r < prob1 ? 1 : 0;
    bits.push(measured);
    qubitStates.push({
      qubitIndex: i,
      alphaRe: inv.toFixed(6), betaRe: inv.toFixed(6),
      prob0: (1 - prob1).toFixed(4), prob1: prob1.toFixed(4),
      measured, randomValue: r.toFixed(6)
    });
  }
  const bitString = bits.join('');
  let numericValue = 0;
  for (let i = 0; i < Math.min(nBits, 52); i++)
    numericValue = (numericValue * 2) + bits[i];
  return {
    nBits, bitString, numericValue,
    hexValue: numericValue.toString(16).toUpperCase(),
    qubitStates,
    circuit: `H⊗${nBits} → Measure (Born rule)`,
    explanation: 'Browser simulation: same Hadamard + Born-rule collapse as server.',
    timestamp: Date.now()
  };
}

function renderQRNGResult(d) {
  const out = document.getElementById('qrngOutput');
  if (!out) return;

  // Build qubit state table (show first 8)
  const show = (d.qubitStates || []).slice(0, 8);
  const rows = show.map(q => `
    <tr>
      <td class="font-monospace small">q${q.qubitIndex}</td>
      <td class="font-monospace small">(${q.alphaRe}, ${q.betaRe}i)</td>
      <td class="text-center">${(parseFloat(q.prob0)*100).toFixed(1)}%</td>
      <td class="text-center">${(parseFloat(q.prob1)*100).toFixed(1)}%</td>
      <td class="font-monospace small">${q.randomValue}</td>
      <td class="text-center fw-bold ${q.measured===1?'text-danger':'text-success'}">|${q.measured}⟩</td>
    </tr>`).join('');

  out.innerHTML = `
    <div class="row g-3 mb-3">
      <div class="col-md-4">
        <div class="qg-metric">
          <div class="small text-muted mb-1">Quantum Bits Generated</div>
          <div class="qg-big-num text-primary">${d.nBits}</div>
          <div class="small text-muted">qubits measured</div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="qg-metric">
          <div class="small text-muted mb-1">Numeric Value</div>
          <div class="fw-bold fs-5 text-success font-monospace">${d.numericValue}</div>
          <div class="small text-muted font-monospace">0x${d.hexValue}</div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="qg-metric">
          <div class="small text-muted mb-1">Circuit</div>
          <div class="small fw-bold font-monospace text-primary">${esc(d.circuit)}</div>
          <div class="small text-muted mt-1">Born rule collapse</div>
        </div>
      </div>
    </div>

    <div class="card p-3 mb-3" style="background:#f8fafc">
      <div class="small fw-bold mb-2 text-primary">⚛️ Raw Bit String (${d.nBits} quantum measurements)</div>
      <code class="small d-block" style="word-break:break-all;letter-spacing:1px">${d.bitString}</code>
    </div>

    ${d.sha3Hash ? `
    <div class="qg-hash-alert mb-3">
      <strong>🔒 SHA-3-256 of quantum output</strong>
      <span class="badge bg-success ms-2">Quantum-safe ✓</span><br>
      <code class="small">${d.sha3Hash}</code><br>
      <span class="text-muted small">Quantum randomness → SHA-3 → cryptographically secure key material</span>
    </div>` : ''}

    <div class="card p-3 mb-3">
      <div class="small fw-bold mb-2">Qubit State Details (first 8 of ${d.nBits})</div>
      <div class="table-responsive">
        <table class="table table-sm table-bordered small mb-0">
          <thead class="table-dark">
            <tr>
              <th>Qubit</th>
              <th>Amplitude α,β (after H gate)</th>
              <th>P(|0⟩)</th>
              <th>P(|1⟩)</th>
              <th>Random r</th>
              <th>Collapsed to</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div class="small text-muted mt-2">
        Each qubit: |0⟩ → <strong>H gate</strong> → (|0⟩+|1⟩)/√2 → <strong>Measure</strong> → collapses via Born rule: P(|1⟩) = |β|² = 0.5
      </div>
    </div>

    <div class="simple-note small">
      <strong>Why is this quantum?</strong> ${esc(d.explanation || '')}
    </div>`;

  // Draw probability chart
  const canvas = document.getElementById('qrngChart');
  if (canvas) {
    if (qrngChartInst) qrngChartInst.destroy();
    const labels = (d.qubitStates || []).map(q => 'q' + q.qubitIndex);
    const zeros  = (d.qubitStates || []).map(q => parseFloat(q.prob0));
    const ones   = (d.qubitStates || []).map(q => parseFloat(q.prob1));
    const meas   = (d.qubitStates || []).map(q => q.measured);
    qrngChartInst = new Chart(canvas, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'P(|0⟩) before measurement', data: zeros, backgroundColor: 'rgba(22,163,74,0.5)', borderColor: '#16a34a', borderWidth: 1 },
          { label: 'P(|1⟩) before measurement', data: ones,  backgroundColor: 'rgba(220,38,38,0.5)', borderColor: '#dc2626', borderWidth: 1 },
        ]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'top' },
          title: { display: true, text: 'Superposition probabilities before measurement — each qubit is truly 50/50' }
        },
        scales: { y: { beginAtZero: true, max: 1, title: { display: true, text: 'Probability' } } }
      }
    });
  }
}

// ── GROVER LIVE SIMULATION ────────────────────────────────────────
// Called from the new "Run Live Grover Simulation" button
function runGroverSim() {
  const nQubits = parseInt(document.getElementById('groverSimQubits')?.value || '3');
  const target  = parseInt(document.getElementById('groverSimTarget')?.value || '5');
  const btn     = document.getElementById('groverSimBtn');
  const out     = document.getElementById('groverSimOutput');

  if (btn) { btn.disabled = true; btn.textContent = '⚛️ Running quantum simulation...'; }
  if (out) out.innerHTML = '<div class="text-muted small">Simulating Grover state vector...</div>';

  fetch(API + '/api/grover', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ nQubits, targetIndex: target })
  })
  .then(r => r.json())
  .then(d => {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Run Live Grover Simulation'; }
    if (d.error) { if (out) out.innerHTML = `<div class="alert alert-danger">${esc(d.error)}</div>`; return; }
    renderGroverSim(d);
  })
  .catch(() => {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Run Live Grover Simulation'; }
    if (out) out.innerHTML = '<div class="alert alert-warning small">Server not running. Start run.bat first.</div>';
  });
}

function renderGroverSim(d) {
  const out = document.getElementById('groverSimOutput');
  if (!out) return;

  const stepTypeIcon = { classical:'💻', quantum:'⚛️', result:'✓' };

  out.innerHTML = `
    <div class="row g-3 mb-3">
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-primary">${d.N}</div>
        <div class="small text-muted">Search space (2^${d.nQubits})</div>
      </div></div>
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-danger">${d.classicalSteps}</div>
        <div class="small text-muted">Classical avg. steps</div>
      </div></div>
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-success">${d.optimalIterations}</div>
        <div class="small text-muted">Grover iterations</div>
      </div></div>
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-warning">${d.speedup}</div>
        <div class="small text-muted">Quantum speedup</div>
      </div></div>
    </div>
    <div class="alert alert-${d.success ? 'success' : 'warning'} small mb-3">
      ${d.success ? '✅' : '⚠️'} Target index ${d.targetIndex} ${d.success ? 'FOUND' : 'MISSED'} at index ${d.foundIndex}. 
      Final probability: ${(parseFloat(d.targetProbability)*100).toFixed(1)}%
    </div>
    <div class="simple-note small mb-3">${esc(d.explanation)}</div>
    <div style="position:relative;height:220px"><canvas id="groverSimChart"></canvas></div>`;

  // Draw the final probability distribution
  setTimeout(() => {
    const canvas = document.getElementById('groverSimChart');
    if (!canvas) return;
    if (groverSimChart) groverSimChart.destroy();
    const lastIter = d.iterations[d.iterations.length - 1];
    const probs = lastIter ? lastIter.probabilities : [];
    const labels = probs.map((_, i) => i === d.targetIndex ? `★${i}` : String(i));
    const colors = probs.map((_, i) => i === d.targetIndex ? '#dc2626' : '#2563eb');
    groverSimChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: `Probability after ${d.optimalIterations} Grover iterations`,
          data: probs,
          backgroundColor: colors,
          borderWidth: 0
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: {
          legend: { position: 'top' },
          title: { display: true, text: `Target state ★${d.targetIndex} has max amplitude — Grover amplification worked` }
        },
        scales: { y: { beginAtZero: true, title: { display: true, text: 'Probability' } } }
      }
    });
  }, 50);
}

// ── SHOR LIVE SIMULATION ─────────────────────────────────────────
function runShorSim() {
  const N   = parseInt(document.getElementById('shorN').value || '15');
  const btn = document.getElementById('shorSimBtn');
  const out = document.getElementById('shorSimOutput');

  if (btn) { btn.disabled = true; btn.textContent = '⚛️ Running Shor simulation...'; }
  if (out) out.innerHTML = '<div class="text-muted small">Running quantum period-finding circuit...</div>';

  fetch(API + '/api/shor', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ N })
  })
  .then(r => r.json())
  .then(d => {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Run Shor Simulation (Backend)'; }
    if (d.error) { if (out) out.innerHTML = `<div class="alert alert-danger">${esc(d.error)}</div>`; return; }
    renderShorSim(d, out);
  })
  .catch(() => {
    if (btn) { btn.disabled = false; btn.textContent = '▶ Run Shor Simulation (Backend)'; }
    if (out) out.innerHTML = '<div class="alert alert-warning small">Server not running. Use the visualiser above.</div>';
  });
}

function renderShorSim(d, out) {
  if (!out) return;
  const typeMap = { classical:'shor-classical', quantum:'shor-quantum', result:'shor-result' };
  const iconMap = { classical:'💻', quantum:'⚛️', result:'✅' };
  const stepsHtml = (d.steps || []).map((s,i) =>
    `<div class="shor-step ${typeMap[s.type]||'shor-classical'}">
      <span class="fw-bold">${iconMap[s.type]||'💻'} ${esc(s.title)}</span><br>
      <span class="small">${esc(s.detail)}</span>
    </div>`).join('');

  out.innerHTML = `
    <div class="row g-3 mb-3">
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-danger">${d.N}</div><div class="small text-muted">N to factor</div>
      </div></div>
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-primary">${d.period}</div><div class="small text-muted">Period r (QFT output)</div>
      </div></div>
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-success">${d.factor1}</div><div class="small text-muted">Factor 1</div>
      </div></div>
      <div class="col-sm-3"><div class="qg-metric">
        <div class="qg-big-num text-success">${d.factor2}</div><div class="small text-muted">Factor 2</div>
      </div></div>
    </div>
    <div class="alert alert-${d.verified?'success':'warning'} small mb-3">
      ${d.verified?'✅':'⚠️'} <strong>${d.N} = ${d.factor1} × ${d.factor2}</strong>
      ${d.verified ? '— Verified! RSA key broken.' : '— Retry with different a.'}
    </div>
    <div class="mb-3">${stepsHtml}</div>
    <div class="simple-note small">${esc(d.explanation)}</div>`;
}