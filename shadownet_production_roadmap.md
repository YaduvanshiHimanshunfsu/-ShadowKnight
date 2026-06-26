# ShadowNet Nexus — Complete Production Roadmap

> Date: 27 June 2026
> Version: v4.0 → v5.0 Production Plan
> Classification: Internal — Do Not Share

---

## Table of Contents

1. [Current State Assessment](#1-current-state-assessment)
2. [Phase 1 — Foundation Repair (Week 1-4)](#2-phase-1--foundation-repair-week-1-4)
3. [Phase 2 — Accuracy Upgrade (Month 2-4)](#3-phase-2--accuracy-upgrade-month-2-4)
4. [Phase 3 — Advanced Web Dashboard & Security (Month 4-6)](#4-phase-3--advanced-web-dashboard--security-month-4-6)
5. [Phase 4 — Distributed Architecture (Month 6-10)](#5-phase-4--distributed-architecture-month-6-10)
6. [Phase 5 — Government & Enterprise Grade (Month 10-16)](#6-phase-5--government--enterprise-grade-month-10-16)
7. [Production-Level Problems You Will Face](#7-production-level-problems-you-will-face)
8. [Competitor Comparison](#8-competitor-comparison)
9. [Legal & Compliance Path](#9-legal--compliance-path)
10. [i4C Presentation Strategy](#10-i4c-presentation-strategy)
11. [Team & Resource Requirements](#11-team--resource-requirements)
12. [Risk Matrix](#12-risk-matrix)

---

## 1. Current State Assessment

### What ShadowNet Is Today

ShadowNet Nexus is a **research prototype** (proof-of-concept) for real-time anti-forensics detection. It does three things well at concept level:

- Detects process creation via WMI events on Windows
- Captures evidence snapshots in parallel threads (<100ms target)
- Sends commands to Gemini AI for threat classification

### What ShadowNet Is NOT Today

- It is NOT production-ready
- It is NOT legally compliant for Indian courts
- It is NOT deployable on enterprise networks
- It is NOT accurate enough for real-world detection

### Full Bug List (Found in Code Review)

| # | Bug | File | Severity | Status |
|---|-----|------|----------|--------|
| 1 | API key committed to git | `.env` | CRITICAL | Must fix now |
| 2 | Config key mismatch (`ai_weight` vs `ai_confidence_weight`) | `shadownet_realtime.py` L76 vs `config.yaml` L70 | HIGH | Config ignored |
| 3 | Prompt template uses `{{ }}` — `.format()` never substitutes values | `enhanced_prompts.py` L11-17 | CRITICAL | All AI calls broken |
| 4 | SI vs FN comparison is copy of same data | `ntfs_timeline_engine.py` L45 | HIGH | Timestomping detection useless |
| 5 | Double `break` — only scans 1 file | `shadownet_realtime.py` L186-207 | MEDIUM | Disk analysis unreliable |
| 6 | Duplicate print line | `model_selector.py` L93-95 | LOW | Cosmetic |
| 7 | `disk_score` can exceed 100 (unbounded accumulation) | `shadownet_realtime.py` L201-204 | MEDIUM | Scoring overflow |
| 8 | Bare `except:` hides all errors including SystemExit | Multiple files | MEDIUM | Masks real bugs |
| 9 | `recent_commands` dict never pruned | `shadownet_realtime.py` L114 | MEDIUM | Memory leak |
| 10 | Thread-unsafe counter increments | `shadownet_realtime.py` L112-113 | LOW | Race condition |
| 11 | Missing `task_done()` for queue sentinel | `shadownet_realtime.py` L138-141 | LOW | Latent join bug |
| 12 | `ntfs_artifact_parser.py` is 0 bytes | `core/ntfs_artifact_parser.py` | HIGH | Empty placeholder |
| 13 | README typo "Nexsus" | `README.md` L1076 | LOW | Documentation |
| 14 | CEF vendor says "Anthropic" | `README.md` L970 | LOW | Wrong branding |
| 15 | Factory function named like class (PascalCase) | `process_monitor.py` L340 | LOW | Misleading API |
| 16 | Entropy threshold mismatch (7.5 in config vs 7.8 in engine default) | `entropy_engine.py` L23 vs `config.yaml` L58 | MEDIUM | Inconsistent detection |

### False Claims in Documentation

These features are described in README but NOT actually implemented:

| Claimed Feature | Actual State | Risk |
|----------------|-------------|------|
| K-S (Kolmogorov-Smirnov) test | Not implemented. Only Shannon entropy exists | Credibility loss |
| Chi-Squared test | Not implemented | Credibility loss |
| Monte Carlo Pi test | Not implemented | Credibility loss |
| GMM keystroke detection | Not implemented. Uses simple threshold | Credibility loss |
| RFC 3161 trusted timestamping | Library in requirements but never called | Legal compliance gap |
| Raw NTFS $FILE_NAME parsing | Uses `os.stat()` only (SI layer) | Forensic detection gap |
| E01/AFF4 export | Not implemented | Format compatibility gap |

---

## 2. Phase 1 — Foundation Repair (Week 1-4)

> Goal: Close the gap between what code claims and what code actually does.

### Step 1.1 — Fix Critical Code Bugs

**Task**: Fix the 3 show-stopper bugs that break core functionality.

| What | How | Time |
|------|-----|------|
| Fix prompt template `{{ }}` | Change `{{command_line}}` to `{command_line}` in `enhanced_prompts.py`. Keep `{{ }}` only in the JSON example block where you want literal braces | 30 minutes |
| Fix config key mismatch | Change `ai_weight` to `ai_confidence_weight` in `shadownet_realtime.py` L76 | 5 minutes |
| Remove API key from git | Run `git rm --cached .env`, rotate the key in Google Cloud Console, add `.env` to `.gitignore` (already there but file was tracked before) | 15 minutes |

**Pros**:
- Immediately makes AI analysis functional (it is currently 100% broken)
- Zero risk, pure bug fix
- Takes under 1 hour total

**Cons**:
- None. These must be fixed regardless of anything else.

---

### Step 1.2 — Implement Statistical Entropy Tests

**Task**: Add K-S, Chi-Squared tests to entropy validation using `scipy.stats` (already in your requirements).

**How it works**:
- K-S test compares byte distribution of a file block against uniform distribution (truly random data is uniform)
- Chi-Squared test checks if observed byte frequencies match expected frequencies
- Both return a p-value. Low p-value (< 0.05) means data is NOT random (structured). High p-value means data looks random (encrypted/wiped)

**Implementation** (add to `entropy_engine.py`):

```python
from scipy.stats import kstest, chisquare
import numpy as np

def ks_test_entropy(self, data: bytes) -> dict:
    """Kolmogorov-Smirnov test against uniform distribution"""
    byte_values = np.array(list(data), dtype=float) / 255.0
    stat, p_value = kstest(byte_values, 'uniform')
    return {
        "test": "kolmogorov_smirnov",
        "statistic": round(stat, 6),
        "p_value": round(p_value, 6),
        "is_random": p_value > 0.05
    }

def chi_squared_test(self, data: bytes) -> dict:
    """Chi-squared goodness-of-fit test"""
    observed = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = np.full(256, len(data) / 256.0)
    stat, p_value = chisquare(observed, expected)
    return {
        "test": "chi_squared",
        "statistic": round(stat, 4),
        "p_value": round(p_value, 6),
        "is_random": p_value > 0.05
    }
```

**Pros**:
- scipy is already listed in your requirements — no new dependency
- Each function is ~10 lines of code
- Gives you 3 statistical validation layers (Shannon + K-S + Chi-Sq)
- Makes your entropy claims truthful

**Cons**:
- With very large files, scipy statistical tests can produce misleading p-values (sample size effect)
- K-S test is only valid for continuous distributions — need to normalize byte values to [0, 1] range first

**Time**: 2-3 hours including tests

---

### Step 1.3 — Implement GMM Keystroke Detection

**Task**: Replace simple threshold-based bot detection with actual Gaussian Mixture Model using `scikit-learn` (already in requirements).

**How it works**:
- GMM fits two clusters: human-like timing (high variance, 80-280ms) and bot-like timing (low variance, <10ms)
- After fitting, you classify new keystroke sequences by which cluster they belong to
- Much more accurate than a simple if-else threshold

**Implementation** (add to `gemini_behavior_analyzer.py` or separate module):

```python
from sklearn.mixture import GaussianMixture
import numpy as np

class KeystrokeGMM:
    def __init__(self):
        self.model = GaussianMixture(n_components=2, random_state=42)
        self._train_default_model()
    
    def _train_default_model(self):
        """Pre-train with synthetic human + bot data"""
        human = np.random.normal(loc=150, scale=50, size=500).reshape(-1, 1)
        bot = np.random.normal(loc=10, scale=2, size=500).reshape(-1, 1)
        training_data = np.vstack([human, bot])
        self.model.fit(training_data)
        
        # Identify which component is "human" (higher mean)
        means = self.model.means_.flatten()
        self.human_component = int(np.argmax(means))
    
    def classify(self, timings: list) -> dict:
        """Classify a keystroke timing sequence"""
        X = np.array(timings).reshape(-1, 1)
        labels = self.model.predict(X)
        human_ratio = np.mean(labels == self.human_component)
        
        return {
            "is_human": human_ratio > 0.6,
            "human_ratio": round(float(human_ratio), 3),
            "confidence": round(float(max(human_ratio, 1 - human_ratio)), 3),
            "method": "gaussian_mixture_model"
        }
```

**Pros**:
- scikit-learn already in requirements
- Statistically much stronger than threshold check
- Self-adapting — can be retrained on real data later
- Makes your GMM claim truthful

**Cons**:
- Default model uses synthetic data. Real-world accuracy depends on calibration with actual human/bot data
- GMM assumes normal distribution of timing intervals — may not perfectly model all human typing patterns
- Need to handle edge case: very short sequences (< 5 keystrokes) produce unreliable classification

**Time**: 3-4 hours including tests

---

### Step 1.4 — Activate RFC 3161 Timestamping

**Task**: Use `rfc3161ng` library (already in requirements) to get cryptographic timestamps from an external Timestamp Authority (TSA).

**How it works**:
- You hash the evidence file (SHA-256)
- Send hash to a public TSA server (like Sectigo or Certum — free)
- TSA returns a signed timestamp token (TST)
- TST proves the evidence existed at that exact time — independently verifiable
- This is legally required for BSA Section 63(4)(c) compliance

**Implementation** (add to `evidence_vault.py`):

```python
import rfc3161ng
import hashlib

TSA_URL = "http://time.certum.pl"  # Free public TSA

def get_trusted_timestamp(self, evidence_path: str) -> dict:
    """Get RFC 3161 trusted timestamp for evidence file"""
    try:
        rt = rfc3161ng.RemoteTimestamper(TSA_URL)
        
        with open(evidence_path, 'rb') as f:
            data = f.read()
        
        tst = rt.timestamp(data=data)
        
        # Save timestamp token alongside evidence
        tst_path = evidence_path + '.tst'
        with open(tst_path, 'wb') as f:
            f.write(tst)
        
        return {
            "status": "success",
            "tsa_url": TSA_URL,
            "tst_file": tst_path,
            "evidence_hash": hashlib.sha256(data).hexdigest()
        }
    except Exception as e:
        return {"status": "failed", "error": str(e)}
```

> Note: `rfc3161ng` has not been actively maintained. Consider `tsp-client` or `rfc3161-client` as modern alternatives.

**Pros**:
- Makes your evidence legally admissible (independent third-party proof of time)
- Free TSA servers available (Certum, DigiCert)
- ~20 lines of code
- Directly maps to BSA Section 63(4)(c) requirement

**Cons**:
- Requires internet connection to reach TSA server. Will fail in air-gapped/offline environments
- Free TSA servers have rate limits. Under heavy incident volume (50+ incidents/minute), timestamps may fail
- TSA server availability is outside your control — if Certum goes down, timestamping stops
- For Indian courts, the TSA's legal standing may be questioned. Indian government may prefer NIC (National Informatics Centre) as TSA

**Time**: 2-3 hours including tests

---

### Step 1.5 — Fix Weighted Scoring Formula

**Task**: Add AI confidence override so high-confidence AI detections are not downgraded by low NTFS/disk scores.

**Current problem**: If Gemini says 99% confidence this is anti-forensics, but NTFS score = 0 and disk score = 0, the weighted score is only 39.6 (below HIGH threshold). A 99% confident detection gets classified as MEDIUM. This is wrong.

**Fix**:

```python
def compute_weighted_score(ai_conf, ntfs_score, disk_score):
    ai_component = ai_conf * ai_weight
    ntfs_component = (ntfs_score / 100) * ntfs_weight
    disk_component = (min(disk_score, 100) / 100) * disk_weight  # cap at 100
    
    weighted = ai_component + ntfs_component + disk_component
    
    # AI Override: if AI is very confident, don't let low disk/NTFS drag it down
    if ai_conf >= 0.90:
        weighted = max(weighted, 70)  # minimum HIGH
    elif ai_conf >= 0.80:
        weighted = max(weighted, 50)  # minimum MEDIUM
    
    return min(weighted, 100)
```

**Pros**:
- Prevents false negatives on obvious attacks (like `wevtutil cl Security`)
- Simple, understandable logic
- Disk score overflow bug also fixed (capped at 100)

**Cons**:
- AI override means a single AI hallucination could force a false HIGH alert
- Need to tune the override thresholds (0.90, 0.80) with real test data
- If Gemini API is down, `ai_conf` defaults to 0, which means the whole scoring depends on NTFS + disk only (may need a separate fallback path)

**Time**: 1 hour

---

### Step 1.6 — Write the Test Suite

**Task**: Create a structured test set that measures your tool's accuracy with real numbers.

**What you need**:

| Test Category | Count | Purpose |
|---------------|-------|---------|
| Benign commands (must NOT trigger) | 50 | Measure false positive rate |
| Anti-forensic commands (must trigger CRITICAL/HIGH) | 50 | Measure true positive rate |
| Obfuscated commands (Base64, concatenated) | 20 | Test decoder accuracy |
| Edge cases (partial matches, typos, admin tools) | 20 | Test robustness |

**Minimum acceptable performance for production**:
- False positive rate < 5% (< 2.5 out of 50 benign commands trigger)
- True positive rate > 95% (> 47.5 out of 50 anti-forensic commands detected)
- Obfuscation detection > 80% (> 16 out of 20 decoded correctly)

**Pros**:
- No government body, no enterprise, no investor will accept a tool without measured FP/FN rates
- Gives you real numbers for your i4C presentation
- Helps you find edge cases before a live demo breaks

**Cons**:
- Requires running 140+ test cases through Gemini API — costs money and time
- Real-world FP/FN rates may be worse than test rates (test commands are synthetic)
- Need to run tests periodically as Gemini model updates (a test that passes today may fail next month)

**Time**: 1 week for test creation + first run

---

### Phase 1 Summary

| Item | Time | Risk | Must Do? |
|------|------|------|----------|
| Fix critical bugs (prompt, config, API key) | 1 hour | None | YES — non-negotiable |
| Statistical entropy tests | 3 hours | Low | YES — removes false claim |
| GMM keystroke detection | 4 hours | Low | YES — removes false claim |
| RFC 3161 timestamping | 3 hours | Low | YES — legal compliance |
| Fix weighted scoring | 1 hour | Low | YES — detection accuracy |
| Test suite | 1 week | Medium | YES — credibility |

**Total Phase 1 time: 2-4 weeks**

---

## 3. Phase 2 — Accuracy Upgrade (Month 2-4)

### Step 2.1 — Implement Real NTFS MFT Parsing

**Task**: Replace the fake `fn = si.copy()` with actual $FILE_NAME attribute parsing from the MFT.

**Options**:

| Approach | Library | Difficulty | Accuracy |
|----------|---------|------------|----------|
| Option A: Use `analyzeMFT` | `analyzeMFT` (pip) | Medium | High — extracts both SI and FN timestamps |
| Option B: Use `python-ntfs` | `python-ntfs` (pip) | Hard | Very high — raw attribute-level access |
| Option C: Shell out to `MFTECmd.exe` | Eric Zimmerman tools | Easy | Very high — industry standard parser |
| Option D: Use `fsutil` + `ctypes` | Built-in Windows API | Very hard | Medium — limited to USN journal, not full MFT |

**Recommendation**: Start with Option A (`analyzeMFT`). It is a Python library, can parse a raw `$MFT` file, and gives you both SI and FN timestamps in structured output. Use Option C (`MFTECmd.exe`) as a validation cross-check.

**Challenge**: Extracting the raw `$MFT` file requires admin privileges and either:
- `rawcopy.exe` (copies locked system files)
- `FTK Imager` command-line extraction
- Direct disk read via `\\.\C:` device handle with `ctypes`

**Pros**:
- Real SI vs FN comparison is the gold standard for timestomping detection
- `analyzeMFT` is open-source and well-tested by the forensics community
- Makes your NTFS claims truthful

**Cons**:
- Requires admin/SYSTEM privileges to read `$MFT` (locked by Windows)
- Parsing full MFT of a Windows system (500K-2M entries) takes 30-60 seconds — too slow for real-time
- On non-NTFS filesystems (Linux ext4, Mac APFS), this is irrelevant
- MFT format varies slightly between Windows versions (7, 10, 11, Server)

**Time**: 2-3 weeks

---

### Step 2.2 — Behavioral Chain Detection

**Task**: Instead of analyzing each command in isolation, detect attack sequences.

**How it works**: Track commands per user in a sliding time window. Define attack chain patterns:

```
Pattern: Ransomware Preparation
  Step 1: vssadmin delete shadows
  Step 2: wevtutil cl Security
  Step 3: bcdedit /set {default} recoveryenabled No
  Window: Any 2 of these within 10 minutes = CRITICAL chain
```

```
Pattern: Credential Theft
  Step 1: whoami /priv
  Step 2: mimikatz OR procdump targeting lsass.exe
  Step 3: reg save HKLM\SAM
  Window: Any 2 of these within 15 minutes = CRITICAL chain
```

**Implementation approach**:
- Maintain a per-user `deque` of recent commands (last 30 minutes)
- After each new detection, scan the deque against predefined chain patterns
- Chain match = multiply the individual command score by chain_multiplier (1.5x-2x)
- Also send the full chain context to Gemini for narrative analysis

**Pros**:
- Massive accuracy improvement. Individual commands have high false positive rates. Attack chains have very low false positive rates
- Provides "attack story" context — much more useful for investigators
- Maps directly to MITRE ATT&CK kill chain stages

**Cons**:
- Defining chain patterns requires deep security knowledge
- Time window selection is tricky. Too short = miss slow attacks. Too long = false correlations
- Attacker who knows the chain patterns can intentionally add benign commands between malicious ones to break the chain
- Memory usage grows with user count and time window length

**Time**: 2-3 weeks

---

### Step 2.3 — ADS (Alternate Data Streams) Detection

**Task**: Detect files hiding data in NTFS Alternate Data Streams.

**What this is**: NTFS allows files to have hidden "streams" that don't show up in Explorer or `dir`. Attackers use ADS to hide malware, stolen data, or tools.

**Implementation** (can use Windows `dir /R` or Python `ctypes`):

```python
import subprocess

def detect_ads(path: str) -> list:
    """Detect Alternate Data Streams in files"""
    result = subprocess.run(
        ["cmd", "/c", f"dir /R \"{path}\""],
        capture_output=True, text=True
    )
    streams = []
    for line in result.stdout.split('\n'):
        if ':$DATA' in line and not line.strip().endswith(':$DATA'):
            streams.append(line.strip())
    return streams
```

**Pros**:
- ADS detection is a fundamental forensic capability. Not having it is a gap
- Windows provides built-in support via `dir /R`
- Very fast to scan

**Cons**:
- Windows-only. No equivalent on Linux/Mac
- Some legitimate software uses ADS (Zone.Identifier for download tracking)
- Need to distinguish malicious ADS from legitimate ones — requires whitelist

**Time**: 1 week

---

### Step 2.4 — Prefetch File Analysis

**Task**: Parse Windows Prefetch files to detect evidence of program execution even after the program is deleted.

**Why this matters**: Even if an attacker deletes `mimikatz.exe`, the Prefetch file `C:\Windows\Prefetch\MIMIKATZ.EXE-XXXXX.pf` still proves it was run. This is critical forensic evidence.

**Libraries**: `windowsprefetch` (pip) or manual binary parsing.

**Pros**:
- Proves program execution even after deletion — extremely valuable
- Prefetch files contain: executable name, run count, last run time, DLLs loaded
- Indian cybercrime cases frequently involve proving tool execution

**Cons**:
- Prefetch is disabled on SSDs by default in Windows 10+ (SuperFetch handles it)
- Requires admin access to read Prefetch directory
- Windows-only feature

**Time**: 1-2 weeks

---

### Phase 2 Summary

| Item | Time | Risk | Impact |
|------|------|------|--------|
| Real NTFS MFT parsing | 2-3 weeks | Medium | Timestamps detection actually works |
| Behavioral chain detection | 2-3 weeks | Medium | Major FP reduction |
| ADS detection | 1 week | Low | New forensic capability |
| Prefetch analysis | 1-2 weeks | Low | Execution proof even after deletion |

**Total Phase 2 time: 2-3 months**

---

## 4. Phase 3 — Advanced Web Dashboard & Security (Month 4-6)

### Step 3.1 — Database (Replace JSON Files)

**Current state**: All evidence stored as flat JSON files. No search, no query, no correlation.

**Recommendation**: Use **SQLite** for single-machine deployment, **PostgreSQL** for multi-endpoint.

**Schema design**:

```sql
-- Core tables
CREATE TABLE incidents (
    id TEXT PRIMARY KEY,
    timestamp DATETIME,
    severity TEXT,
    command TEXT,
    process_name TEXT,
    user TEXT,
    ai_confidence REAL,
    weighted_score REAL,
    mitre_ttps TEXT,      -- JSON array
    status TEXT DEFAULT 'open'
);

CREATE TABLE evidence (
    id TEXT PRIMARY KEY,
    incident_id TEXT REFERENCES incidents(id),
    type TEXT,             -- 'snapshot', 'log', 'artifact'
    file_path TEXT,
    sha256_hash TEXT,
    rfc3161_token BLOB,
    collected_at DATETIME
);

CREATE TABLE attack_chains (
    id TEXT PRIMARY KEY,
    user TEXT,
    commands TEXT,          -- JSON array
    pattern_name TEXT,
    start_time DATETIME,
    end_time DATETIME,
    chain_score REAL
);
```

**Pros**:
- Can search by date, user, TTP, severity
- Can correlate across incidents
- SQLite is zero-dependency (built into Python)
- Can export query results for NCRP case filing

**Cons**:
- Migration from JSON to DB requires data conversion script
- SQLite has concurrency limits (one writer at a time) — may bottleneck under heavy load
- PostgreSQL adds deployment complexity (separate server process)
- Need to backup the database separately from evidence files

**Time**: 2-3 weeks

---

### Step 3.2 — Decoupled REST API (FastAPI Backend)

**Task**: Expose ShadowKnight's SQLite database via a high-performance REST API with advanced enterprise-grade security.
**CRITICAL RULE**: The API must run as a separate process in parallel. The core forensic engine (`shadow_knight_realtime.py`) should NEVER serve web requests. The engine only writes to the DB; the API only reads from the DB.

```
GET  /api/incidents              — List all incidents (paginated)
GET  /api/incidents/{id}         — Get incident deep-dive (MFT, Prefetch, Chain)
GET  /api/incidents/{id}/evidence — Get RFC 3161 evidence tokens
POST /api/search                 — Search by MITRE TTP, date, user
GET  /api/stats                  — Heatmap & Dashboard statistics
```

**Advanced Web & Network Security Model**:
- **Authentication**: JWT (JSON Web Tokens) with short 15-minute expiration and HTTP-only refresh tokens.
- **Network Security**: Mutual TLS (mTLS) enforcement. The API will refuse connection to any client that doesn't hold a cryptographic client certificate.
- **WAF (Web Application Firewall)**: Rate-limiting per IP (max 100 req/min) to prevent brute-force attacks on the SOC dashboard.
- **Data Protection**: AES-256 encryption for the SQLite database at rest.

**Pros**:
- Core engine remains 100% stable and fast (completely decoupled).
- Impossible for a web vulnerability to crash the core monitoring engine.
- Bank-level network security protects the highly sensitive forensic evidence.

**Cons**:
- Requires managing an internal CA (Certificate Authority) for mTLS.
- Requires configuring HTTPS/TLS for local and production deployment.

**Time**: 2-3 weeks


### Step 3.3 — Advanced Web Dashboard (React + Tailwind CSS)

**Task**: Build a "perfect", visually stunning, and highly responsive SOC (Security Operations Center) dashboard. It must look and feel like a multi-million dollar enterprise security product.

**Architecture**:
- **Frontend Framework**: React (Next.js) for component-based, blazing-fast rendering.
- **Styling**: Tailwind CSS for modern, pixel-perfect, dark-mode/glass-morphic aesthetics.
- **Data Fetching**: Axios/React Query polling the FastAPI backend (Step 3.2).
- **Visualization**: Recharts or D3.js for drawing MITRE attack chains and severity heatmaps.

**Key Views**:
- **Live SOC Heatmap**: A dark-themed global or network map showing where anomalies are spiking in real-time.
- **MITRE Attack Chain Visualizer**: Instead of a text log, display nodes connecting "Reconnaissance" -> "Execution" -> "Evasion".
- **One-Click Forensics**: A dedicated panel for law enforcement to click "Generate NCRP Report" which automatically bundles the RFC 3161 timestamps, MFT analysis, and Prefetch evidence into a legal PDF.

**Pros**:
- **Absolute Perfection**: This is the "Wow" factor. i4C and enterprise buyers evaluate tools heavily on UI/UX.
- Zero risk to the core engine. If the React UI crashes, ShadowKnight keeps protecting the system in the background.
- State police cyber cell officers can use it without needing to understand the command line.

**Cons**:
- Advanced web development (React + Tailwind + WebSockets) is a completely different skill set from kernel/forensic Python development.
- Maintaining a "perfect" UI requires constant design tweaks and responsive layout management for different screen sizes.

**Time**: 4-6 weeks

---

## 5. Phase 4 — Distributed Architecture (Month 6-10)

### Step 4.1 — Multi-Endpoint Agent Architecture

**Task**: Separate the detection engine (runs on each machine) from the central server (collects and correlates).

```
[Agent on Machine A] ─┐
[Agent on Machine B] ──┼──→ [Central Server] → [Database] → [Dashboard]
[Agent on Machine C] ─┘          ↓
                         [Correlation Engine]
                         [Alert Dispatch]
```

**Agent responsibilities**:
- Process monitoring (WMI/polling)
- Evidence snapshot capture
- Local threat keyword matching
- Send findings to central server via API

**Central server responsibilities**:
- Receive findings from all agents
- Run Gemini AI analysis (centralized to save API costs)
- Cross-endpoint correlation (same user attacking from multiple machines)
- Dashboard, alerts, reports

**Pros**:
- Enterprise-ready architecture. SOC can monitor 100+ machines
- Centralized AI reduces API costs (one Gemini call per incident, not per endpoint)
- Cross-machine correlation catches lateral movement attacks

**Cons**:
- Major architectural change. Requires splitting current monolithic code
- Agent needs to be lightweight (low CPU/memory) to not impact production servers
- Network reliability becomes critical. If agent can't reach central server, evidence must be buffered locally
- Agent deployment and updates across 100+ machines needs automation (Ansible, GPO, SCCM)
- Agent-server communication needs mutual TLS authentication

**Time**: 6-8 weeks

---

### Step 4.2 — Local LLM Fallback

**Task**: Add option to use local Ollama (Llama 3 8B or Mistral 7B) instead of Gemini for air-gapped environments.

**Why this matters**: 
- Government classified networks cannot send data to Google servers
- i4C will specifically ask about this. "Can this work offline?"
- Gemini has rate limits (60 calls/minute). During a mass attack, you hit the limit

**Implementation**:

```python
# In config.yaml
ai_mode: "gemini"  # Options: "gemini", "local_ollama", "hybrid"
ollama_url: "http://localhost:11434"
ollama_model: "llama3:8b"

# In gemini_command_analyzer.py
if ai_mode == "local_ollama":
    response = requests.post(f"{ollama_url}/api/generate", json={
        "model": ollama_model,
        "prompt": prompt,
        "stream": False
    })
    result = response.json()["response"]
```

**Pros**:
- Works in air-gapped networks (no internet needed)
- No rate limits. Can analyze 1000+ commands per minute on good hardware
- No data leaves the machine — full data sovereignty
- Hybrid mode: use local LLM for fast triage, Gemini for deep analysis only when needed

**Cons**:
- Requires GPU (NVIDIA 8GB+ VRAM) for decent speed. Without GPU, Llama 3 8B runs at ~5 tokens/second on CPU — too slow
- Local LLM accuracy is lower than Gemini 2.5 for security analysis
- Model needs to be fine-tuned on anti-forensics commands for acceptable accuracy
- Hardware cost: a machine with RTX 4060 (8GB VRAM) costs approximately 50,000-70,000 INR
- Fine-tuning dataset requires curated anti-forensics command corpus — does not exist publicly

**Time**: 2-3 weeks (basic integration), 2-3 months (fine-tuning for accuracy)

---

### Phase 3 Summary

| Item | Time | Risk | Impact |
|------|------|------|--------|
| Database migration | 2-3 weeks | Low | Searchable evidence |
| Secure REST API | 2-3 weeks | Medium | Secure external integration |
| Advanced Web Dashboard | 4-6 weeks | Medium | Perfection in LEA UX |

**Total Phase 3 time: 2-3 months**

---

### Phase 4 Summary

| Item | Time | Risk | Impact |
|------|------|------|--------|
| Multi-endpoint agent | 6-8 weeks | HIGH | Enterprise scalability |
| Local LLM fallback | 2-3 weeks base | Medium | Offline capability |

**Total Phase 4 time: 3-4 months**

---

## 6. Phase 5 — Government & Enterprise Grade (Month 10-16)

### Step 5.1 — BSA Section 63(4)(c) Compliance Module

**Task**: Auto-generate the certificate required for digital evidence admissibility in Indian courts.

**What BSA Section 63(4)(c) requires** (replaced old Section 65B IEA):
1. Device identification (machine name, OS, serial number)
2. Regular use declaration (device was in regular operation)
3. Data source description (what evidence was collected, from where)
4. Proper operation certification (device was functioning correctly)
5. Integrity verification (hash values proving data not tampered)
6. Expert validation (hash verified by qualified person)

**What your module should generate**:

```
CERTIFICATE UNDER SECTION 63(4)(c) 
BHARATIYA SAKSHYA ADHINIYAM, 2023

PART A - DEVICE IDENTIFICATION
Computer Name: [auto-populated]
Operating System: [auto-populated]
IP Address: [auto-populated]
Collection Tool: ShadowNet Nexus v5.0

PART B - EVIDENCE INTEGRITY
Evidence File: [filename]
SHA-256 Hash: [auto-calculated]
RFC 3161 Timestamp Token: [auto-attached]
Collection Time: [auto-populated]
Chain of Custody Log: [auto-attached]

PART C - CERTIFICATION
I certify that the above electronic record was produced by 
a device in regular operation, and the information has not 
been altered since collection.

Signature: _________________________
Name: _________________________
Designation: _________________________
Date: _________________________
```

**Pros**:
- Directly addresses the legal admissibility gap
- Auto-populates most fields — reduces investigator workload
- Attaching RFC 3161 token makes timestamp independently verifiable
- Indian courts are increasingly strict about Section 63(4)(c) compliance

**Cons**:
- The certificate template may need to be reviewed and approved by a legal expert
- Different courts may interpret "proper format" differently
- The "expert validation" part still requires a human signature — cannot be fully automated
- If the TSA used for RFC 3161 is not recognized by Indian courts, the timestamp has weaker legal standing

**Time**: 2-3 weeks (technical), 2-4 weeks (legal review)

---

### Step 4.2 — RBAC (Role-Based Access Control)

**Roles**:

| Role | Can Do | Cannot Do |
|------|--------|-----------|
| Investigator | View incidents, view evidence, generate reports | Delete evidence, change config |
| Supervisor | Everything Investigator can + approve evidence chain + export for court | Delete evidence |
| Admin | Full system access, configure system, manage users | — |
| Auditor (read-only) | View all audit logs, verify evidence integrity | Modify anything |

**Why this matters**: Indian legal framework requires documented access control for evidence handling. Without RBAC, any user can tamper with evidence, which breaks chain of custody.

**Time**: 3-4 weeks

---

### Step 4.3 — Standard Evidence Export Formats

**Target formats**:

| Format | Used By | Why |
|--------|---------|-----|
| E01 (EnCase) | CFSL, most Indian forensic labs | Industry standard for court evidence |
| AFF4 | Modern forensic tools | Open standard, supports large datasets |
| NCRP-compatible JSON | NCRP portal (i4C) | Direct upload to national portal |
| STIX 2.1 | Threat intelligence platforms | Machine-readable IOC sharing |

**Pros**:
- Evidence from ShadowNet can be directly used by CFSL without conversion
- NCRP integration means case filing is semi-automated

**Cons**:
- E01 format is complex (segmented, compressed, with built-in hash verification)
- AFF4 library in Python (`pyaff4`) has limited maintenance
- NCRP API specifications may change without notice

**Time**: 3-4 weeks

---

### Step 4.4 — Windows Service / Linux systemd Deployment

**Task**: Package ShadowNet as a proper background service, not a script run from terminal.

**Windows**: Create a Windows Service using `pyinstaller` + `pywin32`:
- Runs at system boot before any user logs in
- Runs with SYSTEM privileges (full WMI access)
- Survives user logoff
- Auto-restarts on crash

**Linux**: Create a systemd service unit:
- `systemctl enable shadownet`
- `systemctl start shadownet`
- Journal logging integration

**Pros**:
- Professional deployment. No one runs forensic tools from a Python terminal in production
- Starts before attacker can disable it (if attacker doesn't have SYSTEM access)
- Proper service lifecycle (start, stop, restart, status)

**Cons**:
- Windows Service development with pywin32 is tricky. Edge cases with service control manager
- pyinstaller packaging can break on some Python libraries (scipy, sklearn)
- Anti-virus may flag a new unknown Windows Service as suspicious
- Code signing certificate needed for Windows (costs ~$200/year) to prevent SmartScreen warnings

**Time**: 2-3 weeks

---

### Phase 4 Summary

| Item | Time | Risk | Impact |
|------|------|------|--------|
| BSA compliance module | 2-3 weeks + legal review | Medium | Court admissibility |
| RBAC | 3-4 weeks | Low | Evidence integrity |
| Evidence export formats | 3-4 weeks | Medium | Lab compatibility |
| Service packaging | 2-3 weeks | Medium | Professional deployment |

**Total Phase 4 time: 4-6 months**

---

## 6. Production-Level Problems You Will Face

### Problem 1: WMI Stability on Real Enterprise Systems

**What will happen**: WMI event subscriptions silently drop on enterprise machines with 50+ security products installed. Group Policy updates, Windows Updates, and AV scans all interfere with WMI event delivery.

**How to solve**: Implement a heartbeat check. Every 30 seconds, verify WMI subscription is alive. If dead, restart it. Log every restart. This is your current polling fallback, but it needs to be more robust.

**Difficulty**: Medium

---

### Problem 2: False Positive Tsunami in Enterprise

**What will happen**: On a real enterprise machine, legitimate admin tools (SCCM, GPO, PowerShell DSC, Ansible) generate thousands of commands per hour that look similar to attack commands. `wevtutil` is used legitimately by SCCM. `bcdedit` is used by Windows Update. Your tool will generate 100+ false alerts per day.

**How to solve**:
- Build a whitelist of known-good processes (by publisher signature, file hash, parent process)
- Implement a learning period (first 7 days = observation only, no alerts)
- Use the behavioral chain detection (Phase 2) — individual commands have high FP, chains have low FP
- Allow investigators to mark false positives, which feeds back into the whitelist

**Difficulty**: Hard. This is the #1 reason forensic tools fail in enterprise.

---

### Problem 3: Performance Under Load

**What will happen**: During a real incident (ransomware attack), hundreds of processes spawn per second. Each one triggers your callback. The Gemini API has a 60 calls/minute limit. Your queue overflows, evidence capture falls behind, and you miss critical commands.

**How to solve**:
- Local rule engine for first-pass filtering (no API call needed for obvious benign commands)
- API call queuing with priority (CRITICAL commands analyzed first)
- Batch multiple commands into single Gemini call where possible
- Local LLM fallback (Phase 3.5) for overflow

**Difficulty**: Hard

---

### Problem 4: Attacker Targeting ShadowNet Itself

**What will happen**: A sophisticated attacker who knows ShadowNet is running will try to:
- Kill the ShadowNet process (`taskkill /F /IM shadownet.exe`)
- Corrupt the evidence vault
- Flood it with benign commands to trigger rate limiting
- Disable WMI service

**How to solve**:
- Run as a protected Windows Service with anti-tamper (service recovery options)
- Monitor your own process health (watchdog thread)
- Digitally sign the evidence vault entries so corruption is detectable
- Alert immediately if WMI service is stopped or ShadowNet process is targeted

**Difficulty**: Very Hard. This is an arms race.

---

### Problem 5: Evidence Vault Disk Usage

**What will happen**: Each incident captures event logs (2-5 MB), process snapshots, network state, etc. On a busy server, this adds up to 500 MB - 1 GB per day. In 30 days, you have 15-30 GB of evidence that cannot be deleted (legal hold).

**How to solve**:
- Implement evidence rotation policy (configurable retention period)
- Compress old evidence (gzip)
- Separate active evidence (SSD) from archived evidence (HDD/NAS)
- Alert when vault exceeds configurable threshold (80% disk usage)

**Difficulty**: Medium

---

### Problem 6: Gemini Model Changes Breaking Your Parsing

**What will happen**: Google updates Gemini model versions regularly. When the model changes, the JSON output format may change slightly. Your `_parse_json_response()` function breaks. Your weighted scoring gets garbage data. No alert is generated because the error is swallowed by `except: pass`.

**How to solve**:
- Pin Gemini model version in config (currently hardcoded to `gemini-2.5-flash`)
- Add JSON schema validation for AI responses (use `jsonschema` library)
- Log every parsing failure with the raw response text
- Run your test suite monthly to detect regressions

**Difficulty**: Medium

---

### Problem 7: Legal Challenge to AI-Generated Classification

**What will happen**: A defense lawyer will argue: "This threat classification was generated by Google's AI, not a human expert. How can you prove the AI's conclusion is correct? Can you explain exactly how the AI reached this conclusion?"

**How to solve**:
- Never present AI classification as the sole evidence. Always pair it with human-verifiable indicators (command text, process tree, timestamp anomalies)
- Frame AI as "AI-assisted triage" not "AI verdict"
- Store the full AI prompt and response for audit trail
- Document AI confidence alongside traditional forensic indicators
- Have a Section 79A certified examiner review and co-sign findings

**Difficulty**: This is a legal problem, not a technical one. Need legal advisor.

---

### Problem 8: Multi-Language / Multi-Script Commands

**What will happen**: Attackers in India may use Hindi/Devanagari in filenames, or use Unicode characters in PowerShell commands to evade ASCII-based keyword detection.

**How to solve**:
- Ensure all file I/O uses UTF-8 encoding
- Keyword matching should be Unicode-aware
- Gemini naturally handles multilingual input, so AI analysis is less affected
- Add Unicode normalization before keyword matching

**Difficulty**: Medium

---

## 7. Competitor Comparison

Understanding what already exists helps position ShadowNet correctly.

| Feature | Wazuh | Velociraptor | OSSEC | ShadowNet |
|---------|-------|-------------|-------|-----------|
| Real-time monitoring | Yes (log-based) | No (query-based) | Yes (basic) | Yes (process-based) |
| Evidence preservation BEFORE destruction | No | No | No | **YES (unique)** |
| AI-powered classification | No | No | No | **YES (unique)** |
| NTFS forensic analysis | Limited | Yes (via VQL) | No | Yes (needs MFT fix) |
| Enterprise scalability | Yes (1000+ agents) | Yes (fleet-wide) | Limited | No (single machine) |
| Indian legal compliance | No | No | No | Planned (BSA module) |
| Open source | Yes | Yes | Yes | Yes |
| Active community | Large | Growing | Declining | You only |
| Dashboard | Yes | Yes | No | Planned |
| Cost | Free | Free | Free | Free |

### ShadowNet's Unique Value Proposition

**No existing tool captures evidence BEFORE an anti-forensics command completes execution.** This is ShadowNet's core differentiator. All other tools are reactive (analyze after the fact) or query-based (ask questions about current state). ShadowNet is proactive (capture evidence while the attack is happening).

This is what i4C will care about most.

---

## 8. Legal & Compliance Path

### BSA Section 63(4)(c) Mapping

| BSA Requirement | ShadowNet Status | What To Do |
|----------------|-----------------|------------|
| Device identification | Auto-detected (OSDetector) | Add serial number, MAC address |
| Regular use declaration | Not implemented | Add template certificate |
| Data integrity (hash) | SHA-256 implemented | Working |
| Independent timestamp | Not implemented | Add RFC 3161 (Phase 1.4) |
| Chain of custody log | Implemented (EvidenceVault) | Needs audit trail for human access |
| Expert certification | Not possible to automate | Needs human co-sign field |

### Section 79A IT Act Path

**Current situation**: NCFL (now N-DISC, National Digital Investigation Support Centre) under i4C provides forensic support to LEAs. There is a shortage of certified forensic tools in India. An indigenous tool endorsed by i4C would fill a real gap.

**Steps to formal recognition**:
1. Present research prototype to i4C's National Cyber Crime Research and Innovation Centre
2. If accepted for collaboration, get access to test environment and real (anonymized) case data
3. Run 90-day pilot with a state police cyber cell
4. Get forensic analysis methodology reviewed by CFSL (Central Forensic Science Laboratory)
5. Apply for empanelment as a forensic examination tool

---

## 9. i4C Presentation Strategy

### What i4C Cares About (Based on Recent Activities)

1. **Indigenous tools** — i4C explicitly funds and collaborates with Indian academic/research institutes for homegrown forensic technology
2. **Financial cybercrime** — i4C signed MoU with RBIH (May 2026) for AI-driven fraud prevention. Losses reached 22,845 crore INR in 2024 (206% increase)
3. **LEA usability** — CyTrain platform trains thousands of police officers. Tools must be usable by non-experts
4. **NCRP integration** — Over 140 million uses since 2020. Evidence that maps to NCRP case filing is immediately useful
5. **International cooperation** — India-US cybercrime MoU (Jan 2025). Tools that align with international standards (STIX, MITRE) are valued

### Presentation Framework

**Layer 1: Problem (30 seconds)**
Anti-forensics costs India crores per year in lost evidence. Attackers destroy logs, timestamps, and shadow copies before investigators arrive. Standard tools detect attacks after evidence is already gone.

**Layer 2: What ShadowNet does differently (60 seconds)**
Live demo: Run `wevtutil cl Security` on screen. Show ShadowNet detecting it in <100ms. Show the captured event log snapshot. Show the AI classification with MITRE TTP mapping. Show the SHA-256 hash and RFC 3161 timestamp. All of this happened before the attacker's command finished.

**Layer 3: Ask (30 seconds)**
Partnership for production development. Access to anonymized case data for accuracy testing. Pilot deployment with a state police cyber cell. Path to NCFL validation.

### What NOT to Say

- Do NOT say "production-ready." Say "research prototype with validated roadmap to deployment"
- Do NOT claim features that are not implemented yet
- Do NOT say "AI replaces investigators." Say "AI assists investigators by reducing triage time from hours to seconds"
- Do NOT share source code without NDA. i4C is government — they understand IP protection

### What to Bring

- A laptop with ShadowNet running live (Windows, admin mode)
- Pre-prepared attack scenarios for demo (3 scenarios: log clearing, timestomping, obfuscated PowerShell)
- Printed one-page summary (problem → solution → ask)
- Test results showing FP/FN rates (from Phase 1.6 test suite)

---

## 10. Team & Resource Requirements

### Minimum Team for Production

| Role | Count | Monthly Cost (INR) | Responsibility |
|------|-------|--------------------|---------------|
| Backend Engineer | 2 | 50K-80K each | Core engine, API, database, agent |
| Security Researcher | 1 | 60K-1L | Detection rules, MITRE mapping, test cases |
| Frontend Developer | 1 | 40K-60K | Dashboard, reports, LEA UI |
| Legal Advisor (part-time) | 1 | 20K-30K/month | BSA compliance, Section 79A guidance |

### Hardware Requirements

| Item | Cost (INR) | Purpose |
|------|-----------|---------|
| Development machine (16GB RAM, SSD) | Already have | Core development |
| Test Windows Server (VM) | 5K-10K/month (Azure/AWS) | Enterprise testing |
| GPU machine (RTX 4060 or above) | 60K-80K one-time | Local LLM fine-tuning and inference |

### Software/Service Costs

| Item | Cost | Purpose |
|------|------|---------|
| Gemini API | Free tier (15 RPM) or $0.15/million tokens | AI analysis |
| Code signing certificate | ~$200/year | Windows Service signing |
| Domain + SSL | ~$20/year | Dashboard hosting |
| GitHub private repo | Free | Version control |

---

## 11. Risk Matrix

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| Gemini API becomes paid-only or discontinued | Low | Critical | Local LLM fallback (Phase 3.5) |
| High false positive rate in enterprise | High | High | Whitelist + chain detection + learning period |
| Legal challenge to AI evidence | Medium | High | AI-assisted framing + human co-sign |
| Competitor releases similar tool | Low | Medium | First-mover advantage + Indian legal focus |
| Team member leaves mid-project | Medium | Medium | Document everything, modular code |
| i4C rejects the proposal | Medium | High | Also approach state-level cyber labs independently |
| WMI instability causes missed detections | High | Medium | Polling fallback + heartbeat monitoring |
| Attacker specifically targets ShadowNet | Low (for now) | High | Anti-tamper protections (Phase 4) |

---

## 12. References

### Research Papers

1. "A Review Study on Anti-Forensic Techniques and Their Detection in Digital Forensics" — Atlantis Press, 2026. Covers classification of anti-forensic methods and detection state-of-art.
2. "Forensic readiness in resource-constrained environments" — Politecnico di Torino, 2024. Explores repurposing monitoring tools for real-time evidence capture.
3. "SOLVE-IT: Systematic Objective-based Listing of Various Established Digital Investigation Techniques" — DFRWS, 2025. Structured knowledge base for forensic techniques.
4. "Blockchain for evidence integrity in digital forensics" — MDPI, 2024. Using blockchain for immutable evidence chains.
5. MITRE ATT&CK T1070 (Indicator Removal) — Complete sub-technique mapping for anti-forensics.
6. MITRE D3FEND — Defensive technique knowledge graph.

### Tools Referenced

- `analyzeMFT` — github.com/rowingdude/analyzeMFT — NTFS MFT parser
- `python-ntfs` — github.com/williballenthin/python-ntfs — Low-level NTFS analysis
- `rfc3161ng` / `tsp-client` — RFC 3161 timestamp libraries
- `MFTECmd` — Eric Zimmerman forensic tools — Industry standard MFT parser
- Wazuh — wazuh.com — Open source SIEM/XDR
- Velociraptor — docs.velociraptor.app — DFIR framework

### Legal References

- Bharatiya Sakshya Adhiniyam, 2023 — Section 63 (Electronic Records Admissibility)
- Information Technology Act, 2000 — Section 79A (Examiner of Electronic Evidence)
- PMLA Authorization for i4C — April 2025 (enables financial cybercrime forensics)
- India-US Cybercrime MoU — January 2025 (DHS + i4C cooperation)

---

> **Bottom line**: ShadowNet has a genuinely innovative core idea (pre-emptive evidence capture). The foundation needs 2-4 weeks of critical fixes. Full production readiness needs 12-14 months with a focused team. The i4C path is realistic if you fix the foundation first and present honestly as a research prototype with a clear deployment roadmap.
