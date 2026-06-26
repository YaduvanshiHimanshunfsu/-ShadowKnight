# 🛡️ ShadowKnight v4.0 — Project Analysis & Bug Report

## What Is This Project?

**ShadowKnight** is an **enterprise-grade digital forensics & incident response (DFIR) platform** built in Python. It detects, analyzes, and preserves evidence of **anti-forensics activity** in real-time.

### Core Idea
When an attacker runs commands like `wevtutil cl Security` (clearing Windows event logs) or `vssadmin delete shadows` (deleting backup shadow copies), ShadowKnight:
1. **Detects** the process creation instantly (via WMI events on Windows, polling on Linux/Mac)
2. **Captures evidence** (event logs, process state, network state) *before* the command can destroy it
3. **Sends the command to Google Gemini AI** for intelligent threat classification
4. **Generates forensic reports**, sends alerts (Slack/Email/Discord), and forwards events to SIEM platforms (Splunk/QRadar/Elastic)

### Architecture
```
Process Monitor (WMI/Polling) → Keyword Filter → Evidence Snapshot (<100ms)
                                                → Gemini AI Analysis (200-500ms)
                                                → Weighted Scoring (AI + NTFS + Disk)
                                                → Incident Report + SIEM + Alerts
```

---

## 🔴 CRITICAL Bugs & Security Issues

### 1. **API Key Committed to Git** — `.env` file is tracked
**File**: [.env](file:///e:/ShadowKnight2-Nexus/.env#L8)  
**Line**: 8

```
GEMINI_API_KEY=[REDACTED_DUE_TO_LEAK]
```

> [!CAUTION]
> The `.env` file contains a **real Gemini API key** and is committed to the repository. Even though `.gitignore` lists `.env`, it was tracked before the gitignore rule was added. Anyone with access to the repo history can extract this key. **You must rotate this key immediately** and run `git rm --cached .env` to untrack it.

---

### 2. **Config Key Mismatch — `ai_weight` Never Reads From Config**
**File**: [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L76)  
**Lines**: 76-78

```python
ai_weight = monitoring_config.get("ai_weight", 40)          # ← looks for "ai_weight"
ntfs_weight = monitoring_config.get("ntfs_weight", 30)
disk_weight = monitoring_config.get("disk_weight", 30)
```

**File**: [config.yaml](file:///e:/ShadowKnight2-Nexus/config/config.yaml#L70-L72)

```yaml
ai_confidence_weight: 40    # ← actual key is "ai_confidence_weight"
ntfs_weight: 30
disk_weight: 30
```

> [!WARNING]
> The config uses `ai_confidence_weight` but the code reads `ai_weight`. The config value is **silently ignored** and the hardcoded default `40` is always used. This doesn't crash, but means changing the weight in config has no effect.

---

### 3. **Prompt Template Uses `{{ }}` Instead of `{ }` — `.format()` Silently Produces Broken Prompts**
**File**: [enhanced_prompts.py](file:///e:/ShadowKnight2-Nexus/prompts/enhanced_prompts.py#L11-L17)

```python
IMPROVED_COMMAND_ANALYSIS_PROMPT = """
...
- Command: {{command_line}}
- Process Name: {{process_name}} (PID: {{pid}})
...
"""
```

**File**: [gemini_command_analyzer.py](file:///e:/ShadowKnight2-Nexus/core/gemini_command_analyzer.py#L62)

```python
prompt = IMPROVED_COMMAND_ANALYSIS_PROMPT.format(
    command_line=decoded_command,
    ...
)
```

> [!CAUTION]
> The prompt string uses **double curly braces** `{{command_line}}` everywhere. In Python's `.format()`, `{{ }}` is an *escaped literal* brace — it renders as `{command_line}` literally, **not** the substituted value. So the prompt sent to Gemini contains the literal text `{command_line}` instead of the actual command. The AI is analyzing placeholder text, not real data. **Every single Gemini analysis call is broken.**
> 
> **Fix**: Change `{{command_line}}` to `{command_line}` throughout the prompt. Keep `{{ }}` only for the JSON example block at the bottom (which is correct there).

---

### 4. **`NTFSTimelineEngine` SI vs FN Comparison Is Meaningless**
**File**: [ntfs_timeline_engine.py](file:///e:/ShadowKnight2-Nexus/core/ntfs_timeline_engine.py#L36-L47)

```python
def _extract_metadata(self, file_path):
    stats = os.stat(file_path)
    si = {
        "created": self._convert(stats.st_ctime),
        "modified": self._convert(stats.st_mtime),
        "accessed": self._convert(stats.st_atime),
    }
    fn = si.copy()  # ← FN is just a COPY of SI
    return si, fn
```

> [!IMPORTANT]
> The `$STANDARD_INFORMATION` vs `$FILE_NAME` comparison is a cornerstone of NTFS timestomping detection, but here `fn` is just `si.copy()`. The `_compare_si_fn` method will **always return zero mismatches** because both dicts are identical. This renders the entire SI/FN mismatch detection useless. True FN timestamps require raw MFT parsing (e.g., via `analyzeMFT` or `pytsk3`), which is not implemented here.

---

### 5. **Disk Analysis Only Scans 1 File Due to Double `break`**
**File**: [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L186-L207)

```python
for root, dirs, files in os.walk(scan_path):
    for file in files:
        ...
        break    # ← breaks inner loop after first file
    break        # ← breaks outer loop after first directory
```

> [!WARNING]
> The disk analysis loops both `break` after the very first file in the very first directory. This means entropy and wipe analysis only ever inspects **one single file** out of potentially thousands. The `disk_score` is therefore almost always 0 or highly unreliable. This appears intentional (config says `disk_max_files_scan: 1`) but combined with the fact that it always picks the first file alphabetically, the detection value is near zero.

---

## 🟡 Medium-Severity Bugs

### 6. **`model_selector.py` Prints Duplicate Status Line**
**File**: [model_selector.py](file:///e:/ShadowKnight2-Nexus/utils/model_selector.py#L93-L95)

```python
print(f"✅ Gemini Model Selector: Intelligent={self.intelligent_model}, Fast={self.fast_model}")
print(f"✅ Gemini Model Selector: Intelligent={self.intelligent_model}, Fast={self.fast_model}")
```

Copy-paste error. The same line is printed twice during startup.

---

### 7. **`compute_weighted_score` Math Is Wrong — AI Confidence Inflated**
**File**: [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L123-L127)

```python
def compute_weighted_score(ai_conf, ntfs_score, disk_score):
    ai_component = ai_conf * ai_weight         # ai_conf is 0.0-1.0, result: 0-40
    ntfs_component = (ntfs_score / 100) * ntfs_weight  # 0-30
    disk_component = (disk_score / 100) * disk_weight   # 0-30
    return ai_component + ntfs_component + disk_component  # max: 100
```

The math is **internally consistent** (max=100) BUT: the `disk_score` is accumulated by `+= 50` in the loop (lines 201, 204), so it can be 0, 50, or 100. Dividing by 100 normalizes it correctly. However, if the double-break is fixed and multiple files are scanned, `disk_score` can easily exceed 100 (unbounded accumulation), which would break the normalization.

---

### 8. **Bare `except:` Clauses Throughout — Silently Swallowing All Errors**
Multiple files use bare `except:` or `except: pass`:

| File | Line(s) |
|------|---------|
| [process_monitor.py](file:///e:/ShadowKnight2-Nexus/core/process_monitor.py#L189) | L30, L189 |
| [ntfs_timeline_engine.py](file:///e:/ShadowKnight2-Nexus/core/ntfs_timeline_engine.py#L157) | L30, L157 |
| [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L194) | L194, L330 |

These hide `KeyboardInterrupt`, `SystemExit`, and real bugs. At minimum, use `except Exception:`.

---

### 9. **`recent_commands` Dict Grows Unbounded — Memory Leak**
**File**: [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L114)

```python
recent_commands = {}  # Never cleaned up
```

The deduplication dict `recent_commands` in the main script is written to on every suspicious command but **never pruned**. Over days/weeks of operation, this dict grows without limit. (The `ProcessMonitor` class uses `deque(maxlen=100)` correctly, but the main script's dict does not.)

---

### 10. **Thread Safety: `detections` and `incidents` Counters Are Not Protected**
**Files**: [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L112-L113)

```python
detections = 0   # Incremented from callback thread (L319)
incidents = 0    # Incremented from worker thread (L290)
```

Both are modified from different threads without any lock. Python's GIL makes simple integer increments *mostly* safe in CPython, but this is still a race condition by spec and will fail on other Python implementations.

---

### 11. **`log_worker` Calls `task_done()` But Not On Sentinel `None`**
**File**: [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L138-L141)

```python
while True:
    item = incident_queue.get()
    if item is None:
        break           # ← no task_done() called
    ...
    incident_queue.task_done()  # only called on real items
```

If you ever call `incident_queue.join()`, the sentinel `None` item will never be marked done. Not a crash risk today (join isn't called), but a latent bug.

---

## 🟢 Minor Issues & Code Smells

### 12. **`ntfs_artifact_parser.py` Is Empty (0 bytes)**
**File**: [ntfs_artifact_parser.py](file:///e:/ShadowKnight2-Nexus/core/ntfs_artifact_parser.py) — listed at 0 bytes.

Placeholder file that's never imported. Should either be implemented or removed.

---

### 13. **README Repo URL Typo**
**File**: [README.md](file:///e:/ShadowKnight2-Nexus/README.md#L1076)

```
git clone https://github.com/kmaruthisrikar/ShadowKnight-Nexsus.git
```

"Nexsus" should be "Nexus".

---

### 14. **README CEF Header Says "Anthropic" Instead of Project Name**
**File**: [README.md](file:///e:/ShadowKnight2-Nexus/README.md#L970)

```
CEF:0|Anthropic|ShadowKnight|4.0|...
```

The vendor field says "Anthropic" but this is a student/personal project, not an Anthropic product.

---

### 15. **`ProcessMonitor` Is a Function, Not a Class**
**File**: [process_monitor.py](file:///e:/ShadowKnight2-Nexus/core/process_monitor.py#L340)

```python
def ProcessMonitor(callback=None, suspicious_keywords=None):
    """Factory function to return the correct monitor for the platform"""
```

This is a factory function named like a class (PascalCase). The `core/__init__.py` does `from .process_monitor import ProcessMonitor as WMIProcessMonitor, ProcessMonitor`, which imports the same function under two names. Not broken, but misleading.

---

### 16. **`entropy_threshold` Config Mismatch**
**File**: [config.yaml](file:///e:/ShadowKnight2-Nexus/config/config.yaml#L58) uses `disk_entropy_threshold: 7.5`  
**File**: [shadow_knight_realtime.py](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L83) reads `entropy_threshold` (correct)  
**File**: [entropy_engine.py](file:///e:/ShadowKnight2-Nexus/core/entropy_engine.py#L23) default is `7.8`

The `EntropyEngine` class default (7.8) and the config (7.5) are different. The main script reads from config correctly (7.5), but `EntropyEngine()` is instantiated at [line 183](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L183) **without** passing the config threshold, so it uses its internal default of 7.8 for its `fast_scan_file` method's `high_entropy_detected` flag. Meanwhile, the comparison at [line 200](file:///e:/ShadowKnight2-Nexus/shadow_knight_realtime.py#L200) uses `entropy_threshold` (7.5) from config, making the two checks inconsistent.

---

## Summary Table

| # | Severity | Bug | Impact |
|---|----------|-----|--------|
| 1 | 🔴 CRITICAL | API key committed to git | Security breach |
| 2 | 🔴 HIGH | Config key mismatch (`ai_weight` vs `ai_confidence_weight`) | Config changes ignored |
| 3 | 🔴 CRITICAL | `{{ }}` in prompt template — `.format()` doesn't substitute | **All AI analysis broken** |
| 4 | 🔴 HIGH | SI/FN comparison always identical | Timestomping detection useless |
| 5 | 🟡 MEDIUM | Double `break` — only scans 1 file | Disk analysis unreliable |
| 6 | 🟢 LOW | Duplicate print in model_selector | Cosmetic |
| 7 | 🟡 MEDIUM | `disk_score` can exceed 100 if fixed | Scoring overflow |
| 8 | 🟡 MEDIUM | Bare `except:` clauses | Hides real errors |
| 9 | 🟡 MEDIUM | `recent_commands` never pruned | Memory leak |
| 10 | 🟢 LOW | Thread-unsafe counter increments | Race condition |
| 11 | 🟢 LOW | Missing `task_done()` for sentinel | Latent join bug |
| 12 | 🟢 LOW | Empty `ntfs_artifact_parser.py` | Dead file |
| 13 | 🟢 LOW | README typo "Nexsus" | Documentation |
| 14 | 🟢 LOW | CEF vendor says "Anthropic" | Wrong branding |
| 15 | 🟢 LOW | Factory function named like class | Misleading API |
| 16 | 🟡 MEDIUM | Entropy threshold mismatch | Inconsistent detection |

---

> [!IMPORTANT]
> **The two most urgent bugs to fix are #1 (rotate the API key) and #3 (the `{{ }}` prompt template issue). Bug #3 means every Gemini AI analysis call is currently broken — the AI receives literal placeholder text instead of actual command data, making the entire threat classification pipeline non-functional.**
