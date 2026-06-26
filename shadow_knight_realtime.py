"""
SHADOWNET NEXUS - COMPLETE REAL-TIME SYSTEM (v4.1 HYBRID)
Hybrid Real-Time + Deep Forensic Architecture
Fully Config-Driven Severity + Scoring
"""

import os
import sys
import time
import threading
import queue
import yaml
import json
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv()

# ============================================================
# CONSTANTS
# ============================================================

DEDUPLICATION_WINDOW = 2.0
SHUTDOWN_TIMEOUT = 5.0

# ============================================================
# HEADER
# ============================================================

def print_header():
    print("-" * 61)
    print("      SHADOWNET NEXUS - v4.1 (HYBRID FORENSIC)")
    print("   Real-Time + Deep Disk Intelligence Engine")
    print("-" * 61)

print_header()

# ============================================================
# LOAD CONFIG
# ============================================================

config_path = Path(__file__).parent / "config" / "config.yaml"
with open(config_path, "r") as f:
    config = yaml.safe_load(f)

monitoring_config = config["shadow_knight"]["monitoring"]

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    print("❌ GEMINI_API_KEY missing.")
    sys.exit(1)

# ============================================================
# IMPORT CORE MODULES
# ============================================================

from core.process_monitor import get_process_monitor
from core.proactive_evidence_collector import ProactiveEvidenceCollector
from core.gemini_command_analyzer import GeminiCommandAnalyzer
from core.siem_integration import SIEMIntegration, SIEMPlatform
from core.alert_manager import AlertManager, AlertChannel, AlertSeverity
from core.incident_report_generator import IncidentReportGenerator
from core.ntfs_timeline_engine import NTFSTimelineEngine
from core.entropy_engine import EntropyEngine
from core.wipe_pattern_engine import WipePatternEngine

# ============================================================
# CONFIG-DRIVEN WEIGHT MODEL
# ============================================================

ai_weight = monitoring_config.get("ai_confidence_weight", 40)
ntfs_weight = monitoring_config.get("ntfs_weight", 30)
disk_weight = monitoring_config.get("disk_weight", 30)

critical_threshold = monitoring_config.get("severity_critical_threshold", 70)
high_threshold = monitoring_config.get("severity_high_threshold", 40)

entropy_threshold = monitoring_config.get("disk_entropy_threshold", 7.5)
min_file_size_mb = monitoring_config.get("min_file_size_mb", 5)
enable_confidence_downgrade = monitoring_config.get(
    "enable_confidence_downgrade_on_fallback", True
)

# ============================================================
# INITIALIZE COMPONENTS
# ============================================================

keywords = monitoring_config.get("suspicious_keywords", [])

ai_analyzer = GeminiCommandAnalyzer(api_key)
siem = SIEMIntegration(config={"syslog_server": "127.0.0.1", "syslog_port": 514})
alert_mgr = AlertManager(config={})
incident_reporter = IncidentReportGenerator(evidence_path="./evidence")

evidence_collector = ProactiveEvidenceCollector(
    evidence_vault_path="./evidence",
    enabled=True,
    capture_network=monitoring_config.get("enable_network_monitoring", True),
    suspicious_keywords=keywords
)

# ============================================================
# GLOBAL STATE
# ============================================================

incident_queue = queue.Queue()
detections = 0
incidents = 0
counters_lock = threading.Lock()
recent_commands = {}
recent_commands_lock = threading.Lock()
MY_PID = os.getpid()
monitor = None

# ============================================================
# WEIGHTED SEVERITY FUNCTION (CONFIG DRIVEN)
# ============================================================

def compute_weighted_score(ai_conf, ntfs_score, disk_score):
    ai_component = ai_conf * ai_weight
    ntfs_component = (ntfs_score / 100) * ntfs_weight
    disk_component = (min(disk_score, 100) / 100) * disk_weight
    
    weighted = ai_component + ntfs_component + disk_component
    
    if ai_conf >= 0.90:
        weighted = max(weighted, 70)
    elif ai_conf >= 0.80:
        weighted = max(weighted, 50)
        
    return min(weighted, 100)

# ============================================================
# LOG WORKER - HYBRID FORENSIC CORE
# ============================================================

def log_worker():

    global incidents
    print("[OK] Hybrid Incident Processor Started")

    while True:
        item = incident_queue.get()
        if item is None:
            incident_queue.task_done()
            break

        start_time = time.time()

        command = item["command"]
        process_info = item["process_info"]
        snapshot_id = item.get("snapshot_id", "N/A")

        # ====================================================
        # 1️⃣ AI ANALYSIS
        # ====================================================

        ai_res = ai_analyzer.analyze_command(command, process_info)
        ai_conf = ai_res.get("confidence", 0)

        # ====================================================
        # 2️⃣ NTFS VALIDATION
        # ====================================================

        ntfs_score = 0
        ntfs_results = {}

        if monitoring_config.get("enable_ntfs_analysis", False):
            try:
                scan_path = monitoring_config.get("ntfs_scan_path", "C:\\Users")
                ntfs_engine = NTFSTimelineEngine(scan_path)
                ntfs_results = ntfs_engine.run_structural_validation()
                ntfs_score = ntfs_results.get("forensic_score", 0)
            except Exception as e:
                print("[NTFS ERROR]", e)

        # ====================================================
        # 3️⃣ DISK ANALYSIS
        # ====================================================

        disk_score = 0
        fallback_triggered = False

        if monitoring_config.get("enable_disk_analysis", False):
            try:
                scan_path = monitoring_config.get("disk_scan_path", "C:\\Users")
                disk_max_files = monitoring_config.get("disk_max_files_scan", 100)
                scanned_count = 0

                entropy_engine = EntropyEngine(entropy_threshold=entropy_threshold)
                wipe_engine = WipePatternEngine()

                for root, dirs, files in os.walk(scan_path):
                    for file in files:
                        if scanned_count >= disk_max_files:
                            break

                        file_path = os.path.join(root, file)

                        try:
                            if os.path.getsize(file_path) < min_file_size_mb * 1024 * 1024:
                                continue
                        except Exception:
                            continue

                        entropy_val = entropy_engine.calculate_entropy_sampled(file_path)
                        wipe_val = wipe_engine.fast_scan_file(file_path)

                        if entropy_val and entropy_val > entropy_threshold:
                            disk_score += 50

                        if wipe_val and wipe_val.get("wipe_detected"):
                            disk_score += 50

                        scanned_count += 1
                        
                    if scanned_count >= disk_max_files:
                        break

            except PermissionError:
                fallback_triggered = True
            except Exception as e:
                print("[DISK ERROR]", e)
                fallback_triggered = True

        # ====================================================
        # 4️⃣ WEIGHTED SCORING
        # ====================================================

        weighted_score = compute_weighted_score(
            ai_conf,
            ntfs_score,
            disk_score
        )

        if fallback_triggered and enable_confidence_downgrade:
            weighted_score *= 0.8

        # Dynamic Severity Thresholds
        if weighted_score >= critical_threshold:
            severity = "CRITICAL"
        elif weighted_score >= high_threshold:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        # ====================================================
        # 5️⃣ INCIDENT CREATION
        # ====================================================

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        incident_id = f"INC-{timestamp}"

        incident_data = {
            "incident_id": incident_id,
            "command": command,
            "process_info": process_info,
            "ai_analysis": ai_res,
            "ntfs_score": ntfs_score,
            "disk_score": disk_score,
            "weighted_score": weighted_score,
            "severity": severity,
            "fallback_triggered": fallback_triggered,
            "snapshot_id": snapshot_id
        }

        incident_dir = Path("evidence/incidents") / incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)

        with open(incident_dir / "incident.json", "w") as f:
            json.dump(incident_data, f, indent=2)

        # ====================================================
        # 6️⃣ SIEM EVENT
        # ====================================================

        siem.send_event({
            "type": "hybrid_forensic",
            "severity": severity,
            "incident_id": incident_id,
            "weighted_score": weighted_score
        }, [SIEMPlatform.SYSLOG])

        # ====================================================
        # 7️⃣ ALERT
        # ====================================================

        alert_mgr.send_alert(
            title="[ALERT] HYBRID FORENSIC DETECTION",
            message=f"{command[:100]}...\nScore: {weighted_score:.2f}",
            severity=AlertSeverity.CRITICAL
            if severity == "CRITICAL"
            else AlertSeverity.HIGH,
            channels=[AlertChannel.CONSOLE],
            metadata=incident_data
        )

        processing_time = time.time() - start_time
        print(f"[OK] Incident {incident_id} processed in {processing_time:.2f}s")

        with counters_lock:
            incidents += 1
            
        incident_queue.task_done()

# ============================================================
# START WORKER
# ============================================================

worker_thread = threading.Thread(target=log_worker, daemon=True)
worker_thread.start()

# ============================================================
# SUSPICIOUS COMMAND HANDLER
# ============================================================

def on_suspicious_command(command, process_info):

    global detections

    cmd_key = f"{process_info.get('name')}:{command}"
    now = time.time()

    with recent_commands_lock:
        if cmd_key in recent_commands and now - recent_commands[cmd_key] < DEDUPLICATION_WINDOW:
            return
            
        # Clean up old entries
        keys_to_delete = [k for k, v in recent_commands.items() if now - v > 60]
        for k in keys_to_delete:
            del recent_commands[k]
            
        recent_commands[cmd_key] = now

    if process_info.get("pid") == MY_PID:
        return

    with counters_lock:
        detections += 1

    snapshot_id = "N/A"

    try:
        res = evidence_collector.on_threat_detected({
            "command": command,
            "process_info": process_info
        })
        if res.get("snapshot_taken"):
            snapshot_id = res.get("snapshot_id")
    except Exception as e:
        print("[COLLECTOR ERROR]", e)

    incident_queue.put({
        "command": command,
        "process_info": process_info,
        "snapshot_id": snapshot_id
    })

# ============================================================
# START MONITORING
# ============================================================

if __name__ == "__main__":

    monitor = get_process_monitor(
        callback=on_suspicious_command,
        suspicious_keywords=keywords
    )

    monitor.start_monitoring()

    print("🔍 ShadowKnight Hybrid Monitoring Active...\n")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        monitor.stop_monitoring()
        incident_queue.put(None)
        worker_thread.join(timeout=SHUTDOWN_TIMEOUT)
        print("👋 Shutdown Complete")