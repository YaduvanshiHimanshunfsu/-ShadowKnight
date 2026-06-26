import os
import subprocess
from datetime import datetime
from .ntfs_artifact_parser import NTFSArtifactParser

class NTFSTimelineEngine:
    """
    NTFS Structural Timeline Integrity Engine
    -----------------------------------------
    Includes:
    - Metadata validation
    - Timeline reconstruction
    - Forensic scoring
    - Limited USN Journal validation
    """

    def __init__(self, root_path="C:\\", max_files=3000):
        self.root_path = root_path
        self.max_files = max_files
        self.analyzed_count = 0
        self.results = []
        self.usn_status = {}
        self.mft_parser = NTFSArtifactParser()

    # ----------------------------------------------------------
    # Timestamp conversion
    # ----------------------------------------------------------
    def _convert(self, ts):
        try:
            return datetime.fromtimestamp(ts)
        except Exception:
            return None

    # ----------------------------------------------------------
    # Metadata extraction
    # ----------------------------------------------------------
    def _extract_metadata(self, file_path):
        mft_data = self.mft_parser.extract_mft_timestamps(file_path)

        si = {
            "created": mft_data.get("si_creation"),
            "modified": None, # Focus on creation for timestomp
            "accessed": None
        }

        fn = {
            "created": mft_data.get("fn_creation"),
            "modified": None,
            "accessed": None
        }

        return si, fn

    # ----------------------------------------------------------
    # SI vs FN comparison
    # ----------------------------------------------------------
    def _compare_si_fn(self, si, fn):
        mismatches = []

        for key in ["created", "modified", "accessed"]:
            if si[key] and fn[key]:
                if abs((si[key] - fn[key]).total_seconds()) > 2:
                    mismatches.append(key)

        return mismatches

    # ----------------------------------------------------------
    # Timeline reconstruction
    # ----------------------------------------------------------
    def _reconstruct_timeline(self, si):
        anomalies = []

        created = si["created"]
        modified = si["modified"]
        accessed = si["accessed"]
        now = datetime.now()

        if modified and created and modified < created:
            anomalies.append("Modified before creation")

        if accessed and created and accessed < created:
            anomalies.append("Access before creation")

        if created and created > now:
            anomalies.append("Creation time in future")

        return anomalies

    # ----------------------------------------------------------
    # USN Journal Validation
    # ----------------------------------------------------------
    def _validate_usn_journal(self):
        """
        Checks:
        - Is USN Journal present?
        - Was it deleted?
        """

        try:
            result = subprocess.run(
                ["fsutil", "usn", "queryjournal", self.root_path[0] + ":"],
                capture_output=True,
                text=True
            )

            if "No active USN journal" in result.stdout:
                self.usn_status = {
                    "exists": False,
                    "issue": "USN Journal not active or deleted"
                }
            else:
                self.usn_status = {
                    "exists": True,
                    "issue": None
                }

        except Exception as e:
            self.usn_status = {
                "exists": False,
                "issue": f"USN check failed: {str(e)}"
            }

    # ----------------------------------------------------------
    # Scoring Model
    # ----------------------------------------------------------
    def _compute_score(self, mismatches, timeline_anomalies):
        score = 0

        if mismatches:
            score += 40

        if timeline_anomalies:
            score += 30

        if not self.usn_status.get("exists", True):
            score += 50  # Major anti-forensic indicator

        score += len(timeline_anomalies) * 10

        return min(score, 100)

    # ----------------------------------------------------------
    # File analysis
    # ----------------------------------------------------------
    def _analyze_file(self, file_path):
        try:
            si, fn = self._extract_metadata(file_path)

            mismatches = self._compare_si_fn(si, fn)
            timeline_issues = self._reconstruct_timeline(si)

            score = self._compute_score(mismatches, timeline_issues)

            if score > 0:
                self.results.append({
                    "file": file_path,
                    "si_fn_mismatch": mismatches,
                    "timeline_anomalies": timeline_issues,
                    "forensic_score": score
                })

        except Exception as e:
            pass

    # ----------------------------------------------------------
    # Directory scan
    # ----------------------------------------------------------
    def _scan_directory(self):
        for root, dirs, files in os.walk(self.root_path):
            for name in files:
                if self.analyzed_count >= self.max_files:
                    return

                file_path = os.path.join(root, name)
                self._analyze_file(file_path)
                self.analyzed_count += 1

    # ----------------------------------------------------------
    # Main public method
    # ----------------------------------------------------------
    def run_structural_validation(self):
        print("\n[NTFS] Structural Validation Started...")

        self._validate_usn_journal()
        self._scan_directory()

        total_score = 0
        for r in self.results:
            total_score += r["forensic_score"]

        overall_score = min(total_score // max(len(self.results), 1), 100)

        print(f"[NTFS] Completed. Files flagged: {len(self.results)}")

        return {
            "total_files_analyzed": self.analyzed_count,
            "files_flagged": len(self.results),
            "usn_status": self.usn_status,
            "details": self.results,
            "forensic_score": overall_score
        }