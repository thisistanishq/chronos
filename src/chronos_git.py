"""
CHRONOS Time Travel Module
Scans Git Commit History for deleted or revoked secrets.
"""

import os
import re
import shutil
import subprocess
import tempfile
import uuid
import logging
from datetime import datetime

import rich
from configs import REGEX_LIST

# Configure Logger
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("Chronos-TimeTravel")

class ChronosGitScanner:
    def __init__(self, repo_url):
        self.repo_url = repo_url
        self.temp_dir = os.path.join(tempfile.gettempdir(), f"chronos_clone_{uuid.uuid4().hex[:8]}")
        self.found_keys = []

    def clone_repo(self):
        """Clones the repository to a temporary directory."""
        rich.print(f"[bold cyan]⏳ CLONING TIMELINE: {self.repo_url}[/bold cyan]")
        try:
            # Full clone needed for history
            subprocess.run(
                ["git", "clone", self.repo_url, self.temp_dir],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            rich.print(f"[bold green]✅ CLONE COMPLETE. LOCATED AT: {self.temp_dir}[/bold green]")
            return True
        except subprocess.CalledProcessError as e:
            rich.print(f"[bold red]❌ CLONE FAILED: {e}[/bold red]")
            return False

    def scan_history(self):
        """Streams git log -p and scans for secrets."""
        if not os.path.exists(self.temp_dir):
            rich.print("[bold red]❌ REPO NOT FOUND. ABORTING TIME TRAVEL.[/bold red]")
            return []

        rich.print("[bold magenta]⚡ INITIATING TEMPORAL SCAN (git log -p)...[/bold magenta]")
        
        # Stream git log -p
        # Format: Commit Hash | Author | Date | Message
        cmd = [
            "git", "log", "-p", "--all", 
            "--pretty=format:COMMIT_META:::%H:::%an:::%ad:::%s"
        ]
        
        process = subprocess.Popen(
            cmd,
            cwd=self.temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Merge stderr to ignore it or capture errors
            text=True,
            errors='replace', # Ignore encoding errors
            bufsize=1
        )

        current_commit = "UNKNOWN"
        current_author = "UNKNOWN"
        current_date = "UNKNOWN"
        
        # Regex Setup
        # We use the global REGEX_LIST from configs
        # Pre-compile for speed
        compiled_regex = [r for r, _, _ in REGEX_LIST]

        total_lines = 0
        hits = 0

        try:
            for line in process.stdout:
                line = line.strip()
                total_lines += 1
                
                # Metadata Line
                if line.startswith("COMMIT_META:::"):
                    parts = line.split(":::")
                    if len(parts) >= 2:
                        current_commit = parts[1]
                        current_author = parts[2] if len(parts) > 2 else "Unknown"
                        current_date = parts[3] if len(parts) > 3 else "Unknown"
                    continue

                # Diff Lines (We care about removals '-' or additions '+')
                # Actually, strictly deleted keys are interesting, but also added keys in old commits.
                if line.startswith("+") or line.startswith("-"):
                    # Check Regex
                    content = line[1:] # Strip +/-
                    if len(content) < 20: continue # Optimization: Skip short lines
                    
                    for regex in compiled_regex:
                        matches = regex.findall(content)
                        for match in matches:
                            hits += 1
                            self._record_find(match, current_commit, current_author, current_date, line.startswith("-"))
                            
                if total_lines % 50000 == 0:
                    print(f"   ...scanned {total_lines} temporal fragments...")

        except Exception as e:
            rich.print(f"[bold red]⚠️ TEMPORAL INTERFERENCE: {e}[/bold red]")
        finally:
            process.terminate()
            self._cleanup()

        rich.print(f"[bold green]✅ TIME TRAVEL COMPLETE. {hits} ANOMALIES DETECTED.[/bold green]")
        return self.found_keys

    def _record_find(self, key, commit, author, date, is_deletion):
        """Records a found key."""
        # Avoid duplicates in local run
        if any(x['key'] == key for x in self.found_keys):
            return

        risk_type = "DELETED_SECRET" if is_deletion else "HISTORICAL_ADDITION"
        color = "red" if is_deletion else "yellow"
        
        rich.print(f"   [bold {color}]☢️  {risk_type} FOUND[/bold {color}]")
        rich.print(f"      🔑 Key: {key[:15]}...")
        rich.print(f"      🕒 Time: {date}")
        rich.print(f"      👤 Blame: {author}")
        rich.print(f"      🔗 Commit: {commit[:8]}")

        self.found_keys.append({
            "key": key,
            "commit": commit,
            "author": author,
            "date": date,
            "type": risk_type
        })

    def _cleanup(self):
        """Removes the temporary clone."""
        rich.print(f"[dim]🧹 Cleaning up temporal anomalies ({self.temp_dir})...[/dim]")
        try:
            shutil.rmtree(self.temp_dir)
        except Exception as e:
            pass # Permissions can be tricky on windows/some envs

if __name__ == "__main__":
    # Test
    url = input("Enter Repo URL to Time Travel: ")
    scanner = ChronosGitScanner(url)
    if scanner.clone_repo():
        scanner.scan_history()
