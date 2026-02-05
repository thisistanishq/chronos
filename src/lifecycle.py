"""
Lifecycle Monitor (Project CHRONOS)
A background daemon that tracks the survival time of leaked credentials.
"""

import time
import rich
from datetime import datetime
from manager import DatabaseManager
from utils import check_key_tier

DB_FILE = "github.db"
CHECK_INTERVAL_SECONDS = 300 # Check every 5 minutes

def lifecycle_loop():
    rich.print("[bold purple]⏳ PROJECT CHRONOS: LIFECYCLE MONITOR ENGAGED...[/bold purple]")
    
    while True:
        try:
            with DatabaseManager(DB_FILE) as db:
                valid_keys = db.all_valid_keys_for_lifecycle()
            
            if not valid_keys:
                rich.print("[dim]💤 No active subjects to monitor. Sleeping...[/dim]")
                time.sleep(CHECK_INTERVAL_SECONDS)
                continue

            rich.print(f"[bold purple]🧬 MONITORING SURFACE: {len(valid_keys)} ACTIVE SUBJECTS[/bold purple]")

            for key_tuple in valid_keys:
                key = key_tuple[0]
                # Re-validate
                result = check_key_tier(key)
                
                if result.status != "yes":
                    # KEY HAS DIED
                    death_time = datetime.now().isoformat()
                    rich.print(f"[bold red]💀 SUBJECT EXPIRED: {key[:8]}... (Reason: {result.status})[/bold red]")
                    
                    with DatabaseManager(DB_FILE) as db:
                        db.update_status(key, result.status, revoked_at=death_time)
                else:
                    # STILL ALIVE
                    # rich.print(f"[green]❤️  STABLE: {key[:8]}...[/green]")
                    pass
            
            rich.print(f"[dim]✅ Cycle complete. Next check in {CHECK_INTERVAL_SECONDS}s[/dim]")
            time.sleep(CHECK_INTERVAL_SECONDS)

        except Exception as e:
            rich.print(f"[bold red]⚠️  MONITOR FAILURE: {e}[/bold red]")
            time.sleep(60)

if __name__ == "__main__":
    lifecycle_loop()
