"""
Research Reporting Module
Exports the Hierarchical Model Clearance System (HMCS) data to CSV for statistical analysis.
"""

import sqlite3
import csv
import os
from datetime import datetime
import rich

DB_FILE = "github.db"
OUTPUT_FILE = f"research_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

def generate_report():
    if not os.path.exists(DB_FILE):
        rich.print("[bold red]❌ NO DATABASE FOUND. RUN SCAN FIRST.[/bold red]")
        return

    rich.print(f"[bold cyan]📊 EXPORTING RESEARCH DATA TO {OUTPUT_FILE}...[/bold cyan]")
    
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    
    # Check for columns to ensure we don't crash on old DBs
    cur.execute("PRAGMA table_info(APIKeys)")
    columns = [info[1] for info in cur.fetchall()]
    
    has_research_data = "model_tier" in columns
    
    if has_research_data:
        # Check for new Chronos columns
        cur.execute("PRAGMA table_info(APIKeys)")
        cols = [c[1] for c in cur.fetchall()]
        has_chronos = "first_found_at" in cols

        if has_chronos:
            query = "SELECT apiKey, status, lastChecked, model_tier, risk_score, context_tag, first_found_at, revoked_at FROM APIKeys"
            headers = ["API Key Masked", "Status", "Last Checked", "Clearance Tier", "Risk Score", "Context Tag", "Born At", "Died At", "Survival (Hours)", "Event Status"]
        else:
            query = "SELECT apiKey, status, lastChecked, model_tier, risk_score, context_tag FROM APIKeys"
            headers = ["API Key Masked", "Status", "Last Checked", "Clearance Tier", "Risk Score", "Context Tag"]
    else:
        rich.print("[yellow]⚠️  LEGACY DATABASE DETECTED. EXPORTING BASIC DATA ONLY.[/yellow]")
        query = "SELECT apiKey, status, lastChecked FROM APIKeys"
        headers = ["API Key Masked", "Status", "Last Checked"]

    cur.execute(query)
    rows = cur.fetchall()

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for row in rows:
            key = row[0]
            masked_key = f"{key[:8]}...{key[-4:]}"
            
            data = [masked_key] + list(row[1:])

            # Survival Analysis Calculation
            if has_chronos and has_research_data:
                # row structure: 0=key, 1=status, 2=lastChecked, 3=tier, 4=risk, 5=context, 6=born, 7=died
                born_at_str = row[6]
                died_at_str = row[7]
                
                survival_hours = "N/A"
                event_status = "Censored" # Default Alive

                if born_at_str:
                    try:
                        born_dt = datetime.fromisoformat(born_at_str)
                        if died_at_str:
                            died_dt = datetime.fromisoformat(died_at_str)
                            delta = died_dt - born_dt
                            survival_hours = delta.total_seconds() / 3600
                            event_status = "Event" # Dead
                        else:
                            # Still alive, calculate time until now
                            delta = datetime.now() - born_dt
                            survival_hours = delta.total_seconds() / 3600
                            event_status = "Censored"
                    except ValueError:
                         pass
                
                data.append(f"{survival_hours:.2f}" if isinstance(survival_hours, float) else survival_hours)
                data.append(event_status)

            writer.writerow(data)

    rich.print(f"[bold green]✅ EXPORT COMPLETE. {len(rows)} RECORDS PROCESSED.[/bold green]")
    con.close()

if __name__ == "__main__":
    generate_report()
