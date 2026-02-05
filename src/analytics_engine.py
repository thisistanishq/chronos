"""
Analytics Engine for Project CHRONOS
Generates the statistical figures required for the research paper:
1. Kaplan-Meier Survival Curves (Tier 1 vs Tier 2)
2. Economic Tier Distribution (Pie Chart)
3. Dataset Leakage Impact (Bar Chart)

Requires: matplotlib, pandas, lifelines
"""

import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import rich

# Try to import lifelines, handle if missing
try:
    from lifelines import KaplanMeierFitter
    HAS_LIFELINES = True
except ImportError:
    HAS_LIFELINES = False

DB_FILE = "github.db"

def load_data():
    con = sqlite3.connect(DB_FILE)
    query = """
    SELECT 
        apiKey, 
        model_tier, 
        first_found_at, 
        revoked_at, 
        is_dataset,
        status
    FROM APIKeys
    """
    df = pd.read_sql_query(query, con)
    con.close()
    return df

def generate_tier_distribution(df):
    """Generates a pie chart of the Economic Tiers."""
    tier_counts = df['model_tier'].value_counts()
    
    plt.figure(figsize=(10, 6))
    plt.pie(tier_counts, labels=tier_counts.index, autopct='%1.1f%%', startangle=140, colors=['#ff9999','#66b3ff','#99ff99','#ffcc99'])
    plt.title('Economic Credential Stratification (N={})'.format(len(df)))
    plt.savefig('figure_1_tier_distribution.png')
    rich.print("[green]✅ Figure 1 Saved: Economic Credential Stratification[/green]")

def generate_survival_curves(df):
    """Generates Kaplan-Meier survival curves for Tier 1 vs Tier 2."""
    if not HAS_LIFELINES:
        rich.print("[red]⚠️  'lifelines' library not found. Skipping Survival Analysis.[/red]")
        rich.print("run: pip install lifelines")
        return

    plt.figure(figsize=(12, 8))
    kmf = KaplanMeierFitter()
    
    # Preprocess Time
    df['first_found_at'] = pd.to_datetime(df['first_found_at'])
    now = datetime.now()
    
    # Calculate duration (T) and Event (E)
    # If revoked_at exists -> Event=1 (Death), Duration = revoked - born
    # If valid -> Event=0 (Censored), Duration = now - born
    
    durations = []
    events = []
    
    for _, row in df.iterrows():
        start = row['first_found_at']
        if row['revoked_at']:
            end = pd.to_datetime(row['revoked_at'])
            E = 1
        else:
            end = now
            E = 0
            
        T = (end - start).total_seconds() / 3600 # Hours
        durations.append(T)
        events.append(E)
        
    df['T'] = durations
    df['E'] = events
    
    # Plot Tier 1
    tier1 = df[df['model_tier'].str.contains("GPT-4", case=False, na=False)]
    if not tier1.empty:
        kmf.fit(tier1['T'], tier1['E'], label='Tier 1 (GPT-4)')
        kmf.plot(ci_show=True)

    # Plot Tier 2
    tier2 = df[df['model_tier'].str.contains("GPT-3.5", case=False, na=False)]
    if not tier2.empty:
        kmf.fit(tier2['T'], tier2['E'], label='Tier 2 (GPT-3.5)')
        kmf.plot(ci_show=True)
        
    plt.title('Kaplan-Meier Survival Estimates by Economic Tier')
    plt.xlabel('Time to Revocation (Hours)')
    plt.ylabel('Survival Probability S(t)')
    plt.savefig('figure_2_survival_curves.png')
    rich.print("[green]✅ Figure 2 Saved: Survival Curves[/green]")

def main():
    try:
        df = load_data()
        if df.empty:
            rich.print("[yellow]⚠️  Database is empty. No charts generated.[/yellow]")
            return

        generate_tier_distribution(df)
        generate_survival_curves(df)
        
    except Exception as e:
        rich.print(f"[red]Error generating analytics: {e}[/red]")

if __name__ == "__main__":
    main()
