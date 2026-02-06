# CHRONOS: Neural Asset Intelligence System
**Defensive Security Research Artifact**

> ⚠️ **DISCLAIMER: FOR SECURITY RESEARCH AND DEFENSIVE ADVERSARIAL SIMULATION ONLY.**
> This tool is designed to help organizations identify, track, and remediate leaked API credentials within their own infrastructure. The authors are not responsible for misuse. Use responsibly and ethically.

---

## 1. The Problem Space
In the modern AI-driven development landscape, the **API Key** has become the new "root password." 

Imagine this real-world scenario: A developer at a fintech startup is working late. They want to test a new feature that uses OpenAI's GPT-4. They hardcode their company's API key into a Python script for a quick test, intending to delete it later. They push the code to a public GitHub repository.

**In less than 3 seconds**, that key is scraped by malicious botnets.

The consequences are immediate:
1.  **Financial Drain**: Attackers consume thousands of dollars in quota.
2.  **Data Exfiltration**: If the key has access to fine-tuned models or files, proprietary data is stolen.
3.  **Reputation Damage**: The organization loses trust.

Standard scanners (like truffleHog or git-secrets) often fail because they rely on simple regex patterns (finding "sk-...") but cannot validate the *context* or *value* of the credential. They generate noise, not intelligence.

## 2. The CHRONOS Solution
CHRONOS is not just a regex scanner. It is a **Neural Asset Intelligence System**.

It mimics the behavior of sophisticated threat actors to help defenders understand their exposure. Instead of just finding a string that *looks* like a key, CHRONOS validates it, probes its permissions, measures its economic value, and tracks its lifecycle.

### Core Architecture

*   **HMCS (Hierarchical Model Clearance System)**
    Think of this as a security clearance check. CHRONOS doesn't just say "Key is Valid." It determines *what* the key can do. Can it access GPT-4 (High Value)? Is it limited to GPT-3.5 (Low Value)? This allows security teams to prioritize remediation based on actual risk, not just volume.

*   **Leviathan Worker Swarm**
    A distributed, multi-process engine that allows CHRONOS to scan massive repositories or search results in parallel. It handles rate-limiting and session management automatically, simulating a human researcher browsing GitHub at scale.

*   **Time Travel Module (Forensics)**
    Attackers don't just look at the latest commit. They look at history. A developer might "fix" a leak by deleting the key in the next commit, but it remains in the git history. The Time Travel module walks backward through the commit log to unearth these "buried" credentials.

*   **Active Defense (Honeypots)**
    CHRONOS includes a self-protection mechanism. If the scanner detects it is being probed or analyzed by unauthorized entities, it deploys honeypot data to confuse and mislead the attacker, preserving the integrity of the research operations.

## 3. Technical Implementation
The system is built as a modular research platform:

*   **Backend**: Python (Flask) with a custom `Driver` wrapper for Selenium to handle complex auth flows (like GitHub's anti-bot protections).
*   **Data Layer**: SQLite with AES-256 encryption. We treat the data we find as toxic waste—it is encrypted at rest to ensure that the scanner itself does not become a leak source.
*   **Frontend**: A cyberpunk-styled "Neural Interface" (Vanilla JS + WebGL) designed to visualize data flow and worker status in real-time, moving away from dry log files to actionable intelligence.

## 4. Getting Started

### Prerequisites
*   Python 3.10+
*   Google Chrome (for the Selenium driver)
*   Git

### Installation (Local Research Mode)

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/thisistanishq/chronos.git
    cd chronos
    ```

2.  **Install Dependencies**
    ```bash
    pip install -r requirements-prod.txt
    ```

3.  **Start the Neural Console**
    ```bash
    cd src
    python server_production.py
    ```

4.  **Access the Dashboard**
    Navigate to `http://localhost:5050`.

### Authentication Note
CHRONOS requires a valid GitHub session to perform deep scans.
*   When you start a scan, if you aren't logged in, CHRONOS will open a browser window.
*   Log in to GitHub securely in that window.
*   CHRONOS will capture the session cookie locally (saved as `cookies.pkl`) and use it for subsequent requests.

## 5. Research & Citation
This codebase accompanies our research paper on "Automated Credential Risk Assessment in Open Source Supply Chains." If you use this tool for academic research, please cite the repository and the included `Paper.pdf`.

---
*Maintained by the CHRONOS Research Group.*
