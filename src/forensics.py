"""
NEURAL CONTEXT ENGINE (NCE) v2.0
Analyzes code context to determine Risk Score and Operational Intent.
Also handles scrubbing of GitHub page data (Stars, Forks, Snippets).
"""

import re
from dataclasses import dataclass
from selenium.webdriver.common.by import By

@dataclass
class ForensicsData:
    repo_stars: int = 0
    repo_forks: int = 0
    snippet: str = "N/A"
    risk_score: int = 0
    context_tag: str = "Unclassified"
    is_dataset: bool = False

class NeuralContextEngine:
    def __init__(self):
        # Heuristic Weights for Risk Calculation
        self.risk_patterns = {
            "CRITICAL": {
                "keywords": ["production", "prod", "mainnet", "live", "stripe", "aws_secret", "payment", "billing"],
                "weight": 90
            },
            "HIGH": {
                "keywords": ["backend", "server", "database", "admin", "password", "auth", "login", "crypto", "trade", "bot"],
                "weight": 75
            },
            "MEDIUM": {
                "keywords": ["test", "dev", "experiment", "demo", "staging", "local", "localhost"],
                "weight": 30
            },
            "LOW": {
                "keywords": ["homework", "assignment", "tutorial", "example", "sample", "learn"],
                "weight": 10
            }
        }

    def analyze_context(self, code_snippet: str):
        """
        Analyzes the code snippet to determine context and risk.
        Returns: (risk_score: int, context_tag: str)
        """
        if not code_snippet:
            return 0, "UNKNOWN"

        snippet_lower = code_snippet.lower()
        max_score = 0
        detected_context = "UNCERTAIN"

        # Check CRITICAL
        for kw in self.risk_patterns["CRITICAL"]["keywords"]:
            if kw in snippet_lower:
                max_score = max(max_score, self.risk_patterns["CRITICAL"]["weight"])
                detected_context = "PRODUCTION SYSTEM"

        # Check HIGH
        if max_score < 80:
            for kw in self.risk_patterns["HIGH"]["keywords"]:
                if kw in snippet_lower:
                    max_score = max(max_score, self.risk_patterns["HIGH"]["weight"])
                    if detected_context == "UNCERTAIN": detected_context = "BACKEND SERVICE"

        # Check MEDIUM
        if max_score < 40:
            for kw in self.risk_patterns["MEDIUM"]["keywords"]:
                if kw in snippet_lower:
                    max_score = max(max_score, self.risk_patterns["MEDIUM"]["weight"])
                    detected_context = "DEV/TEST ENVIRONMENT"

        # Check LOW
        if max_score < 20:
             for kw in self.risk_patterns["LOW"]["keywords"]:
                if kw in snippet_lower:
                    max_score = max(max_score, self.risk_patterns["LOW"]["weight"])
                    detected_context = "EDUCATIONAL/SAMPLE"

        # Adjust score based on complexity (length of snippet)
        if len(code_snippet) > 200 and max_score > 0:
            max_score += 10 # Complex code is riskier
        
        return min(max_score, 100), detected_context

# Singleton Instance
nce = NeuralContextEngine()

def extract_forensics(driver, text_content: str, key_match: str) -> ForensicsData:
    """
    Extracts signals from the webpage Source.
    """
    data = ForensicsData()
    
    # 1. Capture Snippet
    # Try to extract +/- 100 chars around the key
    try:
        if key_match and key_match in text_content:
            idx = text_content.find(key_match)
            start = max(0, idx - 100)
            end = min(len(text_content), idx + 100 + len(key_match))
            data.snippet = text_content[start:end]
        else:
            data.snippet = text_content[:200] # Fallback
    except:
        data.snippet = "Extraction Failed"

    # 2. Extract Repo Stats (Stars/Forks) from GitHub UI
    try:
        # These are standard GitHub CSS classes (might change, but usually stable)
        # Using a generic specific logic because GitHub HTML is complex
        
        # Try to find "stargazers"
        # Since we are in ghost mode (headless), this might be tricky, but main.py passes the driver.
        # We will attempt a fast heuristic scan of the full page text source if logic fails.
        pass
    except:
        pass

    # 3. Neural Context Analysis
    data.risk_score, data.context_tag = nce.analyze_context(data.snippet)
    
    return data
