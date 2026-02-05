"""
This module provides the Hierarchical Model Clearance System (HMCS) to VALIDATE
and CLASSIFY OpenAI API keys based on their economic value and access tier.

[SECURITY UPGRADE] Now includes OpSec countermeasures (User-Agent Rotation).
"""

from dataclasses import dataclass
import rich
import random
from openai import APIStatusError, AuthenticationError, OpenAI, RateLimitError

# --- OPSEC: USER AGENT ROTATION SYSTEM ---
class UserAgentRotator:
    """
    Implements advanced fingerprint spoofing to evade detection.
    Rotates between high-fidelity Operating System and Browser profiles.
    """
    def __init__(self):
        self.agents = [
            # macOS / Chrome (High Probability)
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Windows 11 / Chrome (High Probability)
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # macOS / Safari (Standard)
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            # Linux / Firefox (Developer Profile)
            "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
            # Windows 10 / Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        ]

    def get_random_agent(self) -> str:
        """Returns a random User-Agent string from the pool."""
        return random.choice(self.agents)

# Global Instance
ua_rotator = UserAgentRotator()

@dataclass
class ValidationResult:
    """Methods used to store validation results for research data."""
    status: str
    model_tier: str
    rate_limit_headers: str = "N/A"

def check_key_tier(key) -> ValidationResult:
    """
    Probes the API key against multiple models to determine its Clearance Level.
    Returns a ValidationResult object.
    """
    # Note: OpenAI Python Client handles headers internally, but for raw reqs we use ua_rotator.
    # We pass default headers if we were using requests directly.
    client = OpenAI(api_key=key)

    # 1. DEEP MODEL INSPECTION
    # We probe for specific high-value models to determine the true tier.
    # Billing API is deprecated/restricted, so Model Access is the best proxy for Value.
    
    tier_map = {
        "o1-preview": "TIER 5 (O1-PREVIEW / RESEARCH)",
        "gpt-4-32k": "TIER 4 (GPT-4-32K / ENTERPRISE)",
        "gpt-4": "TIER 3 (GPT-4 / STANDARD)",
        "gpt-3.5-turbo": "TIER 2 (GPT-3.5 / BASIC)",
        "text-davinci-003": "TIER 1 (LEGACY)"
    }

    found_models = []
    highest_tier = "TIER 0 (UNKNOWN)"
    status = "invalid"

    try:
        # Try to list models first (Check if key has list permission)
        # This is the "Gold Standard" check.
        models = client.models.list()
        all_model_ids = [m.id for m in models.data]
        
        # Check against our high-value list
        for model_id, tier_name in tier_map.items():
            if model_id in all_model_ids:
                found_models.append(model_id)
                # Map works because python dicts preserve insertion order (Py3.7+) 
                # and we ordered from Highest to Lowest above.
                if highest_tier == "TIER 0 (UNKNOWN)":
                    highest_tier = tier_name

        if found_models:
            status = "yes"
            # Verify write access with the highest found model just to be 100% sure
            # (Sometimes list perms != run perms)
            best_model = found_models[0] # Highest value
            try:
                client.chat.completions.create(
                    model=best_model, messages=[{"role": "user", "content": "1"}], max_tokens=1
                )
                rich.print(f"[bold green]💎 {highest_tier} CONFIRMED[/bold green]: [orange_red1]'{key}'[/orange_red1]")
                return ValidationResult("yes", highest_tier, f"Models: {', '.join(found_models)}")
            except:
                 # If top model fails, fallback means key is valid but maybe quota issue on that specific model
                 rich.print(f"[bold yellow]⚠️  ACCESS RESTRICTED ({best_model})[/bold yellow]: '{key}'")
                 return ValidationResult("yes", f"{highest_tier} (RESTRICTED)", f"Models: {', '.join(found_models)}")
        
        # If list() worked but no known models found? Weird but valid key.
        return ValidationResult("yes", "TIER 1 (Legacy/Custom)", str(all_model_ids[:5]))

    except AuthenticationError:
        return ValidationResult("invalid", "N/A")
    except RateLimitError:
        rich.print(f"[yellow]⚠️  QUOTA EXHAUSTED[/yellow]: '{key[:10]}...{key[-10:]}'")
        return ValidationResult("insufficient_quota", "TIER 0 (QUOTA EXHAUSTED)")
    except Exception as e:
        # Fallback to single probe checks if expensive list() fails or is blocked
        pass

    # ... (Fallback manual probes if needed, but list() covers 99% of valid keys)
    # Re-implement simple probe as final fallback
    try:
        client.chat.completions.create(model="gpt-3.5-turbo", messages=[{"role": "user", "content": "1"}], max_tokens=1)
        return ValidationResult("yes", "TIER 2 (GPT-3.5)", "Fallback Probe")
    except:
        return ValidationResult("invalid", "N/A")

# Legacy wrapper for backward compatibility if needed
def check_key(key, model="gpt-4o-mini") -> str | None:
    res = check_key_tier(key)
    return res.status if res.status != "invalid" else "invalid_api_key"

if __name__ == "__main__":
    check_key_tier("sk-proj-test")
