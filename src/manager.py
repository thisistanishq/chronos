import os
import sqlite3
import json
import pickle
import logging
import sys
import time
from datetime import date
from selenium.common.exceptions import UnableToSetCookieException
from selenium.webdriver.common.by import By
from crypto import crypto  # [SECURITY] AES-256 Encryption

class DatabaseManager:
    # ... (Previous __init__)

    def __enter__(self):
        if not os.path.exists(self.db_filename):
            logging.info("⚡ ALLOCATING NEW DATABASE SECTOR: github.db")

        self.con = sqlite3.connect(self.db_filename)
        self.cur = self.con.cursor()

        self.cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='APIKeys'")
        if self.cur.fetchone() is None:
            logging.info("Creating table APIKeys")
            # Added key_hash
            self.cur.execute("CREATE TABLE APIKeys(apiKey, status, lastChecked, model_tier, risk_score, context_tag, first_found_at, revoked_at, repo_stars, repo_forks, snippet, is_dataset, key_hash)")
        else:
            # Migrations...
            # ... (Previous migrations)
            
            try:
                self.cur.execute("SELECT key_hash FROM APIKeys LIMIT 1")
            except sqlite3.OperationalError:
                logging.info("⚠️  MIGRATING DATABASE SCHEMA TO HASH-LOOKUP PROTOCOL...")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN key_hash")

        self.cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='URLs'")
        if self.cur.fetchone() is None:
            logging.info("Creating table URLs")
            self.cur.execute("CREATE TABLE URLs(url, key)")

        return self

    def _hash_key(self, api_key: str) -> str:
        """Deterministic SHA-256 hash for lookups."""
        return hashlib.sha256(api_key.encode()).hexdigest()

    def all_iq_keys(self) -> list:
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        # Return decrypted keys
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE status='insufficient_quota'")
        return [(crypto.decrypt_data(row[0]),) for row in self.cur.fetchall()]

    def all_keys(self) -> list:
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE status='yes'")
        return [(crypto.decrypt_data(row[0]),) for row in self.cur.fetchall()]
        
    def all_valid_keys_for_lifecycle(self) -> list:
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE status='yes' AND revoked_at IS NULL")
        return [(crypto.decrypt_data(row[0]),) for row in self.cur.fetchall()]

    def deduplicate(self) -> None:
        """
        Deduplicate the 'APIKeys' table based on key_hash.
        """
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
            
        # Group by hash instead of apiKey (since apiKey is random encrypted string)
        self.cur.execute("CREATE TABLE temp_table as SELECT apiKey, status, MAX(lastChecked) as lastChecked, model_tier, risk_score, context_tag, MIN(first_found_at) as first_found_at, revoked_at, repo_stars, repo_forks, snippet, is_dataset, key_hash FROM APIKeys GROUP BY key_hash;")
        self.cur.execute("DROP TABLE APIKeys;")
        self.cur.execute("ALTER TABLE temp_table RENAME TO APIKeys;")
        self.con.commit()

    def delete(self, api_key: str) -> None:
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
            
        # Delete by hash
        k_hash = self._hash_key(api_key)
        self.cur.execute("DELETE FROM APIKeys WHERE key_hash=?", (k_hash,))
        self.con.commit()
    
    def update_status(self, api_key: str, status: str, revoked_at: str | None = None):
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        
        # Update by hash
        k_hash = self._hash_key(api_key)
        today = date.today()
        if revoked_at:
             self.cur.execute("UPDATE APIKeys SET status=?, lastChecked=?, revoked_at=? WHERE key_hash=?", (status, today, revoked_at, k_hash))
        else:
             self.cur.execute("UPDATE APIKeys SET status=?, lastChecked=? WHERE key_hash=?", (status, today, k_hash))
        self.con.commit()

    def insert(self, api_key: str, status: str, model_tier: str = "Unknown", risk_score: int = 0, context_tag: str = "Unclassified", repo_stars: int = 0, repo_forks: int = 0, snippet: str = "", is_dataset: bool = False):
        if self.con is None:
            raise ValueError("Connection is not initialized")
        
        # [SECURITY] Encrypt + Hash
        encrypted_key = crypto.encrypt_data(api_key)
        k_hash = self._hash_key(api_key)
        
        today = date.today()
        from datetime import datetime
        now_ts = datetime.now().isoformat()
        
        self.cur.execute(
            "INSERT INTO APIKeys(apiKey, status, lastChecked, model_tier, risk_score, context_tag, first_found_at, revoked_at, repo_stars, repo_forks, snippet, is_dataset, key_hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (encrypted_key, status, today, model_tier, risk_score, context_tag, now_ts, None, repo_stars, repo_forks, snippet, is_dataset, k_hash)
        )
        self.con.commit()

        # Notify Server (send DECRYPTED/RAW for UI)
        try:
            import requests
            payload = {
                "key": f"{api_key[:10]}...{api_key[-6:]}" if len(api_key) > 20 else api_key,
                "full_key": api_key, 
                "status": status,
                "tier": model_tier,
                "risk": risk_score,
                "context": context_tag,
                "found_at": now_ts,
                "snippet": snippet,
                "stars": repo_stars,
                "forks": repo_forks
            }
            requests.post("http://127.0.0.1:5050/api/internal/key_found", json=payload, timeout=1.0)
        except:
            pass

    def key_exists(self, api_key: str) -> bool:
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        
        # Check by hash
        k_hash = self._hash_key(api_key)
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE key_hash=?", (k_hash,))
        return self.cur.fetchone() is not None

    def insert_url(self, url: str) -> None:
        pass
        
    def get_url(self, url: str) -> bool:
        return False

LOGGER_NAME = "Airtouch-Scanner"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt="[%X]")
logger = logging.getLogger(LOGGER_NAME)


class ProgressManagerError(Exception):
    """Custom exception for ProgressManager class errors"""

    def __init__(self, message):
        super().__init__(message)


class ProgressManager:
    """
    Manages and persists progress information for long-running operations.

    Attributes:
        progress_file (Path): Path to the progress file

    Methods:
        save: Saves current progress
        load: Loads saved progress
    """

    def __init__(self, progress_file=".progress.txt"):
        """
        Initialize the ProgressManager with a specified progress file.

        Args:
            progress_file (str): The file where progress data is stored.
        """
        self.progress_file = progress_file

    def save(self, from_iter: int, total: int):
        """
        Saves the current progress to a file.

        Args:
            from_iter (int): The current iteration progress.
            total (int): The total number of iterations.
        """
        with open(self.progress_file, "w", encoding="utf-8") as file:
            file.write(f"{from_iter}/{total}/{time.time()}")

    def load(self, total: int) -> int:
        """
        Loads the previously saved progress if available and valid.

        Args:
            total (int): The total number of iterations for the current process.

        Returns:
            int: The iteration number to continue from.
        """
        if not os.path.exists(self.progress_file):
            return 0

        with open(self.progress_file, "r", encoding="utf-8") as file:
            last_, totl_, tmst_ = file.read().strip().split("/")
            last, totl = int(last_), int(totl_)

        if time.time() - float(tmst_) < 3600 and totl == total:
            # AUTOMATIC RESUME: Continue from saved progress without prompting
            print(f"🔄 RESUMING FROM PREVIOUS PROGRESS ({last}/{totl})...")
            return last

        return 0


class CookieManager:
    """
    Manages browser cookie operations.

    Methods:
        save: Saves cookies to a file
        load: Loads cookies from a file
        verify_user_login: Checks if the user is currently logged in
    """

    def __init__(self, driver):
        """
        Initialize the CookieManager with a Selenium WebDriver instance.

        Args:
            driver (WebDriver): The Selenium WebDriver for cookie operations.
        """
        self.driver = driver

    def save(self):
        """
        Save cookies from the current browser session to a file.
        """
        cookies = self.driver.get_cookies()
        with open("cookies.pkl", "wb") as file:
            pickle.dump(cookies, file)
            logger.info("🍪 Cookies saved")

    def load(self):
        """
        Load cookies from a file and attempt to add them to the current browser session.
        """
        try:
            # Ensure we are on the right domain first
            if "github.com" not in self.driver.current_url:
                self.driver.get("https://github.com/404")

            cookie_file = "cookies.pkl"
            if not os.path.exists(cookie_file):
                # Check parent dir (if running from src/)
                parent_cookie = os.path.join("..", "cookies.pkl")
                if os.path.exists(parent_cookie):
                    cookie_file = parent_cookie

            with open(cookie_file, "rb") as file:
                cookies = pickle.load(file)
                for cookie in cookies:
                    try:
                        # Fix for SameSite attribute which can cause issues
                        if 'sameSite' in cookie:
                            if cookie['sameSite'] not in ["Strict", "Lax", "None"]:
                                del cookie['sameSite']

                        self.driver.add_cookie(cookie)
                    except Exception:
                        # Fallback: Try removing domain/expiry if strict check fails
                        try:
                            if 'domain' in cookie:
                                del cookie['domain']
                            if 'expiry' in cookie:
                                del cookie['expiry']
                            self.driver.add_cookie(cookie)
                        except Exception:
                            # If it still fails, just ignore this cookie
                            pass
                            
        except (EOFError, pickle.UnpicklingError, FileNotFoundError):
            if os.path.exists("cookies.pkl"):
                os.remove("cookies.pkl")
            logger.error("🔴 Error, unable to load cookies, invalid cookies has been removed, please restart.")

    def verify_user_login(self):
        """
        Test if the user is really logged in by navigating to GitHub and checking login status.
        """
        logger.info("👻 INITIATING GHOST PROTOCOL (Verifying Login)...")
        self.driver.get("https://github.com/")

        if self.driver.find_elements(by=By.XPATH, value="//*[contains(text(), 'Sign in')]"):
            if os.path.exists("cookies.pkl"):
                os.remove("cookies.pkl")
            logger.error("🛑 ACCESS DENIED. LOGIN REQUIRED. TERMINATING.")
            sys.exit(1)
        return True


class DatabaseManager:
    """
    This class is used to manage the database, including creating tables and handling data interactions.
    """

    def __init__(self, db_filename: str):
        """
        Initialize the DatabaseManager with the specified database filename.

        Args:
            db_filename (str): Path to the SQLite database file.
        """
        self.db_filename = db_filename
        self.con = None
        self.cur = None

    def __enter__(self):
        """
        Enter the runtime context related to this object, initializing the database if needed.
        """
        if not os.path.exists(self.db_filename):
            logging.info("⚡ ALLOCATING NEW DATABASE SECTOR: github.db")

        self.con = sqlite3.connect(self.db_filename)
        self.cur = self.con.cursor()

        self.cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='APIKeys'")
        if self.cur.fetchone() is None:
            logging.info("Creating table APIKeys")
            self.cur.execute("CREATE TABLE APIKeys(apiKey, status, lastChecked, model_tier, risk_score, context_tag, first_found_at, revoked_at, repo_stars, repo_forks, snippet)")
        else:
            # Migration check: If columns missing, add them (simplified for this context)
            try:
                self.cur.execute("SELECT repo_stars FROM APIKeys LIMIT 1")
            except sqlite3.OperationalError:
                logging.info("⚠️  MIGRATING DATABASE SCHEMA TO FORENSICS PROTOCOL...")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN repo_stars")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN repo_forks")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN snippet")

            try:
                self.cur.execute("SELECT first_found_at FROM APIKeys LIMIT 1")
            except sqlite3.OperationalError:
                logging.info("⚠️  MIGRATING DATABASE SCHEMA TO CHRONOS PROTOCOL...")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN first_found_at")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN revoked_at")
                # Backfill existing keys found date to today (or unknown)
                today = date.today().isoformat()
                self.cur.execute("UPDATE APIKeys SET first_found_at = ? WHERE first_found_at IS NULL", (today,))
            
            try:
                self.cur.execute("SELECT model_tier FROM APIKeys LIMIT 1")
            except sqlite3.OperationalError:
                logging.info("⚠️  MIGRATING DATABASE SCHEMA TO RESEARCH PROTOCOL...")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN model_tier")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN risk_score")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN context_tag")
            
            try:
                self.cur.execute("SELECT is_dataset FROM APIKeys LIMIT 1")
            except sqlite3.OperationalError:
                logging.info("⚠️  MIGRATING DATABASE SCHEMA TO DATASET FORENSICS PROTOCOL...")
                self.cur.execute("ALTER TABLE APIKeys ADD COLUMN is_dataset BOOLEAN DEFAULT 0")


        self.cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='URLs'")
        if self.cur.fetchone() is None:
            logging.info("Creating table URLs")
            self.cur.execute("CREATE TABLE URLs(url, key)")

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """
        Exit the runtime context and close the database connection.
        """
        if self.con:
            self.con.close()

    def all_iq_keys(self) -> list:
        """
        Get all keys with the status 'insufficient_quota'.

        Returns:
            list: A list of tuples containing API keys.
        """
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE status='insufficient_quota'")
        return self.cur.fetchall()

    def all_keys(self) -> list:
        """
        Get all keys with the status 'yes'.

        Returns:
            list: A list of tuples containing API keys.
        """
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE status='yes'")
        return self.cur.fetchall()
        
    def all_valid_keys_for_lifecycle(self) -> list:
        """
        Get all keys that are currently valid (status='yes') and NOT revoked.
        For the lifecycle monitor.
        """
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE status='yes' AND revoked_at IS NULL")
        return self.cur.fetchall()

    def deduplicate(self) -> None:
        """
        Deduplicate the 'APIKeys' table by retaining only the latest record for each key.
        """
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        # Updated deduplication for new schema
        self.cur.execute("CREATE TABLE temp_table as SELECT apiKey, status, MAX(lastChecked) as lastChecked, model_tier, risk_score, context_tag, MIN(first_found_at) as first_found_at, revoked_at, repo_stars, repo_forks, snippet FROM APIKeys GROUP BY apiKey;")
        self.cur.execute("DROP TABLE APIKeys;")
        self.cur.execute("ALTER TABLE temp_table RENAME TO APIKeys;")
        self.con.commit()

    def delete(self, api_key: str) -> None:
        """
        Delete a specific API key from the database.

        Args:
            api_key (str): The unique API key to remove.
        """
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("DELETE FROM APIKeys WHERE apiKey=?", (api_key,))
        self.con.commit()
    
    def update_status(self, api_key: str, status: str, revoked_at: str | None = None):
        """
        Update just the status (and revoked_at) of a key without deleting/reinserting.
        Used by Lifecycle Monitor.
        """
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        
        today = date.today()
        if revoked_at:
             self.cur.execute("UPDATE APIKeys SET status=?, lastChecked=?, revoked_at=? WHERE apiKey=?", (status, today, revoked_at, api_key))
        else:
             self.cur.execute("UPDATE APIKeys SET status=?, lastChecked=? WHERE apiKey=?", (status, today, api_key))
        self.con.commit()

    def insert(self, api_key: str, status: str, model_tier: str = "Unknown", risk_score: int = 0, context_tag: str = "Unclassified", repo_stars: int = 0, repo_forks: int = 0, snippet: str = "", is_dataset: bool = False):
        """
        Insert a new API key and status into the database.

        Args:
            api_key (str): The API key to insert.
            status (str): The status of the API key.
            model_tier (str): The clearance level of the key.
            risk_score (int): Contextual risk score 0-100.
            context_tag (str): Context description.
            repo_stars (int): Repository stars.
            repo_forks (int): Repository forks.
            snippet (str): Code snippet.
            is_dataset (bool): Whether it was found in a dataset file.
        """
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        today = date.today()
        from datetime import datetime
        now_ts = datetime.now().isoformat()
        
        self.cur.execute(
            "INSERT INTO APIKeys(apiKey, status, lastChecked, model_tier, risk_score, context_tag, first_found_at, revoked_at, repo_stars, repo_forks, snippet, is_dataset) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (api_key, status, today, model_tier, risk_score, context_tag, now_ts, None, repo_stars, repo_forks, snippet, is_dataset)
        )
        self.con.commit()

        # REAL-TIME SIGNAL: Notify Server
        try:
            import requests
            payload = {
                "key": f"{api_key[:10]}...{api_key[-6:]}" if len(api_key) > 20 else api_key,
                "full_key": api_key,
                "status": status,
                "tier": model_tier,
                "risk": risk_score,
                "context": context_tag,
                "found_at": now_ts,
                "snippet": snippet,
                "stars": repo_stars,
                "forks": repo_forks
            }
            # Timeout is tiny to prevent blocking worker flow
            requests.post("http://127.0.0.1:5050/api/internal/key_found", json=payload, timeout=1.0)
        except:
            pass # Fire and forget, don't crash worker on notify fail

    def key_exists(self, api_key: str) -> bool:
        """
        Check if a given API key exists in the database.

        Args:
            api_key (str): The API key to search for.

        Returns:
            bool: True if the API key exists, False otherwise.
        """
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("SELECT apiKey FROM APIKeys WHERE apiKey=?", (api_key,))
        return self.cur.fetchone() is not None

    def insert_url(self, url: str) -> None:
        """
        Insert a new URL into the 'URLs' table.

        Args:
            url (str): The URL to add.
        """
        if self.con is None:
            raise ValueError("Connection is not initialized")
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("INSERT INTO URLs(url, key) VALUES(?, ?)", (url, 1))
        self.con.commit()

    def get_url(self, url: str) -> str | None:
        """
        Retrieve the 'key' associated with the given URL.

        Args:
            url (str): The URL to look up.

        Returns:
            str | None: The key if it exists, None if not.
        """
        if self.cur is None:
            raise ValueError("Cursor is not initialized")
        self.cur.execute("SELECT key FROM URLs WHERE url=?", (url,))
        fetch = self.cur.fetchone()
        return fetch[0] if fetch else None
