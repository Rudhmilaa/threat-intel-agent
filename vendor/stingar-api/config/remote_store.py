"""
Remote store configuration management.
"""

import os
import logging
from typing import Dict, Any, Optional
from configparser import ConfigParser
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)


class RemoteStoreConfig:
    """
    Configuration manager for remote store settings.
    """
    
    def __init__(self, config_file: str = None):
        """
        Initialize configuration.
        
        :param config_file: Path to config file (optional)
        """
        self.config_file = config_file or self._get_default_config_path()
        self.config = ConfigParser()
        self._load_config()
        self._load_env_file()
    
    def _get_default_config_path(self) -> str:
        """Get default config file path."""
        return str(Path(__file__).parent.parent.parent / 'configs' / 'remote_store.ini')
    
    def _load_config(self):
        """Load configuration from file and environment variables."""
        # Load from file if it exists
        if Path(self.config_file).exists():
            self.config.read(self.config_file)
        
        # Ensure REMOTE_STORE section exists
        if not self.config.has_section('REMOTE_STORE'):
            self.config.add_section('REMOTE_STORE')

    def _load_env_file(self):
        """Load environment variables from stingar.env file."""
        # Try to load from stingar.env file
        env_file_paths = [
            Path(__file__).parent.parent.parent / 'stingar.env',  # apiarist/stingar.env
            Path('/app/stingar.env'),  # Docker container path
            Path('./stingar.env'),  # Current directory
        ]
        
        for env_path in env_file_paths:
            if env_path.exists():
                # Overwrite=True ensures new values override existing ones
                load_dotenv(env_path, override=True)
                logger = logging.getLogger(__name__)
                logger.debug(f"Loaded environment variables from {env_path}")
                break
    
    def get(self, key: str, default: str = None) -> str:
        """
        Get configuration value with environment variable override.
        Priority: stingar.env > environment variables > config file > default
        
        :param key: Configuration key
        :param default: Default value if not found
        :return: Configuration value
        """
        # Reload env file to ensure we have latest values (especially after API key updates)
        self._load_env_file()
        
        # Check environment variable first (includes stingar.env)
        env_key = f"REMOTE_STORE_{key}"
        env_value = os.getenv(env_key)
        
        # Also check by reading stingar.env directly (more reliable than os.getenv after file changes)
        if not env_value or env_value.strip() == '':
            try:
                # Read stingar.env directly to avoid circular import
                env_file_paths = [
                    Path(__file__).parent.parent.parent / 'stingar.env',  # apiarist/stingar.env
                    Path('/app/stingar.env'),  # Docker container path
                    Path('./stingar.env'),  # Current directory
                ]
                
                for env_path in env_file_paths:
                    if env_path.exists():
                        env_vars = {}
                        with open(env_path, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#') and '=' in line:
                                    key, value = line.split('=', 1)
                                    key = key.strip()
                                    value = value.strip()
                                    # Skip commented out values and empty values
                                    if value.startswith('#') or not value:
                                        continue
                                    env_vars[key] = value
                        
                        direct_value = env_vars.get(env_key)
                        if direct_value and direct_value.strip() != '':
                            # Update os.environ so future calls use the correct value
                            os.environ[env_key] = direct_value
                            logger.debug(f"Read {env_key} directly from {env_path}: {direct_value[:10]}...")
                            return direct_value
                        break
            except Exception as e:
                logger.debug(f"Could not read stingar.env directly: {e}")
        
        if env_value is not None and env_value.strip() != '':
            return env_value
        
        # Fall back to config file
        try:
            return self.config.get('REMOTE_STORE', key)
        except:
            return default
    
    def get_int(self, key: str, default: int = 0) -> int:
        """Get integer configuration value."""
        try:
            return int(self.get(key, str(default)))
        except (ValueError, TypeError):
            return default
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean configuration value."""
        value = self.get(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get all configuration values.
        
        WARNING: This method returns sensitive data including API keys.
        When logging configuration, always use safe_log_config() from resources.store
        to mask sensitive values.
        """
        # Get API key with enhanced logging
        api_key = self.get('API_KEY', '')
        if not api_key or api_key.strip() == '':
            logger.warning("API_KEY is empty after get() call, attempting direct file read")
            # Try direct file read as last resort
            try:
                env_file_paths = [
                    Path('/app/stingar.env'),  # Docker container path
                    Path(__file__).parent.parent.parent / 'stingar.env',  # apiarist/stingar.env
                    Path('./stingar.env'),  # Current directory
                ]
                
                for env_path in env_file_paths:
                    if env_path.exists():
                        logger.info(f"Reading API key directly from {env_path}")
                        env_vars = {}
                        with open(env_path, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#') and '=' in line:
                                    key, value = line.split('=', 1)
                                    key = key.strip()
                                    value = value.strip()
                                    # Include empty values so we can detect if key exists but is empty
                                    if value.startswith('#'):
                                        continue
                                    # Include the key even if value is empty (to detect empty vs missing)
                                    env_vars[key] = value
                        
                        direct_api_key = env_vars.get('REMOTE_STORE_API_KEY', '')
                        if direct_api_key and direct_api_key.strip() != '':
                            logger.info(f"Found API key in file: {direct_api_key[:10]}...")
                            # Update os.environ for future calls
                            os.environ['REMOTE_STORE_API_KEY'] = direct_api_key
                            api_key = direct_api_key
                        elif 'REMOTE_STORE_API_KEY' in env_vars:
                            # Key exists but is empty - instance needs to register
                            logger.warning(f"REMOTE_STORE_API_KEY exists in {env_path} but is empty. Instance needs to register with HP App Store.")
                        else:
                            logger.warning(f"REMOTE_STORE_API_KEY not found in {env_path}. Available REMOTE_STORE_ keys: {[k for k in env_vars.keys() if k.startswith('REMOTE_STORE_')]}")
                        break
            except Exception as e:
                logger.error(f"Failed to read API key directly from file: {e}", exc_info=True)
        
        return {
            'base_url': self.get('BASE_URL', 'https://store.4warned.io'),
            'api_key': api_key,  # Use the potentially updated api_key
            'timeout': self.get_int('TIMEOUT', 30),
            'enabled': self.get_bool('ENABLED', True),
            'sync_interval': self.get_int('SYNC_INTERVAL', 3600),
            'auto_sync': self.get_bool('AUTO_SYNC', True),
            'retry_attempts': self.get_int('RETRY_ATTEMPTS', 3),
            'retry_delay': self.get_int('RETRY_DELAY', 5),
            # Removed unused variables:
            # - auth_enabled, auth_type, auth_token (code always uses API key auth)
            # - connect_timeout, read_timeout (httpx uses single timeout)
            # - max_retries (redundant with retry_attempts)
            # - log_level, log_requests (logging configured globally)
        }

    def get_env_file_path(self) -> Optional[str]:
        """Get the path to the stingar.env file if it exists."""
        env_file_paths = [
            Path(__file__).parent.parent.parent / 'stingar.env',  # apiarist/stingar.env
            Path('/app/stingar.env'),  # Docker container path
            Path('./stingar.env'),  # Current directory
        ]
        
        for env_path in env_file_paths:
            if env_path.exists():
                return str(env_path)
        return None


# Global configuration instance
remote_store_config = RemoteStoreConfig() 