"""
Store configuration resource for managing stingar.env settings.

Provides endpoints to read and update configuration values from stingar.env file,
specifically for HP App Store registration and API key management.
"""

import os
import logging
import falcon
from typing import Dict, Any

logger = logging.getLogger(__name__)


def get_stingar_env_path() -> str:
    """Get the path to the stingar.env file.
    
    Checks multiple locations in order of priority:
    1. Docker container path (/app/stingar.env) - most common in production
    2. Environment variable STINGAR_ENV_PATH if set
    3. Project root relative to this file
    4. Current directory
    """
    # Priority 1: Docker container path (most common in production)
    docker_paths = [
        '/app/stingar.env',  # Standard Docker container path
        '/app/stingar.env',  # Apiarist container path
    ]
    
    for docker_path in docker_paths:
        if os.path.exists(docker_path):
            logger.debug(f"Found stingar.env at Docker path: {docker_path}")
            return docker_path
    
    # Priority 2: Environment variable override
    env_path = os.getenv('STINGAR_ENV_PATH')
    if env_path and os.path.exists(env_path):
        logger.debug(f"Found stingar.env at STINGAR_ENV_PATH: {env_path}")
        return env_path
    
    # Priority 3: Project root relative to this file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    apiarist_dir = os.path.dirname(current_dir)  # Go up from resources/
    project_root = os.path.dirname(apiarist_dir)  # Go up from apiarist/
    project_path = os.path.join(project_root, 'stingar.env')
    if os.path.exists(project_path):
        logger.debug(f"Found stingar.env at project root: {project_path}")
        return project_path
    
    # Priority 4: Current directory (fallback)
    current_dir_path = os.path.join(os.getcwd(), 'stingar.env')
    if os.path.exists(current_dir_path):
        logger.debug(f"Found stingar.env at current directory: {current_dir_path}")
        return current_dir_path
    
    # Default: return Docker path if in container, otherwise project root
    # This allows creating the file if it doesn't exist
    if os.path.exists('/app'):
        logger.debug("Using Docker container path for new file: /app/stingar.env")
        return '/app/stingar.env'
    else:
        logger.debug(f"Using project root path for new file: {project_path}")
        return project_path


def read_stingar_env() -> Dict[str, str]:
    """Read all environment variables from stingar.env file."""
    env_file_path = get_stingar_env_path()
    env_vars = {}
    file_modified = False
    keys_found = set()
    
    if os.path.exists(env_file_path):
        try:
            with open(env_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        # Track that this key exists in the file (even if empty or commented)
                        keys_found.add(key)
                        # Skip if value starts with # (commented out value like "#your-api-key")
                        if value.startswith('#'):
                            continue
                        # Include empty values so we can check if key exists
                        env_vars[key] = value
        except Exception as e:
            logger.error(f"Error reading stingar.env file: {e}")
    else:
        # File doesn't exist, we'll create it with required variables
        logger.debug(f"stingar.env file not found at {env_file_path}, will create it")
        file_modified = True
    
    # Ensure REMOTE_STORE_API_KEY exists (create if missing)
    if 'REMOTE_STORE_API_KEY' not in keys_found:
        logger.debug("REMOTE_STORE_API_KEY not found in stingar.env, creating it")
        if 'REMOTE_STORE_API_KEY' not in env_vars:
            env_vars['REMOTE_STORE_API_KEY'] = ''
        file_modified = True
    
    # Ensure REMOTE_STORE_ENABLED exists (create if missing)
    if 'REMOTE_STORE_ENABLED' not in keys_found:
        logger.debug("REMOTE_STORE_ENABLED not found in stingar.env, creating it")
        if 'REMOTE_STORE_ENABLED' not in env_vars:
            env_vars['REMOTE_STORE_ENABLED'] = 'true'
        file_modified = True
    
    # Ensure REMOTE_STORE_BASE_URL exists (create if missing)
    if 'REMOTE_STORE_BASE_URL' not in keys_found:
        logger.debug("REMOTE_STORE_BASE_URL not found in stingar.env, creating it")
        if 'REMOTE_STORE_BASE_URL' not in env_vars:
            env_vars['REMOTE_STORE_BASE_URL'] = 'https://store.4warned.io'
        file_modified = True
    
    # Write back to file if we added missing variables
    if file_modified:
        try:
            # Read all existing vars first to preserve them
            if os.path.exists(env_file_path):
                with open(env_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            # Preserve existing values (don't overwrite)
                            if key not in env_vars and not value.startswith('#'):
                                env_vars[key] = value
            
            write_stingar_env(env_vars)
            logger.debug("Updated stingar.env with missing REMOTE_STORE_ variables")
        except Exception as e:
            logger.warning(f"Could not write missing variables to stingar.env: {e}")
    
    return env_vars


def write_stingar_env(env_vars: Dict[str, str]) -> None:
    """Write environment variables to stingar.env file."""
    env_file_path = get_stingar_env_path()
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(env_file_path), exist_ok=True)
        
        with open(env_file_path, 'w') as f:
            # Write REMOTE_STORE variables first
            f.write("# Remote Store Configuration\n")
            f.write("# HP_AppStore connection settings\n")
            for key in sorted(env_vars.keys()):
                if key.startswith('REMOTE_STORE_'):
                    f.write(f"{key}={env_vars[key]}\n")
            
            # Write other variables
            f.write("\n# Other Configuration\n")
            for key in sorted(env_vars.keys()):
                if not key.startswith('REMOTE_STORE_'):
                    f.write(f"{key}={env_vars[key]}\n")
        
        # Set file permissions: owner and group read/write, others read (664)
        # This allows group access which is often needed in Docker/container environments
        os.chmod(env_file_path, 0o664)
        logger.debug(f"Set permissions on {env_file_path} to 664 (rw-rw-r--)")
    except Exception as e:
        logger.error(f"Error writing stingar.env file: {e}")
        raise


class StoreConfigResource(object):
    """Resource for managing store configuration from stingar.env."""
    
    def on_get(self, req, resp):
        """Get configuration from stingar.env file."""
        try:
            config = read_stingar_env()
            
            # Return only non-sensitive config values
            # Include API key presence (but not the actual key value) for registration checks
            api_key = config.get('REMOTE_STORE_API_KEY', '')
            safe_config = {
                'INSTITUTION_NAME': config.get('INSTITUTION_NAME', ''),
                'institution_name': config.get('INSTITUTION_NAME', ''),  # Alias for compatibility
                'FLUENTD_REMOTE_HOST': config.get('FLUENTD_REMOTE_HOST', ''),
                'fluentd_remote_host': config.get('FLUENTD_REMOTE_HOST', ''),  # Alias for compatibility
                'CONTACT_EMAIL': config.get('CONTACT_EMAIL', ''),
                'contact_email': config.get('CONTACT_EMAIL', ''),  # Alias for compatibility
                'REMOTE_STORE_BASE_URL': config.get('REMOTE_STORE_BASE_URL', 'https://store.4warned.io'),
                'REMOTE_STORE_ENABLED': config.get('REMOTE_STORE_ENABLED', 'true'),
                'REMOTE_STORE_API_KEY': api_key if api_key else '',  # Return empty string if not set (for checking presence)
                'remote_store_api_key': api_key if api_key else ''  # Alias for compatibility
            }
            
            resp.status = falcon.HTTP_200
            resp.media = safe_config
            
        except Exception as e:
            logger.error(f"Error reading config: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.media = {"error": str(e)}


class StoreConfigAPIKeyResource(object):
    """Resource for storing API key in stingar.env file."""
    
    def on_post(self, req, resp):
        """Store API key in stingar.env file."""
        try:
            data = req.media
            api_key = data.get('api_key')
            
            if not api_key:
                resp.status = falcon.HTTP_400
                resp.media = {"error": "api_key is required"}
                return
            
            # Validate API key format (HP App Store keys start with hp_ak_)
            if not api_key.startswith('hp_ak_'):
                resp.status = falcon.HTTP_400
                resp.media = {"error": "Invalid API key format. Expected format: hp_ak_..."}
                return
            
            # Read existing env vars
            env_vars = read_stingar_env()
            
            # Update REMOTE_STORE_API_KEY
            env_vars['REMOTE_STORE_API_KEY'] = api_key
            env_vars['REMOTE_STORE_ENABLED'] = 'true'
            if 'REMOTE_STORE_BASE_URL' not in env_vars:
                env_vars['REMOTE_STORE_BASE_URL'] = 'https://store.4warned.io'
            
            # Write back to file
            write_stingar_env(env_vars)
            
            # Reload remote store config so Apiarist picks up the new API key
            try:
                from config.remote_store import remote_store_config
                # Reload the environment file to pick up the new API key
                remote_store_config._load_env_file()
                # Verify the API key was loaded
                loaded_key = remote_store_config.get('API_KEY', '')
                if loaded_key and loaded_key.startswith('hp_ak_'):
                    logger.info(f"Remote store config reloaded successfully. API key present: {loaded_key[:10]}...")
                else:
                    logger.warning(f"Remote store config reloaded but API key appears invalid or empty: {loaded_key[:20] if loaded_key else 'empty'}")
            except Exception as reload_error:
                logger.warning(f"Failed to reload remote store config: {reload_error}")
                # Continue anyway - the API key is stored and will be picked up on next restart
            
            logger.info("API key stored successfully in stingar.env")
            
            resp.status = falcon.HTTP_200
            resp.media = {
                "success": True,
                "message": "API key stored successfully",
                "config_file": get_stingar_env_path()
            }
            
        except Exception as e:
            logger.error(f"Error storing API key: {e}")
            resp.status = falcon.HTTP_500
            resp.media = {"error": str(e)}


class StoreRegistrationResource(object):
    """Resource for proxying instance registration to HP App Store."""
    
    def on_post(self, req, resp):
        """Proxy registration request to HP App Store."""
        try:
            import httpx
            from config.remote_store import remote_store_config
            
            # Get HP App Store base URL
            config = remote_store_config.get_all()
            base_url = config.get('base_url', 'https://store.4warned.io')
            
            # Get request data
            try:
                request_data = req.media
            except:
                request_data = {}
            
            # Proxy request to HP App Store (no API key needed for registration)
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Make request to HP App Store registration endpoint
            registration_url = f"{base_url}/api/v2/auth/register-instance"
            logger.info(f"Proxying registration request to {registration_url}")
            
            with httpx.Client(timeout=30.0) as client:
                response = client.post(
                    registration_url,
                    json=request_data,
                    headers=headers
                )
                
                # Forward response
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                try:
                    resp.media = response.json()
                except:
                    resp.text = response.text
                    
        except Exception as e:
            logger.error(f"Error proxying registration request: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.media = {"error": str(e)}

