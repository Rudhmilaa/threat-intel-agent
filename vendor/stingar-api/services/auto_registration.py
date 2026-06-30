"""
Automatic instance registration service for HP App Store.

This service automatically registers the STINGAR instance with HP App Store
on startup if no API key is present. The UI doesn't need to know about
registration - it just checks if the store is available.
"""

import os
import logging
import httpx
from typing import Optional, Dict, Any
from pathlib import Path
from resources.store_config import read_stingar_env, write_stingar_env, get_stingar_env_path
from config.remote_store import remote_store_config

logger = logging.getLogger(__name__)


def get_instance_identifier() -> Dict[str, str]:
    """
    Get instance identifier for registration.
    Priority: INSTITUTION_NAME > FLUENTD_REMOTE_HOST > domain > IP
    
    :return: Dictionary with identifier, type, and name
    """
    env_vars = read_stingar_env()
    
    # Priority 1: INSTITUTION_NAME
    institution_name = env_vars.get('INSTITUTION_NAME', '')
    if institution_name:
        return {
            'instance_identifier': institution_name.lower().replace(' ', '_').replace('-', '_'),
            'identifier_type': 'institution_name',
            'instance_name': institution_name
        }
    
    # Priority 2: FLUENTD_REMOTE_HOST (extract hostname)
    fluentd_remote_host = env_vars.get('FLUENTD_REMOTE_HOST', '')
    if fluentd_remote_host:
        hostname = fluentd_remote_host.split(':')[0]
        return {
            'instance_identifier': hostname.lower().replace('.', '_'),
            'identifier_type': 'domain_name',
            'instance_name': hostname
        }
    
    # Priority 3: Try to get hostname from system
    try:
        import socket
        hostname = socket.gethostname()
        if hostname and hostname != 'localhost':
            return {
                'instance_identifier': hostname.lower().replace('.', '_'),
                'identifier_type': 'domain_name',
                'instance_name': hostname
            }
    except:
        pass
    
    # Last resort: use IP address
    try:
        import socket
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return {
            'instance_identifier': ip.replace('.', '_'),
            'identifier_type': 'ip_address',
            'instance_name': f'STINGAR Instance ({ip})'
        }
    except:
        return {
            'instance_identifier': 'unknown',
            'identifier_type': 'ip_address',
            'instance_name': 'Unknown STINGAR Instance'
        }


def auto_register_instance(force_refresh: bool = False) -> Optional[str]:
    """
    Automatically register this STINGAR instance with HP App Store if no API key exists.
    Also handles expired API key refresh when force_refresh=True.
    Gracefully handles HP App Store unavailability - doesn't raise exceptions.
    Respects REMOTE_STORE_ENABLED flag - won't attempt if disabled.
    
    :param force_refresh: If True, force re-registration even if API key exists (for expired keys)
    :return: API key if registration successful, None if failed, unavailable, or disabled
    """
    try:
        # Check if remote store is enabled
        config = remote_store_config.get_all()
        if not config.get('enabled', False):
            logger.debug("Remote store is disabled (REMOTE_STORE_ENABLED=false), skipping registration")
            return None
        
        # Check if API key already exists
        api_key = config.get('api_key', '')
        
        if api_key and api_key.strip() != '' and api_key.startswith('hp_ak_') and not force_refresh:
            logger.info("API key already exists, skipping auto-registration")
            return api_key
        
        if force_refresh and api_key:
            logger.info(f"API key expired or invalid, refreshing registration (current key: {api_key[:10]}...)")
        elif not api_key:
            logger.info("No API key found, attempting automatic registration with HP App Store")
        
        logger.info("No API key found, attempting automatic registration with HP App Store")
        
        # Get instance identifier
        identifier_data = get_instance_identifier()
        
        # Get contact email if available
        env_vars = read_stingar_env()
        contact_email = env_vars.get('CONTACT_EMAIL', '')
        
        # Get HP App Store base URL
        base_url = config.get('base_url', 'https://store.4warned.io')
        
        # Prepare registration request
        registration_data = {
            'instance_identifier': identifier_data['instance_identifier'],
            'identifier_type': identifier_data['identifier_type'],
            'instance_name': identifier_data['instance_name'],
            'contact_email': contact_email
        }
        
        # Register with HP App Store
        registration_url = f"{base_url}/api/v2/auth/register-instance"
        logger.info(f"Registering instance with HP App Store: {registration_url}")
        logger.debug(f"Registration data: {registration_data}")
        
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                registration_url,
                json=registration_data,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            )
            
            if not response.is_success:
                error_msg = f"Registration failed: {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg = error_data.get('detail', error_data.get('message', error_msg))
                except:
                    error_msg = f"{error_msg} - {response.text[:200]}"
                
                # Log warning but don't raise exception - HP App Store might be temporarily unavailable
                if response.status_code >= 500:
                    logger.warning(f"HP App Store appears unavailable (HTTP {response.status_code}): {error_msg}")
                else:
                    logger.warning(f"Registration failed (HTTP {response.status_code}): {error_msg}")
                return None
            
            # Get API key from response
            response_data = response.json()
            api_key = response_data.get('api_key')
            
            if not api_key or not api_key.startswith('hp_ak_'):
                logger.error(f"Invalid API key received from registration: {api_key[:20] if api_key else 'empty'}")
                return None
            
            # Store API key in stingar.env
            env_vars = read_stingar_env()
            env_vars['REMOTE_STORE_API_KEY'] = api_key
            env_vars['REMOTE_STORE_ENABLED'] = 'true'
            if 'REMOTE_STORE_BASE_URL' not in env_vars:
                env_vars['REMOTE_STORE_BASE_URL'] = base_url
            
            write_stingar_env(env_vars)
            
            # Reload remote store config
            try:
                remote_store_config._load_env_file()
                if force_refresh:
                    logger.info(f"Successfully refreshed API key: {api_key[:10]}...")
                else:
                    logger.info(f"Successfully registered and stored API key: {api_key[:10]}...")
            except Exception as reload_error:
                logger.warning(f"Stored API key but failed to reload config: {reload_error}")
            
            return api_key
            
    except httpx.ConnectError as e:
        # Network error - HP App Store is unreachable
        logger.warning(f"HP App Store is unreachable: {e}")
        logger.info("Apiarist will continue to function normally. Registration will be retried when HP App Store is available.")
        return None
    except httpx.TimeoutException as e:
        # Timeout - HP App Store is slow or unavailable
        logger.warning(f"HP App Store request timed out: {e}")
        logger.info("Apiarist will continue to function normally. Registration will be retried later.")
        return None
    except Exception as e:
        # Other errors - log but don't crash
        logger.error(f"Error during auto-registration: {e}", exc_info=True)
        logger.info("Apiarist will continue to function normally. Registration will be retried.")
        return None


def ensure_registered() -> bool:
    """
    Ensure instance is registered. Called on startup.
    Does not block if HP App Store is unavailable - will retry later.
    Respects REMOTE_STORE_ENABLED flag - won't attempt if disabled.
    
    :return: True if registered (or registration successful), False if needs retry or disabled
    """
    try:
        # Check if remote store is enabled
        config = remote_store_config.get_all()
        if not config.get('enabled', False):
            logger.info("Remote store is disabled (REMOTE_STORE_ENABLED=false), skipping registration")
            return False
        
        # Check if already registered
        api_key = config.get('api_key', '')
        
        if api_key and api_key.strip() != '' and api_key.startswith('hp_ak_'):
            logger.debug("Instance already registered")
            return True
        
        # Attempt auto-registration (non-blocking)
        logger.info("Instance not registered, attempting auto-registration...")
        result = auto_register_instance()
        
        if result:
            logger.info("Auto-registration successful")
            return True
        else:
            # Don't fail startup - HP App Store might be temporarily unavailable
            logger.warning("Auto-registration failed - HP App Store may be unavailable. Will retry periodically.")
            logger.info("Apiarist will continue to function normally. Store features will be unavailable until registration succeeds.")
            return False
            
    except Exception as e:
        # Don't fail startup if registration check fails
        logger.error(f"Error checking registration status: {e}", exc_info=True)
        logger.info("Apiarist will continue to function normally. Registration will be retried.")
        return False


def refresh_expired_api_key() -> Optional[str]:
    """
    Refresh an expired API key by re-registering the instance.
    This is called when authentication fails due to expired key.
    
    :return: New API key if refresh successful, None otherwise
    """
    logger.info("Detected expired API key, attempting to refresh...")
    return auto_register_instance(force_refresh=True)


def retry_registration_periodically():
    """
    Periodically retry registration if not yet registered.
    Runs in background thread and doesn't block anything.
    Respects REMOTE_STORE_ENABLED flag - won't attempt if disabled.
    """
    import time
    
    while True:
        try:
            # Wait 5 minutes between retry attempts
            time.sleep(300)  # 5 minutes
            
            # Check if remote store is enabled
            config = remote_store_config.get_all()
            if not config.get('enabled', False):
                # Remote store disabled - wait longer before checking again
                logger.debug("Remote store is disabled (REMOTE_STORE_ENABLED=false), skipping registration retry")
                time.sleep(1800)  # Wait 30 minutes before checking if enabled again
                continue
            
            # Check if registration is needed
            api_key = config.get('api_key', '')
            
            if api_key and api_key.strip() != '' and api_key.startswith('hp_ak_'):
                # Already registered, check less frequently (every 30 minutes)
                time.sleep(1800)  # 30 minutes
                continue
            
            # Not registered, attempt registration
            logger.info("Retrying automatic registration with HP App Store...")
            result = auto_register_instance()
            
            if result:
                logger.info("Registration successful on retry")
            else:
                logger.debug("Registration retry failed - will try again in 5 minutes")
                
        except Exception as e:
            logger.error(f"Error in registration retry loop: {e}", exc_info=True)
            # Continue retry loop even if there's an error
            time.sleep(300)  # Wait 5 minutes before next retry

