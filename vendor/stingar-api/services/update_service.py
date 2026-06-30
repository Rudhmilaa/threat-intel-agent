"""
Background service for checking STINGAR versions and pulling Docker images.
"""

import os
import time
import json
import logging
import subprocess
from datetime import datetime, time as dt_time
from typing import Dict, Optional, Any
import httpx

logger = logging.getLogger(__name__)


def get_remote_store_config():
    """
    Get remote store configuration.
    Uses the same config system as remote_store service.
    """
    try:
        from config.remote_store import remote_store_config
        return remote_store_config.get_all()
    except ImportError as e:
        logger.warning(f"Failed to import remote store config module: {e}")
        logger.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'not set')}")
        logger.debug(f"Current working directory: {os.getcwd()}")
        # Fall back to environment variables
        return {
            'base_url': os.getenv('REMOTE_STORE_BASE_URL', 'https://store.4warned.io'),
            'api_key': os.getenv('REMOTE_STORE_API_KEY', ''),
            'timeout': int(os.getenv('REMOTE_STORE_TIMEOUT', '30')),
            'enabled': os.getenv('REMOTE_STORE_ENABLED', 'true').lower() == 'true'
        }
    except Exception as e:
        logger.warning(f"Failed to load remote store config: {e}")
        return {
            'base_url': os.getenv('REMOTE_STORE_BASE_URL', 'https://store.4warned.io'),
            'api_key': os.getenv('REMOTE_STORE_API_KEY', ''),
            'timeout': int(os.getenv('REMOTE_STORE_TIMEOUT', '30')),
            'enabled': os.getenv('REMOTE_STORE_ENABLED', 'true').lower() == 'true'
        }


def get_update_config() -> Dict[str, Any]:
    """
    Get update service configuration from environment variables.
    """
    return {
        'check_interval': int(os.getenv('UPDATE_CHECK_INTERVAL', '10800')),  # Default: 3 hours (10800 seconds)
        'window_start': os.getenv('UPDATE_WINDOW_START', '00:00'),  # Default: midnight
        'window_end': os.getenv('UPDATE_WINDOW_END', '06:00'),  # Default: 6am
        'compose_file': os.getenv('COMPOSE_FILE', 'docker-compose.yml'),
        'version_state_file': os.getenv('CURRENT_VERSION_FILE', '/srv/db/update-state/version.json'),
        'enabled': os.getenv('UPDATE_SERVICE_ENABLED', 'true').lower() == 'true'
    }


def is_within_update_window(window_start: str, window_end: str) -> bool:
    """
    Check if current time is within the update window.
    
    Args:
        window_start: Start time in HH:MM format (e.g., "00:00")
        window_end: End time in HH:MM format (e.g., "06:00")
        
    Returns:
        bool: True if current time is within window
    """
    try:
        now = datetime.now().time()
        
        # Parse window times
        start_hour, start_min = map(int, window_start.split(':'))
        end_hour, end_min = map(int, window_end.split(':'))
        
        start_time = dt_time(start_hour, start_min)
        end_time = dt_time(end_hour, end_min)
        
        # Handle window that spans midnight (e.g., 22:00 - 06:00)
        if start_time > end_time:
            # Window spans midnight
            return now >= start_time or now <= end_time
        else:
            # Normal window (e.g., 00:00 - 06:00)
            return start_time <= now <= end_time
            
    except Exception as e:
        logger.error(f"Error checking update window: {e}")
        return False


# Process-lifetime cache for the docker.sock detection. apiarist's
# own image tag does not change while the process is alive; caching
# avoids hammering the docker socket on every API request.
_container_version_cache: Optional[str] = None
_container_version_cache_resolved: bool = False


def _detect_version_from_running_container() -> Optional[str]:
    """
    Resolve apiarist's own running image tag via the docker socket.

    Steps:
      1. Read own container id from /etc/hostname (Docker uses the
         container's short id as the default hostname).
      2. ``docker inspect`` that container, parse ``Config.Image``,
         return the tag portion (e.g. ``v2.3`` from
         ``4warned/stingar-api:v2.3``).

    Returns ``None`` if the lookup fails for any reason (no docker
    CLI, no socket mount, ``latest`` tag, etc.). Result is cached
    for the process lifetime.

    See Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md (phase 3 / P0).
    """
    global _container_version_cache, _container_version_cache_resolved
    if _container_version_cache_resolved:
        return _container_version_cache

    _container_version_cache_resolved = True

    try:
        with open('/etc/hostname', 'r') as f:
            container_id = f.read().strip()
        if not container_id:
            return None

        result = subprocess.run(
            ['docker', 'inspect', '--format', '{{.Config.Image}}', container_id],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            logger.debug(
                "docker inspect %s failed (rc=%s): %s",
                container_id, result.returncode, result.stderr.strip(),
            )
            return None

        image = result.stdout.strip()
        if ':' not in image:
            return None

        tag = image.rsplit(':', 1)[1]
        if tag and tag != 'latest':
            _container_version_cache = tag
            return tag
    except FileNotFoundError as e:
        logger.debug("Docker socket unavailable for version detection: %s", e)
    except Exception as e:
        logger.debug("Could not detect version from running container: %s", e)

    return None


def get_current_version() -> Optional[str]:
    """
    Resolve the "installed STINGAR version" for the dashboard.

    Priority (highest first):
      1. ``STINGAR_VERSION`` env var, baked into the image at build
         time (see ``apiarist/Dockerfile``). Single source of truth.
      2. Image tag of apiarist's own running container, queried via
         docker.sock. Handles older images where the env var was
         not baked.
      3. ``installed_version`` from
         ``/srv/db/update-state/version.json``. Legacy fallback;
         this file can be stale when the operator runs
         ``docker compose pull`` out-of-band (the v2.2.x customer
         bug). Used only if the first two sources fail.

    Returns ``None`` only if all three sources are unavailable.

    See Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md (phase 3 / P0).
    """
    env_version = os.getenv('STINGAR_VERSION')
    if env_version and env_version.strip():
        return env_version.strip()

    sock_version = _detect_version_from_running_container()
    if sock_version:
        return sock_version

    try:
        config = get_update_config()
        version_file = config['version_state_file']
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                state = json.load(f)
                version = state.get('installed_version')
                if version:
                    return version
    except Exception as e:
        logger.debug(f"Could not read version from state file: {e}")

    return None


def reconcile_version_state_on_boot() -> None:
    """
    Rewrite the legacy version state file on startup if it disagrees
    with the authoritative running-image version.

    Motivation: ``update_version_state(images_pulled=True)`` is only
    called by apiarist's internal updater path. Operators who run
    ``docker compose pull`` themselves never trigger that codepath,
    so ``version.json`` stays pinned to the last-auto-updated
    version forever and the dashboard nags about an "available
    update" that's actually already installed.

    This routine reconciles by:
      1. Asking the authoritative sources (env var, then docker.sock)
         "what version is actually running?". Deliberately skips the
         state file -- the whole point is that the file may be wrong.
      2. Comparing against ``installed_version`` in the state file.
      3. Calling ``update_version_state(authoritative,
         images_pulled=True)`` if they disagree.

    Failures are logged and swallowed; this must never block boot.

    See Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md (phase 4 / P4).
    """
    try:
        authoritative = (os.getenv('STINGAR_VERSION') or '').strip() or None
        if not authoritative:
            authoritative = _detect_version_from_running_container()

        if not authoritative:
            logger.info(
                "Version reconciliation skipped: no authoritative source "
                "(STINGAR_VERSION unset, docker.sock lookup failed)"
            )
            return

        config = get_update_config()
        version_file = config['version_state_file']
        stale_value = None
        if os.path.exists(version_file):
            try:
                with open(version_file, 'r') as f:
                    stale_value = json.load(f).get('installed_version')
            except Exception as e:
                logger.warning(
                    "Could not read version state file for reconciliation: %s", e,
                )

        if stale_value == authoritative:
            logger.info(
                "Version state file is consistent with running image (%s)",
                authoritative,
            )
            return

        logger.warning(
            "Version drift detected: state file installed_version=%s, "
            "running image=%s -- reconciling state file to running version",
            stale_value, authoritative,
        )
        update_version_state(authoritative, images_pulled=True)
    except Exception as e:
        logger.error("Error during version reconciliation: %s", e, exc_info=True)


def check_latest_version() -> Optional[Dict[str, Any]]:
    """
    Check latest available version from store.4warned.io.
    
    Returns:
        Dict with version info or None if check failed
    """
    try:
        config = get_remote_store_config()
        
        if not config.get('enabled', False):
            logger.debug("Remote store is disabled, skipping version check")
            return None
        
        base_url = config.get('base_url', 'https://store.4warned.io')
        api_key = config.get('api_key', '')
        timeout = min(config.get('timeout', 30), 10)  # Cap at 10s to avoid blocking
        
        if not api_key:
            logger.warning("No API key configured, cannot check for updates")
            return None
        
        # Make request to version endpoint
        url = f"{base_url}/api/v2/stingar/version/latest"
        headers = {
            'API-KEY': api_key,
            'Content-Type': 'application/json'
        }
        
        with httpx.Client(timeout=timeout, verify=True) as client:
            response = client.get(url, headers=headers)
            
            if response.status_code == 200:
                version_info = response.json()
                logger.info(f"Version check successful: latest version is {version_info.get('version')}")
                return version_info
            elif response.status_code == 401:
                logger.warning("Authentication failed when checking version - API key may be invalid")
                return None
            else:
                logger.warning(f"Version check failed with status {response.status_code}: {response.text}")
                return None
                
    except httpx.TimeoutException:
        logger.warning("Version check timed out - store.4warned.io may be unavailable")
        return None
    except httpx.ConnectError as e:
        logger.debug("Version check skipped - cannot reach store (network/DNS restricted): %s", str(e))
        return None
    except Exception as e:
        logger.error(f"Error checking latest version: {e}", exc_info=True)
        return None


def pull_images(compose_file: str) -> bool:
    """
    Pull Docker images using docker compose.
    
    Args:
        compose_file: Path to docker-compose.yml file
        
    Returns:
        bool: True if pull succeeded, False otherwise
    """
    try:
        logger.info(f"Pulling Docker images using {compose_file}")
        
        # Find docker-compose.yml file
        # Check multiple possible locations
        possible_paths = [
            compose_file,
            os.path.join(os.getcwd(), compose_file),
            os.path.join('/', compose_file),
            '/apiarist/docker-compose-v2.2.yml',
            '/apiarist/docker-compose.yml',
            '/app/docker-compose-v2.2.yml',
            '/app/docker-compose.yml',
            # Check parent directories (common in Docker setups)
            os.path.join(os.path.dirname(os.getcwd()), compose_file),
            os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), compose_file),
            # Check if we're in a mounted volume scenario
            '/stingar-development/docker-compose-v2.2.yml',
            '/stingar-development/docker-compose.yml',
        ]
        
        compose_path = None
        for path in possible_paths:
            if os.path.exists(path):
                compose_path = path
                break
        
        if not compose_path:
            logger.error(f"Could not find docker-compose file: {compose_file}")
            return False
        
        # Run docker compose pull
        result = subprocess.run(
            ['docker', 'compose', '-f', compose_path, 'pull'],
            capture_output=True,
            text=True,
            timeout=1800  # 30 minute timeout
        )
        
        if result.returncode == 0:
            logger.info("Successfully pulled Docker images")
            return True
        else:
            logger.error(f"Failed to pull images: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("Image pull timed out after 30 minutes")
        return False
    except Exception as e:
        logger.error(f"Error pulling images: {e}", exc_info=True)
        return False


def update_version_state(version: str, images_pulled: bool = False):
    """
    Update version state file.
    
    Args:
        version: Version string
        images_pulled: Whether images were successfully pulled
    """
    try:
        config = get_update_config()
        version_file = config['version_state_file']
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(version_file), exist_ok=True)
        
        # Read existing state or create new
        state = {
            'installed_version': version,
            'installed_date': datetime.utcnow().isoformat() + 'Z',
            'update_history': [],
            'last_check': datetime.utcnow().isoformat() + 'Z',
            'last_update_attempt': None,
            'images_pulled': images_pulled,
            'images_pulled_date': datetime.utcnow().isoformat() + 'Z' if images_pulled else None
        }
        
        # Try to preserve existing history if file exists
        if os.path.exists(version_file):
            try:
                with open(version_file, 'r') as f:
                    existing = json.load(f)
                    state['update_history'] = existing.get('update_history', [])
                    # Only update installed_version if images were pulled
                    if not images_pulled:
                        state['installed_version'] = existing.get('installed_version', version)
            except Exception:
                pass
        
        # Write updated state
        with open(version_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        logger.debug(f"Updated version state file: {version_file}")
        
    except Exception as e:
        logger.error(f"Error updating version state: {e}", exc_info=True)


def check_and_pull_updates():
    """
    Check for updates and pull images if within update window.
    This function is called periodically by the background thread.
    """
    try:
        update_config = get_update_config()
        
        if not update_config.get('enabled', True):
            logger.debug("Update service is disabled")
            return
        
        # Check latest version
        latest_version_info = check_latest_version()
        if not latest_version_info:
            logger.debug("Could not get latest version info")
            return
        
        latest_version = latest_version_info.get('version')
        if not latest_version:
            logger.warning("Version info missing version field")
            return
        
        # Get current version
        current_version = get_current_version()
        
        # Compare versions
        if current_version and current_version == latest_version:
            logger.debug(f"Already on latest version: {latest_version}")
            # Update last_check timestamp
            update_version_state(current_version, images_pulled=False)
            return
        
        logger.info(f"New version available: {latest_version} (current: {current_version or 'unknown'})")
        
        # Check if within update window
        window_start = update_config['window_start']
        window_end = update_config['window_end']
        
        if not is_within_update_window(window_start, window_end):
            logger.info(f"Outside update window ({window_start} - {window_end}), will pull during next window")
            # Update state with latest version info but don't pull
            update_version_state(current_version or latest_version, images_pulled=False)
            return
        
        # Within update window - pull images directly by tag
        logger.info(f"Within update window, pulling images for version {latest_version}")
        
        # Import disk space check function
        from services.update_workflow import check_disk_space
        
        # Pull images directly from version_info instead of using compose file
        docker_images = latest_version_info.get('docker_images', {})
        if docker_images:
            pulled_count = 0
            failed_images = []
            for service, image_tag in docker_images.items():
                # Check disk space before each image pull
                # Estimate ~1GB per image (conservative estimate for large images)
                estimated_image_size = 1024 * 1024 * 1024  # 1GB
                has_space, disk_msg = check_disk_space(required_space=estimated_image_size)
                
                if not has_space:
                    error_msg = f"Insufficient disk space before pulling {image_tag}: {disk_msg}"
                    failed_images.append(image_tag)
                    logger.warning(error_msg)
                    # Continue to next image instead of aborting immediately
                    continue
                
                logger.debug(f"Disk space check passed for {image_tag}: {disk_msg}")
                
                try:
                    logger.info(f"Pulling image: {image_tag}")
                    result = subprocess.run(
                        ['docker', 'pull', image_tag],
                        capture_output=True,
                        text=True,
                        timeout=600  # 10 minutes per image
                    )
                    if result.returncode == 0:
                        pulled_count += 1
                        logger.info(f"Successfully pulled {image_tag}")
                    else:
                        failed_images.append(image_tag)
                        logger.warning(f"Failed to pull {image_tag}: {result.stderr}")
                except subprocess.TimeoutExpired:
                    failed_images.append(image_tag)
                    logger.warning(f"Timeout pulling {image_tag}")
                except Exception as e:
                    failed_images.append(image_tag)
                    logger.warning(f"Error pulling {image_tag}: {e}")
            
            if failed_images:
                update_version_state(current_version or latest_version, images_pulled=False)
                logger.warning(f"Failed to pull some images for version {latest_version}: {failed_images}")
            else:
                update_version_state(latest_version, images_pulled=True)
                logger.info(f"Successfully pulled {pulled_count} images for version {latest_version}")
        else:
            # Fallback to compose file method if no docker_images in version_info
            logger.warning("No docker_images in version_info, falling back to compose file method")
            compose_file = update_config['compose_file']
            success = pull_images(compose_file)
            
            # Update state
            if success:
                update_version_state(latest_version, images_pulled=True)
                logger.info(f"Successfully pulled images for version {latest_version}")
            else:
                update_version_state(current_version or latest_version, images_pulled=False)
                logger.warning(f"Failed to pull images for version {latest_version}")
            
    except Exception as e:
        logger.error(f"Error in check_and_pull_updates: {e}", exc_info=True)


def start_update_service():
    """
    Start the background update service.
    Runs in a separate thread and checks for updates periodically.
    """
    import threading
    
    def update_loop():
        """Main update loop running in background thread."""
        update_config = get_update_config()
        check_interval = update_config['check_interval']
        
        logger.info(f"Starting update service (check interval: {check_interval}s, window: {update_config['window_start']} - {update_config['window_end']})")
        
        # Initial check after a short delay
        time.sleep(60)  # Wait 1 minute after startup
        
        while True:
            try:
                check_and_pull_updates()
            except Exception as e:
                logger.error(f"Error in update loop: {e}", exc_info=True)
            
            # Wait for next check interval
            time.sleep(check_interval)
    
    # Start background thread
    update_thread = threading.Thread(target=update_loop, daemon=True)
    update_thread.start()
    logger.info("Update service thread started")


def ensure_update_service_started():
    """
    Ensure update service is started.
    Called on apiarist startup.
    """
    try:
        update_config = get_update_config()
        
        if not update_config.get('enabled', True):
            logger.info("Update service is disabled (UPDATE_SERVICE_ENABLED=false)")
            return
        
        # Check if remote store is enabled (required for version checks)
        remote_config = get_remote_store_config()
        if not remote_config.get('enabled', False):
            logger.info("Update service requires remote store to be enabled")
            return
        
        start_update_service()
        
    except Exception as e:
        logger.warning(f"Could not start update service: {e}")
        logger.info("Apiarist will continue to function normally without update service")

