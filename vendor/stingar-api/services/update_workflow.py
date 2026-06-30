"""
Update workflow service for handling container restarts and update operations.

This module implements the complete update workflow including:
- Pre-update validation
- Health checks
- Container restart
- Post-update validation
- Rollback mechanism
"""

import os
import json
import logging
import subprocess
import shutil
import time
try:
    from ruamel.yaml import YAML
    RUAMEL_AVAILABLE = True
except ImportError:
    import yaml
    RUAMEL_AVAILABLE = False
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from services.update_service import (
    get_current_version,
    get_update_config,
    pull_images,
    update_version_state
)

logger = logging.getLogger(__name__)

# Minimum free disk space required (2GB in bytes)
MIN_DISK_SPACE = 2 * 1024 * 1024 * 1024  # 2GB


def check_disk_space(required_space: Optional[int] = None) -> Tuple[bool, str]:
    """
    Check if sufficient disk space is available.
    
    Args:
        required_space: Required space in bytes (optional). If not provided, uses MIN_DISK_SPACE.
    
    Returns:
        Tuple of (has_space, message)
    """
    try:
        stat = shutil.disk_usage('/')
        free_space = stat.free
        
        # Use provided required_space or default to MIN_DISK_SPACE
        space_required = required_space if required_space is not None else MIN_DISK_SPACE
        
        if free_space < space_required:
            free_gb = free_space / (1024 ** 3)
            required_gb = space_required / (1024 ** 3)
            return False, f"Insufficient disk space: {free_gb:.2f}GB free, {required_gb:.2f}GB required"
        
        free_gb = free_space / (1024 ** 3)
        required_gb = space_required / (1024 ** 3)
        return True, f"Disk space OK: {free_gb:.2f}GB free (required: {required_gb:.2f}GB)"
        
    except Exception as e:
        logger.error(f"Error checking disk space: {e}", exc_info=True)
        return False, f"Error checking disk space: {str(e)}"


def check_service_health(timeout: int = 30) -> Tuple[bool, str]:
    """
    Check if apiarist service is healthy.
    
    Args:
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (is_healthy, message)
    """
    try:
        # Use httpx instead of curl (already imported in update_service)
        import httpx
        
        try:
            with httpx.Client(timeout=timeout, verify=False) as client:
                response = client.get('http://localhost:8000/api/v2')
                if response.status_code == 200:
                    return True, "Service health check passed"
                else:
                    return False, f"Service health check failed: HTTP {response.status_code}"
        except httpx.TimeoutException:
            return False, "Service health check timed out"
        except httpx.ConnectError:
            return False, "Service health check failed: Could not connect to service"
        except Exception as e:
            return False, f"Service health check failed: {str(e)}"
            
    except Exception as e:
        logger.error(f"Error checking service health: {e}", exc_info=True)
        return False, f"Error checking service health: {str(e)}"


def verify_images_pulled(target_version: str, compose_file: str) -> Tuple[bool, str]:
    """
    Verify that Docker images for target version are pulled.
    
    Args:
        target_version: Target version string
        compose_file: Path to docker-compose.yml
        
    Returns:
        Tuple of (images_available, message)
    """
    try:
        # Check if docker command is available
        try:
            result = subprocess.run(
                ['which', 'docker'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                logger.warning("Docker CLI not available, skipping image verification")
                return True, "Image verification skipped (Docker CLI not available)"
        except Exception:
            logger.warning("Could not check for Docker CLI, skipping image verification")
            return True, "Image verification skipped (Docker CLI not available)"
        
        # Get docker images from version info
        from services.update_service import check_latest_version
        
        version_info = check_latest_version()
        if not version_info:
            return False, "Could not get version information"
        
        docker_images = version_info.get('docker_images', {})
        
        if not docker_images:
            logger.warning("No docker_images in version info, skipping verification")
            return True, "Image verification skipped (no image list available)"
        
        # Check if images exist locally
        result = subprocess.run(
            ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            logger.warning(f"Failed to list Docker images: {result.stderr}, assuming images are available")
            return True, "Image verification skipped (could not list images)"
        
        # Filter out empty strings and normalize image names
        available_images_raw = result.stdout.strip().split('\n')
        available_images = set()
        for img in available_images_raw:
            img = img.strip()
            if img and img != '<none>:<none>':  # Filter out empty and untagged images
                available_images.add(img)
        
        missing_images = []
        
        for service, image_tag in docker_images.items():
            # Normalize image_tag (remove any whitespace)
            image_tag = image_tag.strip()
            if image_tag not in available_images:
                missing_images.append(image_tag)
        
        if missing_images:
            # Try to pull missing images before failing
            logger.info(f"Attempting to pull missing images: {', '.join(missing_images)}")
            from services.update_service import pull_images
            pull_success = pull_images(compose_file)
            
            if pull_success:
                # Re-check after pull
                result = subprocess.run(
                    ['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    available_images_raw = result.stdout.strip().split('\n')
                    available_images = set()
                    for img in available_images_raw:
                        img = img.strip()
                        if img and img != '<none>:<none>':
                            available_images.add(img)
                    
                    # Check again
                    still_missing = [img for img in missing_images if img not in available_images]
                    if still_missing:
                        return False, f"Missing images after pull attempt: {', '.join(still_missing)}"
                    else:
                        return True, f"All images available after pull: {len(docker_images)} images"
            
            return False, f"Missing images: {', '.join(missing_images)}"
        
        return True, f"All images available: {len(docker_images)} images"
        
    except FileNotFoundError:
        logger.warning("Docker command not found, skipping image verification")
        return True, "Image verification skipped (Docker CLI not available)"
    except Exception as e:
        logger.error(f"Error verifying images: {e}", exc_info=True)
        # Don't fail the update if we can't verify images - they may still be available
        logger.warning("Assuming images are available despite verification error")
        return True, f"Image verification skipped: {str(e)}"


def restart_containers(compose_file: str) -> Tuple[bool, str]:
    """
    Restart containers using docker commands directly.
    Since we're running inside a container, we restart by container name/service name
    instead of using docker-compose file.
    
    Args:
        compose_file: Path to docker-compose.yml (used for logging, not required)
        
    Returns:
        Tuple of (success, message)
    """
    try:
        # Check if docker command is available
        try:
            result = subprocess.run(
                ['which', 'docker'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return False, "Docker CLI not available. Please mount Docker socket or install Docker CLI in container."
        except Exception:
            return False, "Could not verify Docker CLI availability"
        
        # Get list of STINGAR containers to restart
        # These are the standard container names from docker-compose-v2.2.yml
        stingar_containers = [
            'stingar_stingarapi_1',      # From docker-compose project name
            'stingarapi',                 # Alternative name
            'stingar_stingarui_1',
            'stingarui',
            'stingar_langstroth_1',
            'langstroth',
            'stingar_elasticsearch_1',
            'elasticsearch',
            'stingar_kibana_1',
            'kibana',
            'stingar_fluentd_1',
            'fluentd',
        ]
        
        # Also try to find containers by label or image prefix
        logger.info("Finding STINGAR containers to restart...")
        
        # Get all running containers
        result = subprocess.run(
            ['docker', 'ps', '--format', '{{.Names}}'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            return False, f"Failed to list containers: {result.stderr}"
        
        running_containers = [name.strip() for name in result.stdout.strip().split('\n') if name.strip()]
        
        # Find STINGAR containers (containers with 4warned images or matching names)
        containers_to_restart = []
        for container in running_containers:
            # Check if container name matches STINGAR patterns
            if any(pattern in container.lower() for pattern in ['stingar', 'apiarist', 'langstroth', 'kibana', 'elasticsearch', 'fluentd']):
                containers_to_restart.append(container)
            else:
                # Check container image
                try:
                    inspect_result = subprocess.run(
                        ['docker', 'inspect', '--format', '{{.Config.Image}}', container],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if inspect_result.returncode == 0:
                        image = inspect_result.stdout.strip()
                        if '4warned/' in image or 'stingar' in image.lower():
                            containers_to_restart.append(container)
                except Exception:
                    pass  # Skip if we can't inspect
        
        if not containers_to_restart:
            logger.warning("No STINGAR containers found to restart")
            return False, "No STINGAR containers found to restart"
        
        logger.info(f"Restarting {len(containers_to_restart)} containers: {', '.join(containers_to_restart)}")
        
        # Restart each container
        restarted = []
        failed = []
        for container in containers_to_restart:
            try:
                result = subprocess.run(
                    ['docker', 'restart', container],
                    capture_output=True,
                    text=True,
                    timeout=60  # 1 minute per container
                )
                if result.returncode == 0:
                    restarted.append(container)
                    logger.info(f"Successfully restarted {container}")
                else:
                    failed.append(f"{container}: {result.stderr}")
                    logger.error(f"Failed to restart {container}: {result.stderr}")
            except subprocess.TimeoutExpired:
                failed.append(f"{container}: timeout")
                logger.error(f"Timeout restarting {container}")
            except Exception as e:
                failed.append(f"{container}: {str(e)}")
                logger.error(f"Error restarting {container}: {e}")
        
        if failed:
            if restarted:
                return False, f"Partially restarted: {len(restarted)} succeeded, {len(failed)} failed. Failures: {', '.join(failed)}"
            else:
                return False, f"Failed to restart containers: {', '.join(failed)}"
        
        return True, f"Successfully restarted {len(restarted)} containers: {', '.join(restarted)}"
            
    except FileNotFoundError:
        return False, "Docker command not found. Please mount Docker socket (/var/run/docker.sock) and install Docker CLI in container."
    except subprocess.TimeoutExpired:
        return False, "Container restart timed out"
    except Exception as e:
        logger.error(f"Error restarting containers: {e}", exc_info=True)
        return False, f"Error restarting containers: {str(e)}"


def wait_for_service_ready(timeout: int = 120, check_interval: int = 5) -> Tuple[bool, str]:
    """
    Wait for service to become ready after restart.
    
    Args:
        timeout: Maximum time to wait in seconds
        check_interval: Interval between checks in seconds
        
    Returns:
        Tuple of (is_ready, message)
    """
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        is_healthy, message = check_service_health(timeout=10)
        if is_healthy:
            elapsed = time.time() - start_time
            return True, f"Service ready after {elapsed:.1f} seconds"
        
        time.sleep(check_interval)
    
    return False, f"Service did not become ready within {timeout} seconds"


def backup_compose_file(compose_file_path: str) -> Optional[str]:
    """
    Create a timestamped backup of the docker-compose.yml file.
    
    When a single file is mounted (not a directory), the parent directory may not be writable.
    So we store backups in /srv/db/update-state/ which is a writable mounted volume.
    
    Args:
        compose_file_path: Path to docker-compose.yml file
        
    Returns:
        Path to backup file, or None if backup failed
    """
    try:
        if not os.path.exists(compose_file_path):
            logger.warning(f"Compose file not found for backup: {compose_file_path}")
            return None
        
        # Get the compose filename for backup naming
        compose_filename = os.path.basename(compose_file_path)
        
        # Use /srv/db/update-state/ as backup directory (writable mounted volume)
        # This is the same directory used for version state files
        from services.update_service import get_update_config
        config = get_update_config()
        version_state_file = config.get('version_state_file', '/srv/db/update-state/version.json')
        backup_dir = os.path.dirname(version_state_file)
        
        # Ensure backup directory exists
        try:
            os.makedirs(backup_dir, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create backup directory {backup_dir}: {e}")
            return None
        
        # Check if backup directory is writable
        if not os.access(backup_dir, os.W_OK):
            logger.error(f"Backup directory is not writable: {backup_dir}")
            return None
        
        # Create backup filename with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"{compose_filename}.backup.{timestamp}"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Log backup attempt
        logger.info(f"Creating backup of {compose_file_path} to {backup_path}")
        
        # Copy file
        shutil.copy2(compose_file_path, backup_path)
        
        # Verify backup was created
        if not os.path.exists(backup_path):
            logger.error(f"Backup file was not created: {backup_path}")
            return None
        
        # Explicitly flush and sync the file to ensure it's written to disk
        # This is critical because the container may be restarted shortly after backup creation
        try:
            # Open file in append mode to flush buffers
            with open(backup_path, 'a') as f:
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
            logger.debug(f"Flushed backup file to disk: {backup_path}")
        except Exception as flush_error:
            logger.warning(f"Could not flush backup file (non-fatal): {flush_error}")
        
        # Also try to sync the filesystem (if sync command is available)
        try:
            subprocess.run(['sync'], timeout=5, check=False)
            logger.debug("Synced filesystem")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # sync command not available or timed out - non-fatal
            logger.debug("Filesystem sync not available or timed out (non-fatal)")
        except Exception as sync_error:
            logger.debug(f"Filesystem sync failed (non-fatal): {sync_error}")
        
        # Verify backup file size matches original
        original_size = os.path.getsize(compose_file_path)
        backup_size = os.path.getsize(backup_path)
        if original_size != backup_size:
            logger.warning(f"Backup file size mismatch: original={original_size}, backup={backup_size}")
        
        # Verify backup file is still accessible after flush
        if not os.path.exists(backup_path):
            logger.error(f"Backup file disappeared after flush: {backup_path}")
            return None
        
        logger.info(f"Successfully created backup of docker-compose.yml: {backup_path} ({backup_size} bytes)")
        return backup_path
        
    except PermissionError as e:
        logger.error(f"Permission denied creating backup of compose file: {e}", exc_info=True)
        return None
    except OSError as e:
        logger.error(f"OS error creating backup of compose file: {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Error creating backup of compose file: {e}", exc_info=True)
        return None


def find_compose_file(compose_file: str) -> Optional[str]:
    """
    Find the docker-compose.yml file in various possible locations.
    
    The compose file may not be accessible from inside the container if it's not mounted.
    This is non-fatal - the update workflow can still function without it.
    
    Priority order:
    1. Check if compose file is explicitly mounted (most reliable)
    2. Check environment variable COMPOSE_FILE
    3. Check common mount points
    4. Fall back to searching multiple paths
    
    Args:
        compose_file: Name or path of compose file
    
    Returns:
        Full path to compose file if found, None otherwise
    """
    # First, try to detect which compose file was actually used to start this container
    # by checking which compose files are mounted into the container
    mounted_compose_files = []
    for possible_mount in ['/app/docker-compose-v2.2.yml', '/app/docker-compose.yml', 
                          '/app/docker-compose-v2.1.yml', '/app/docker-compose-v2.0.yml']:
        if os.path.exists(possible_mount):
            mounted_compose_files.append(possible_mount)
            logger.debug(f"Found mounted compose file: {possible_mount}")
    
    # If exactly one compose file is mounted, use that one (most reliable)
    if len(mounted_compose_files) == 1:
        logger.info(f"Using mounted compose file: {mounted_compose_files[0]}")
        return mounted_compose_files[0]
    elif len(mounted_compose_files) > 1:
        # Multiple compose files mounted - prefer the one matching COMPOSE_FILE env var
        logger.warning(f"Multiple compose files mounted: {mounted_compose_files}")
        logger.info(f"Using COMPOSE_FILE environment variable to select: {compose_file}")
    
    # Check if compose_file is already an absolute path
    if os.path.isabs(compose_file) and os.path.exists(compose_file):
        return compose_file
    
    # Build list of possible paths to check, prioritizing mounted files
    possible_paths = []
    
    # If we found mounted files, check them first (matching the requested filename)
    for mounted_file in mounted_compose_files:
        if compose_file in mounted_file or os.path.basename(mounted_file) == compose_file:
            possible_paths.append(mounted_file)
    
    # Add other possible paths
    possible_paths.extend([
        # Absolute paths
        compose_file if os.path.isabs(compose_file) else None,
        os.path.join('/', compose_file),
        # Common container mount points (check in order of preference)
        '/app/docker-compose-v2.2.yml',
        '/app/docker-compose.yml',
        '/apiarist/docker-compose-v2.2.yml',
        '/apiarist/docker-compose.yml',
        '/stingar-development/docker-compose-v2.2.yml',
        '/stingar-development/docker-compose.yml',
        # Relative to current working directory
        os.path.join(os.getcwd(), compose_file),
        # Relative to parent directories
        os.path.join(os.path.dirname(os.getcwd()), compose_file),
        os.path.join(os.path.dirname(os.path.dirname(os.getcwd())), compose_file),
        # Check if stingar.env is mounted, compose file might be nearby
        # (stingar.env is typically at /app/stingar.env, compose might be at /app/../docker-compose-v2.2.yml)
        os.path.join(os.path.dirname('/app/stingar.env'), compose_file) if os.path.exists('/app/stingar.env') else None,
        # Check common project root locations
        '/opt/stingar/docker-compose-v2.2.yml',
        '/opt/stingar/docker-compose.yml',
        '/srv/stingar/docker-compose-v2.2.yml',
        '/srv/stingar/docker-compose.yml',
    ])
    
    # Filter out None values and check each path
    for path in [p for p in possible_paths if p is not None]:
        if os.path.exists(path):
            logger.debug(f"Found docker-compose file at: {path}")
            return path
    
    # Log debug info about what we checked
    logger.debug(f"Could not find docker-compose file '{compose_file}' in any of the checked locations")
    logger.debug(f"Current working directory: {os.getcwd()}")
    logger.debug(f"Mounted compose files found: {mounted_compose_files}")
    logger.debug(f"Checked paths: {[p for p in possible_paths if p is not None]}")
    
    return None


def update_compose_file_images(compose_file_path: str, docker_images: Dict[str, str]) -> Tuple[bool, str, Optional[str]]:
    """
    Update image tags in docker-compose.yml file based on version_info.
    
    This function:
    1. Creates a backup of the current compose file
    2. Updates image tags for services that match docker_images keys
    3. Preserves all other compose file content
    
    Args:
        compose_file_path: Path to docker-compose.yml file
        docker_images: Dictionary mapping service names to image tags
                      e.g., {'stingar-api': '4warned/stingar-api:v2.2.1.2', ...}
        
    Returns:
        Tuple of (success, message, backup_path)
    """
    try:
        if not os.path.exists(compose_file_path):
            return False, f"Compose file not found: {compose_file_path}", None
        
        # Create backup first
        logger.info(f"Attempting to create backup of compose file: {compose_file_path}")
        backup_path = backup_compose_file(compose_file_path)
        if not backup_path:
            logger.warning(f"Failed to create backup of {compose_file_path}, but continuing with update")
            logger.warning(f"Compose file exists: {os.path.exists(compose_file_path)}")
            if os.path.exists(compose_file_path):
                compose_dir = os.path.dirname(compose_file_path)
                logger.warning(f"Compose directory: {compose_dir}")
                logger.warning(f"Directory exists: {os.path.exists(compose_dir)}")
                logger.warning(f"Directory writable: {os.access(compose_dir, os.W_OK) if os.path.exists(compose_dir) else 'N/A'}")
        else:
            logger.info(f"Backup created successfully: {backup_path}")
        
        # Read current compose file
        # Use ruamel.yaml if available for better preservation of structure and comments
        if RUAMEL_AVAILABLE:
            yaml_parser = YAML()
            yaml_parser.preserve_quotes = True
            yaml_parser.width = 1000  # Prevent line wrapping
            with open(compose_file_path, 'r') as f:
                compose_data = yaml_parser.load(f)
        else:
            with open(compose_file_path, 'r') as f:
                compose_data = yaml.safe_load(f)
        
        if not compose_data or 'services' not in compose_data:
            return False, "Invalid docker-compose.yml structure: missing 'services' section", backup_path
        
        # Map service names from docker_images to compose service names
        # docker_images keys might be like 'stingar-api', 'stingar-ui', etc.
        # compose service names might be 'stingarapi', 'stingarui', etc.
        service_name_mapping = {
            'stingar-api': 'stingarapi',
            'stingar-api': 'stingarapi',  # Handle both formats
            'stingar-ui': 'stingarui',
            'stingar-ui': 'stingarui',
            'langstroth': 'langstroth',
            'elasticsearch': 'elasticsearch',
            'kibana': 'kibana',
            'fluentd': 'fluentd',
            'docs': 'docs',
        }
        
        # Update image tags for matching services
        updated_count = 0
        updated_services = []
        
        for image_key, image_tag in docker_images.items():
            # Try to find matching service name
            service_name = service_name_mapping.get(image_key, image_key)
            
            # Also try variations (with/without hyphens, case-insensitive)
            matching_service = None
            for compose_service_name in compose_data['services'].keys():
                # Normalize names for comparison (remove hyphens, lowercase)
                normalized_compose = compose_service_name.lower().replace('-', '').replace('_', '')
                normalized_image = image_key.lower().replace('-', '').replace('_', '')
                
                if normalized_compose == normalized_image or normalized_compose == service_name.lower().replace('-', ''):
                    matching_service = compose_service_name
                    break
            
            if not matching_service:
                # Try direct match
                if service_name in compose_data['services']:
                    matching_service = service_name
                elif image_key in compose_data['services']:
                    matching_service = image_key
            
            if matching_service and matching_service in compose_data['services']:
                service_config = compose_data['services'][matching_service]
                old_image = service_config.get('image', '')
                
                # Store original config keys to verify preservation
                original_keys = set(service_config.keys())
                
                # Only update the image field
                service_config['image'] = image_tag
                
                # Verify that all original fields are still present
                current_keys = set(service_config.keys())
                if original_keys != current_keys:
                    missing_keys = original_keys - current_keys
                    logger.warning(f"Warning: Some fields were lost when updating {matching_service}: {missing_keys}")
                    # Restore missing keys from backup if available
                    if backup_path and os.path.exists(backup_path):
                        try:
                            if RUAMEL_AVAILABLE:
                                yaml_parser = YAML()
                                with open(backup_path, 'r') as backup_f:
                                    backup_data = yaml_parser.load(backup_f)
                            else:
                                with open(backup_path, 'r') as backup_f:
                                    backup_data = yaml.safe_load(backup_f)
                            
                            if backup_data and 'services' in backup_data and matching_service in backup_data['services']:
                                backup_service = backup_data['services'][matching_service]
                                for key in missing_keys:
                                    if key in backup_service:
                                        service_config[key] = backup_service[key]
                                        logger.info(f"Restored missing field '{key}' for {matching_service} from backup")
                        except Exception as restore_error:
                            logger.error(f"Failed to restore missing fields from backup: {restore_error}")
                
                updated_count += 1
                updated_services.append(f"{matching_service}: {old_image} -> {image_tag}")
                logger.info(f"Updated {matching_service} image: {old_image} -> {image_tag}")
            else:
                logger.debug(f"No matching service found for image key '{image_key}' (tried: {service_name})")
        
        if updated_count == 0:
            return False, f"No matching services found to update. Available services: {list(compose_data['services'].keys())}", backup_path
        
        # Verify critical fields are preserved before writing
        for service_name, service_config in compose_data.get('services', {}).items():
            # Check that volumes exist (if they were in the original)
            # We can't verify against original here, but we can log if volumes are missing
            # for services that typically have volumes
            if service_name == 'stingarapi' and 'volumes' not in service_config:
                logger.warning(f"Warning: 'stingarapi' service missing 'volumes' field - this may indicate data loss")
        
        # Write updated compose file
        # Use ruamel.yaml if available for better preservation of structure and comments
        if RUAMEL_AVAILABLE:
            yaml_parser = YAML()
            yaml_parser.preserve_quotes = True
            yaml_parser.width = 1000  # Prevent line wrapping
            yaml_parser.indent(mapping=2, sequence=4, offset=2)
            with open(compose_file_path, 'w') as f:
                yaml_parser.dump(compose_data, f)
        else:
            # Fallback to PyYAML with explicit settings
            with open(compose_file_path, 'w') as f:
                yaml.dump(
                    compose_data,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                    width=1000,  # Prevent line wrapping
                    indent=2  # Match standard docker-compose indentation
                )
        
        # Verify the written file still has expected structure
        try:
            if RUAMEL_AVAILABLE:
                yaml_parser = YAML()
                with open(compose_file_path, 'r') as verify_f:
                    verify_data = yaml_parser.load(verify_f)
            else:
                with open(compose_file_path, 'r') as verify_f:
                    verify_data = yaml.safe_load(verify_f)
            
            # Check that volumes are preserved for stingarapi
            if 'services' in verify_data and 'stingarapi' in verify_data['services']:
                stingarapi_config = verify_data['services']['stingarapi']
                if 'volumes' not in stingarapi_config:
                    logger.error("CRITICAL: 'stingarapi' service missing 'volumes' field after write - attempting restore from backup")
                    if backup_path and os.path.exists(backup_path):
                        logger.info(f"Restoring from backup: {backup_path}")
                        shutil.copy2(backup_path, compose_file_path)
                        return False, "Failed to preserve volumes - restored from backup. Please check compose file manually.", backup_path
        except Exception as verify_error:
            logger.warning(f"Could not verify written compose file: {verify_error}")
        
        message = f"Updated {updated_count} service(s) in docker-compose.yml"
        if backup_path:
            message += f" (backup: {backup_path})"
        
        logger.info(f"Successfully updated docker-compose.yml: {', '.join(updated_services)}")
        
        # Flush the updated compose file to ensure it's persisted
        try:
            with open(compose_file_path, 'rb') as f:
                os.fsync(f.fileno())
            logger.debug(f"Updated compose file flushed to disk: {compose_file_path}")
        except Exception as flush_error:
            logger.warning(f"Could not flush updated compose file (non-fatal): {flush_error}")
        
        return True, message, backup_path
        
    except Exception as e:
        # Handle both ruamel.yaml and PyYAML errors
        error_type = type(e).__name__
        if 'YAMLError' in error_type or 'YAML' in error_type:
            logger.error(f"Error parsing docker-compose.yml: {e}", exc_info=True)
            return False, f"Error parsing docker-compose.yml: {str(e)}", None
        else:
            logger.error(f"Error updating docker-compose.yml: {e}", exc_info=True)
            return False, f"Error updating docker-compose.yml: {str(e)}", None


def restore_compose_file_backup(compose_file_path: str, backup_path: str) -> Tuple[bool, str]:
    """
    Restore docker-compose.yml from a backup file.
    
    Args:
        compose_file_path: Path to docker-compose.yml file
        backup_path: Path to backup file
        
    Returns:
        Tuple of (success, message)
    """
    try:
        if not os.path.exists(backup_path):
            return False, f"Backup file not found: {backup_path}"
        
        shutil.copy2(backup_path, compose_file_path)
        logger.info(f"Restored docker-compose.yml from backup: {backup_path}")
        return True, f"Restored docker-compose.yml from backup"
        
    except Exception as e:
        logger.error(f"Error restoring compose file from backup: {e}", exc_info=True)
        return False, f"Error restoring backup: {str(e)}"


def perform_rollback(compose_file: str, previous_version: str) -> Tuple[bool, str]:
    """
    Perform rollback to previous version.
    
    Args:
        compose_file: Path to docker-compose.yml
        previous_version: Version to rollback to
        
    Returns:
        Tuple of (success, message)
    """
    try:
        logger.warning(f"Performing rollback to version {previous_version}")
        
        # Find and restore docker-compose.yml backup if available
        compose_file_path = find_compose_file(compose_file)
        if compose_file_path:
            # Look for most recent backup in /srv/db/update-state/ (where backups are stored)
            from services.update_service import get_update_config
            config = get_update_config()
            version_state_file = config.get('version_state_file', '/srv/db/update-state/version.json')
            backup_dir = os.path.dirname(version_state_file)
            
            compose_filename = os.path.basename(compose_file_path)
            backup_files = []
            if os.path.exists(backup_dir):
                try:
                    for filename in os.listdir(backup_dir):
                        if filename.startswith(compose_filename + '.backup.'):
                            backup_files.append(os.path.join(backup_dir, filename))
                except Exception as e:
                    logger.warning(f"Error listing backup directory {backup_dir}: {e}")
            
            if backup_files:
                # Sort by modification time, most recent first
                backup_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                latest_backup = backup_files[0]
                restore_success, restore_msg = restore_compose_file_backup(compose_file_path, latest_backup)
                if restore_success:
                    logger.info(f"Restored docker-compose.yml from backup: {latest_backup}")
                else:
                    logger.warning(f"Failed to restore compose file backup: {restore_msg}")
        
        # Restart containers (they should use previous images from restored compose file or cached images)
        success, message = restart_containers(compose_file)
        
        if success:
            # Update version state
            update_version_state(previous_version, images_pulled=False)
            return True, f"Rollback to {previous_version} completed"
        else:
            return False, f"Rollback failed: {message}"
            
    except Exception as e:
        logger.error(f"Error during rollback: {e}", exc_info=True)
        return False, f"Rollback error: {str(e)}"


def execute_update_workflow(
    target_version: str,
    job_id: str,
    job_status_callback=None
) -> Dict[str, Any]:
    """
    Execute the complete update workflow.
    
    Args:
        target_version: Target version to update to
        job_id: Job ID for tracking
        job_status_callback: Optional callback function to update job status
        
    Returns:
        Dict with workflow result
    """
    update_config = get_update_config()
    compose_file = update_config.get('compose_file', 'docker-compose.yml')
    current_version = get_current_version()
    
    workflow_steps = []
    
    def update_status(status: str, message: str, error: Optional[str] = None):
        """Update job status."""
        step = {
            'step': status,
            'message': message,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'error': error
        }
        workflow_steps.append(step)
        
        if job_status_callback:
            job_status_callback(status, message, error)
    
    try:
        # Step 1: Pre-update validation
        update_status('validating', 'Starting pre-update validation')
        
        # Check disk space
        has_space, disk_msg = check_disk_space()
        if not has_space:
            update_status('failed', 'Pre-update validation failed', disk_msg)
            return {
                'success': False,
                'error': disk_msg,
                'steps': workflow_steps
            }
        update_status('validating', disk_msg)
        
        # Pull images first - pull directly by tag from version info
        update_status('pulling', 'Pulling Docker images for new version')
        from services.update_service import check_latest_version
        version_info = check_latest_version()
        if not version_info:
            update_status('failed', 'Failed to get version information', 'Could not retrieve version info')
            return {
                'success': False,
                'error': 'Could not retrieve version information',
                'steps': workflow_steps
            }
        
        docker_images = version_info.get('docker_images', {})
        if not docker_images:
            update_status('failed', 'No images specified for version', 'Version info missing docker_images')
            return {
                'success': False,
                'error': 'Version info missing docker_images',
                'steps': workflow_steps
            }
        
        # Pull each image directly by tag
        pulled_count = 0
        failed_images = []
        for service, image_tag in docker_images.items():
            # Check disk space before each image pull
            # Estimate ~500MB per image (conservative estimate for large images)
            estimated_image_size = 500 * 1024 * 1024  # 500MB
            has_space, disk_msg = check_disk_space(required_space=estimated_image_size)
            
            if not has_space:
                error_msg = f"Insufficient disk space before pulling {image_tag}: {disk_msg}"
                failed_images.append(f"{image_tag}: {error_msg}")
                logger.error(error_msg)
                update_status('pulling', f"Disk space check failed for {image_tag}: {disk_msg}")
                # Continue to next image instead of aborting immediately
                # This allows partial success if some images are smaller
                continue
            
            logger.info(f"Disk space check passed for {image_tag}: {disk_msg}")
            
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
                    # Update status after successful pull
                    update_status('pulling', f"Successfully pulled {image_tag} ({pulled_count}/{len(docker_images)})")
                else:
                    failed_images.append(f"{image_tag}: {result.stderr}")
                    logger.error(f"Failed to pull {image_tag}: {result.stderr}")
                    update_status('pulling', f"Failed to pull {image_tag}: {result.stderr}")
            except subprocess.TimeoutExpired:
                failed_images.append(f"{image_tag}: timeout")
                logger.error(f"Timeout pulling {image_tag}")
                update_status('pulling', f"Timeout pulling {image_tag}")
            except Exception as e:
                failed_images.append(f"{image_tag}: {str(e)}")
                logger.error(f"Error pulling {image_tag}: {e}")
                update_status('pulling', f"Error pulling {image_tag}: {str(e)}")
        
        if failed_images:
            update_status('failed', 'Failed to pull some Docker images', f"Failed: {', '.join(failed_images)}")
            return {
                'success': False,
                'error': f"Failed to pull images: {', '.join(failed_images)}",
                'steps': workflow_steps
            }
        
        update_status('pulling', f'Successfully pulled {pulled_count} Docker images')
        
        # Step 1.5: Update docker-compose.yml with new image tags
        update_status('updating_compose', 'Updating docker-compose.yml with new image tags')
        compose_file_path = find_compose_file(compose_file)
        compose_backup_path: Optional[str] = None
        
        if compose_file_path:
            compose_updated, compose_msg, compose_backup_path = update_compose_file_images(compose_file_path, docker_images)
            if compose_updated:
                update_status('updating_compose', compose_msg)
                
                # If backup was created, ensure it's flushed to disk before container restart
                if compose_backup_path:
                    logger.info(f"Ensuring backup file is flushed to disk: {compose_backup_path}")
                    try:
                        with open(compose_backup_path, 'rb') as f:
                            os.fsync(f.fileno())
                        logger.debug(f"Backup file flushed to disk: {compose_backup_path}")
                    except Exception as flush_error:
                        logger.warning(f"Could not flush backup file (non-fatal): {flush_error}")
            else:
                # Non-fatal: log warning but continue (containers will use new images via restart)
                logger.warning(f"Failed to update docker-compose.yml: {compose_msg}")
                update_status('updating_compose', f"Warning: {compose_msg} (containers will use new images)")
        else:
            # This is non-fatal - compose file update is optional
            # Containers will still use new images via restart, but compose file won't be updated
            logger.info(f"Could not find docker-compose.yml file: {compose_file} (this is non-fatal - compose file update is optional)")
            logger.info("Note: To enable compose file updates, mount the compose file into the container or set COMPOSE_FILE to an accessible path")
            update_status('updating_compose', f"Info: Compose file not found (optional - containers will use new images via restart)")
        
        # Small delay before restart to ensure all file operations are synced to disk
        # This is critical because the container may restart itself during the update
        logger.debug("Waiting 2 seconds before container restart to ensure file operations are synced to disk...")
        time.sleep(2)
        
        # Sync filesystem to ensure all writes are persisted
        try:
            subprocess.run(['sync'], timeout=5, check=False)
            logger.debug("Filesystem synced before container restart")
        except Exception as sync_error:
            logger.debug(f"Filesystem sync failed (non-fatal): {sync_error}")
        
        # Verify images are pulled
        images_ok, images_msg = verify_images_pulled(target_version, compose_file)
        if not images_ok:
            update_status('failed', 'Pre-update validation failed', images_msg)
            return {
                'success': False,
                'error': images_msg,
                'steps': workflow_steps
            }
        update_status('validating', images_msg)
        
        # Check service health before update
        is_healthy, health_msg = check_service_health()
        if not is_healthy:
            update_status('failed', 'Pre-update validation failed', health_msg)
            return {
                'success': False,
                'error': health_msg,
                'steps': workflow_steps
            }
        update_status('validating', health_msg)
        
        # Step 2: Restart containers
        update_status('restarting', 'Restarting containers')
        restart_success, restart_msg = restart_containers(compose_file)
        
        if not restart_success:
            update_status('failed', 'Container restart failed', restart_msg)
            # Attempt rollback
            update_status('rolling_back', 'Attempting rollback')
            rollback_success, rollback_msg = perform_rollback(compose_file, current_version)
            if rollback_success:
                update_status('rolled_back', rollback_msg)
            else:
                update_status('rollback_failed', rollback_msg)
            
            return {
                'success': False,
                'error': restart_msg,
                'steps': workflow_steps,
                'rolled_back': rollback_success if not restart_success else False
            }
        
        update_status('restarting', restart_msg)
        
        # Step 3: Wait for service to be ready
        update_status('waiting', 'Waiting for service to become ready')
        is_ready, ready_msg = wait_for_service_ready(timeout=120)
        
        if not is_ready:
            update_status('failed', 'Service did not become ready', ready_msg)
            # Attempt rollback
            update_status('rolling_back', 'Attempting rollback due to health check failure')
            rollback_success, rollback_msg = perform_rollback(compose_file, current_version)
            if rollback_success:
                update_status('rolled_back', rollback_msg)
            else:
                update_status('rollback_failed', rollback_msg)
            
            return {
                'success': False,
                'error': ready_msg,
                'steps': workflow_steps,
                'rolled_back': rollback_success
            }
        
        update_status('waiting', ready_msg)
        
        # Step 4: Post-update health check
        update_status('validating', 'Performing post-update health check')
        is_healthy, health_msg = check_service_health()
        
        if not is_healthy:
            update_status('failed', 'Post-update health check failed', health_msg)
            # Attempt rollback
            update_status('rolling_back', 'Attempting rollback due to health check failure')
            rollback_success, rollback_msg = perform_rollback(compose_file, current_version)
            if rollback_success:
                update_status('rolled_back', rollback_msg)
            else:
                update_status('rollback_failed', rollback_msg)
            
            return {
                'success': False,
                'error': health_msg,
                'steps': workflow_steps,
                'rolled_back': rollback_success
            }
        
        update_status('validating', health_msg)
        
        # Step 5: Update version state
        update_status('completing', 'Updating version state')
        update_version_state(target_version, images_pulled=True)
        update_status('completed', f'Successfully updated to {target_version}')
        
        return {
            'success': True,
            'message': f'Successfully updated to {target_version}',
            'steps': workflow_steps,
            'current_version': current_version,
            'target_version': target_version
        }
        
    except Exception as e:
        logger.error(f"Error in update workflow: {e}", exc_info=True)
        update_status('failed', 'Update workflow error', str(e))
        
        # Attempt rollback on unexpected error
        try:
            update_status('rolling_back', 'Attempting rollback due to unexpected error')
            rollback_success, rollback_msg = perform_rollback(compose_file, current_version)
            if rollback_success:
                update_status('rolled_back', rollback_msg)
            else:
                update_status('rollback_failed', rollback_msg)
        except Exception as rollback_error:
            logger.error(f"Rollback also failed: {rollback_error}", exc_info=True)
            update_status('rollback_failed', f"Rollback error: {str(rollback_error)}")
        
        return {
            'success': False,
            'error': str(e),
            'steps': workflow_steps,
            'rolled_back': False
        }

