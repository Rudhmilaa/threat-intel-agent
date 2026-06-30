"""
System resource for managing STINGAR version and update operations.

Provides endpoints for:
- Checking current version
- Checking for available updates
- Viewing update status
- Triggering updates (manual mode)
- Managing update settings
- Release notes (bundled fallback when HP Store does not provide)
"""

import os
import json
import logging
import uuid
import threading
import falcon
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from services.update_service import (
    get_current_version,
    check_latest_version,
    get_update_config,
    get_remote_store_config,
    is_within_update_window,
    update_version_state
)
from services.update_workflow import execute_update_workflow
from resources.store_config import read_stingar_env, write_stingar_env

logger = logging.getLogger(__name__)

# Path to bundled release notes (relative to this module)
RELEASE_NOTES_DIR = Path(__file__).parent.parent / 'release_notes'


def _load_bundled_release_notes(version: str) -> Optional[str]:
    """Load release notes from bundled file when HP Store does not provide them."""
    if not version:
        return None
    # Normalize version: v2.3 or 2.3 -> v2.3
    v = version if version.startswith('v') else f'v{version}'
    path = RELEASE_NOTES_DIR / f'{v}.md'
    if path.exists():
        try:
            return path.read_text(encoding='utf-8')
        except Exception as e:
            logger.debug(f"Could not read bundled release notes: {e}")
    return None


def _ensure_release_notes(version_info: Dict[str, Any]) -> Dict[str, Any]:
    """Inject release_notes from bundled file if Store did not provide them."""
    if not version_info:
        return version_info
    if version_info.get('release_notes') or version_info.get('release_notes_url'):
        return version_info
    version = version_info.get('version')
    bundled = _load_bundled_release_notes(version)
    if bundled:
        version_info = dict(version_info)
        version_info['release_notes'] = bundled
    return version_info


# In-memory job tracking (persisted to disk for container restart resilience)
_update_jobs: Dict[str, Dict[str, Any]] = {}

# Job retention period: keep completed/failed jobs for 24 hours
JOB_RETENTION_HOURS = 24


def get_jobs_file_path() -> str:
    """Get the path to the update jobs file."""
    from services.update_service import get_update_config
    config = get_update_config()
    version_file = config.get('version_state_file', '/srv/db/update-state/version.json')
    jobs_dir = os.path.dirname(version_file)
    return os.path.join(jobs_dir, 'update-jobs.json')


def load_update_jobs() -> Dict[str, Dict[str, Any]]:
    """
    Load update jobs from disk.
    
    Returns:
        Dictionary of job_id -> job_data
    """
    jobs_file = get_jobs_file_path()
    jobs = {}
    
    if os.path.exists(jobs_file):
        try:
            with open(jobs_file, 'r') as f:
                jobs_data = json.load(f)
                # Filter out old jobs (older than retention period)
                cutoff_time = datetime.utcnow().timestamp() - (JOB_RETENTION_HOURS * 3600)
                
                for job_id, job in jobs_data.items():
                    # Parse updated_at timestamp
                    try:
                        updated_at_str = job.get('updated_at', '')
                        if updated_at_str:
                            # Parse ISO format timestamp (handles 'Z' suffix)
                            try:
                                # Replace 'Z' with '+00:00' for UTC timezone
                                if updated_at_str.endswith('Z'):
                                    updated_at_str = updated_at_str[:-1] + '+00:00'
                                updated_at = datetime.fromisoformat(updated_at_str)
                                updated_timestamp = updated_at.timestamp()
                            except (ValueError, AttributeError):
                                # Fallback: parse naive datetime (remove timezone info)
                                try:
                                    # Remove timezone suffix if present
                                    naive_str = updated_at_str.split('+')[0].split('-')[0] if '+' in updated_at_str or (updated_at_str.count('-') > 2 and updated_at_str[-6] == '-') else updated_at_str
                                    naive_str = naive_str.replace('Z', '')
                                    updated_at = datetime.fromisoformat(naive_str)
                                    # Convert to UTC timestamp (assume UTC for naive datetime)
                                    updated_timestamp = (updated_at - datetime(1970, 1, 1)).total_seconds()
                                except Exception as parse_error:
                                    # If all parsing fails, skip this job
                                    logger.warning(f"Could not parse timestamp for job {job_id}: {updated_at_str}, error: {parse_error}")
                                    continue
                            
                            # Only include jobs within retention period
                            if updated_timestamp > cutoff_time:
                                jobs[job_id] = job
                            else:
                                logger.debug(f"Filtering out old job {job_id} (updated: {updated_at_str})")
                        else:
                            # Include jobs without timestamp (shouldn't happen, but be safe)
                            jobs[job_id] = job
                    except Exception as e:
                        logger.warning(f"Error parsing job {job_id} timestamp: {e}, including job anyway")
                        jobs[job_id] = job
                
                logger.info(f"Loaded {len(jobs)} update job(s) from disk")
        except Exception as e:
            logger.error(f"Error loading update jobs from disk: {e}", exc_info=True)
    
    return jobs


def save_update_jobs():
    """Save update jobs to disk."""
    try:
        jobs_file = get_jobs_file_path()
        jobs_dir = os.path.dirname(jobs_file)
        
        # Ensure directory exists
        os.makedirs(jobs_dir, exist_ok=True)
        
        # Write jobs to file
        with open(jobs_file, 'w') as f:
            json.dump(_update_jobs, f, indent=2)
        
        logger.debug(f"Saved {len(_update_jobs)} update job(s) to disk")
    except Exception as e:
        logger.error(f"Error saving update jobs to disk: {e}", exc_info=True)


def cleanup_old_jobs():
    """Remove jobs older than retention period."""
    try:
        cutoff_time = datetime.utcnow().timestamp() - (JOB_RETENTION_HOURS * 3600)
        jobs_to_remove = []
        
        for job_id, job in _update_jobs.items():
            try:
                updated_at_str = job.get('updated_at', '')
                if updated_at_str:
                    # Parse ISO format timestamp (handles 'Z' suffix)
                    try:
                        # Replace 'Z' with '+00:00' for UTC timezone
                        if updated_at_str.endswith('Z'):
                            updated_at_str = updated_at_str[:-1] + '+00:00'
                        updated_at = datetime.fromisoformat(updated_at_str)
                        updated_timestamp = updated_at.timestamp()
                    except (ValueError, AttributeError):
                        # Fallback: parse naive datetime (remove timezone info)
                        try:
                            # Remove timezone suffix if present
                            naive_str = updated_at_str.split('+')[0] if '+' in updated_at_str else updated_at_str
                            naive_str = naive_str.replace('Z', '')
                            updated_at = datetime.fromisoformat(naive_str)
                            # Convert to UTC timestamp (assume UTC for naive datetime)
                            updated_timestamp = (updated_at - datetime(1970, 1, 1)).total_seconds()
                        except Exception:
                            # If parsing fails, skip this job
                            continue
                    
                    if updated_timestamp < cutoff_time:
                        jobs_to_remove.append(job_id)
            except Exception:
                # If we can't parse timestamp, keep the job
                pass
        
        for job_id in jobs_to_remove:
            del _update_jobs[job_id]
            logger.debug(f"Removed old job {job_id} (older than {JOB_RETENTION_HOURS} hours)")
        
        if jobs_to_remove:
            save_update_jobs()
    except Exception as e:
        logger.error(f"Error cleaning up old jobs: {e}", exc_info=True)


# Load jobs from disk on module import
_update_jobs = load_update_jobs()

# Clean up old jobs on startup
cleanup_old_jobs()


class SystemVersionResource:
    """Resource for getting current system version."""
    
    def on_get(self, req, resp):
        """GET /api/v2/system/version - Get current installed version."""
        try:
            current_version = get_current_version()
            update_config = get_update_config()
            
            # Try to read version state file for more details
            version_info = {
                'version': current_version or 'unknown',
                'version_state_file': update_config.get('version_state_file'),
                'compose_file': update_config.get('compose_file')
            }
            
            # Read version state file if it exists
            version_state_file = update_config.get('version_state_file')
            if version_state_file and os.path.exists(version_state_file):
                try:
                    with open(version_state_file, 'r') as f:
                        state = json.load(f)
                        version_info.update({
                            'installed_date': state.get('installed_date'),
                            'last_check': state.get('last_check'),
                            'images_pulled': state.get('images_pulled', False),
                            'images_pulled_date': state.get('images_pulled_date')
                        })
                except Exception as e:
                    logger.debug(f"Could not read version state file: {e}")
            
            resp.media = version_info
            resp.status = falcon.HTTP_200
            
        except Exception as e:
            logger.error(f"Error getting system version: {e}", exc_info=True)
            resp.media = {'error': f'Failed to get version: {str(e)}'}
            resp.status = falcon.HTTP_500


class SystemUpdateCheckResource:
    """Resource for checking if updates are available."""
    
    def on_get(self, req, resp):
        """GET /api/v2/system/update-check - Check for available updates."""
        try:
            current_version = get_current_version()
            latest_version_info = check_latest_version()
            
            if not latest_version_info:
                resp.media = {
                    'error': 'Could not check for updates. Store may be unavailable.',
                    'current_version': current_version
                }
                resp.status = falcon.HTTP_503
                return
            
            latest_version = latest_version_info.get('version')
            update_available = current_version != latest_version if current_version else True
            
            # Check if within update window
            update_config = get_update_config()
            window_start = update_config.get('window_start', '00:00')
            window_end = update_config.get('window_end', '06:00')
            within_window = is_within_update_window(window_start, window_end)
            
            latest_info = latest_version_info if update_available else None
            if latest_info:
                latest_info = _ensure_release_notes(latest_info)

            resp.media = {
                'current_version': current_version,
                'latest_version': latest_version,
                'update_available': update_available,
                'within_update_window': within_window,
                'update_window': {
                    'start': window_start,
                    'end': window_end
                },
                'latest_version_info': latest_info
            }
            resp.status = falcon.HTTP_200
            
        except Exception as e:
            logger.error(f"Error checking for updates: {e}", exc_info=True)
            resp.media = {'error': f'Failed to check for updates: {str(e)}'}
            resp.status = falcon.HTTP_500


class SystemUpdateStatusResource:
    """Resource for getting update service status."""
    
    def on_get(self, req, resp):
        """GET /api/v2/system/update-status - Get update service status."""
        try:
            update_config = get_update_config()
            remote_config = get_remote_store_config()
            
            # Check if update service is enabled
            service_enabled = update_config.get('enabled', True)
            remote_store_enabled = remote_config.get('enabled', False)
            
            # Get current version info
            current_version = get_current_version()
            
            # Check for latest version
            latest_version_info = None
            try:
                latest_version_info = check_latest_version()
            except Exception as e:
                logger.debug(f"Could not check latest version: {e}")
            
            update_available = (
                current_version != latest_version_info.get('version')
                if latest_version_info and current_version
                else False
            )

            latest_info = latest_version_info if update_available else None
            if latest_info:
                latest_info = _ensure_release_notes(latest_info)

            status = {
                'service_enabled': service_enabled,
                'remote_store_enabled': remote_store_enabled,
                'current_version': current_version,
                'latest_version': latest_version_info.get('version') if latest_version_info else None,
                'update_available': update_available,
                'latest_version_info': latest_info,
                'check_interval': update_config.get('check_interval'),
                'update_window': {
                    'start': update_config.get('window_start'),
                    'end': update_config.get('window_end'),
                    'within_window': is_within_update_window(
                        update_config.get('window_start', '00:00'),
                        update_config.get('window_end', '06:00')
                    )
                },
                'compose_file': update_config.get('compose_file'),
                'version_state_file': update_config.get('version_state_file')
            }
            
            resp.media = status
            resp.status = falcon.HTTP_200
            
        except Exception as e:
            logger.error(f"Error getting update status: {e}", exc_info=True)
            resp.media = {'error': f'Failed to get update status: {str(e)}'}
            resp.status = falcon.HTTP_500


class SystemUpdateApplyResource:
    """Resource for applying updates (manual mode)."""
    
    def on_post(self, req, resp):
        """POST /api/v2/system/update/apply - Apply available update."""
        try:
            # Check if update is available
            current_version = get_current_version()
            latest_version_info = check_latest_version()
            
            if not latest_version_info:
                resp.media = {'error': 'Could not check for updates. Store may be unavailable.'}
                resp.status = falcon.HTTP_503
                return
            
            latest_version = latest_version_info.get('version')
            
            if current_version == latest_version:
                resp.media = {
                    'message': f'Already on latest version: {latest_version}',
                    'current_version': current_version,
                    'latest_version': latest_version
                }
                resp.status = falcon.HTTP_200
                return
            
            # Check if within update window
            update_config = get_update_config()
            window_start = update_config.get('window_start', '00:00')
            window_end = update_config.get('window_end', '06:00')
            
            if not is_within_update_window(window_start, window_end):
                resp.media = {
                    'error': f'Outside update window ({window_start} - {window_end}). Updates can only be applied during this window.',
                    'update_window': {
                        'start': window_start,
                        'end': window_end
                    }
                }
                resp.status = falcon.HTTP_400
                return
            
            # Generate job ID
            job_id = str(uuid.uuid4())
            
            # Create job entry
            _update_jobs[job_id] = {
                'job_id': job_id,
                'status': 'pending',
                'current_version': current_version,
                'target_version': latest_version,
                'created_at': datetime.utcnow().isoformat() + 'Z',
                'updated_at': datetime.utcnow().isoformat() + 'Z',
                'error': None,
                'steps': []
            }
            
            # Save to disk immediately
            save_update_jobs()
            
            # Define callback to update job status
            def update_job_status(status: str, message: str, error: Optional[str] = None):
                """Update job status from workflow."""
                if job_id in _update_jobs:
                    _update_jobs[job_id]['status'] = status
                    _update_jobs[job_id]['updated_at'] = datetime.utcnow().isoformat() + 'Z'
                    if error:
                        _update_jobs[job_id]['error'] = error
                    if 'steps' not in _update_jobs[job_id]:
                        _update_jobs[job_id]['steps'] = []
                    _update_jobs[job_id]['steps'].append({
                        'step': status,
                        'message': message,
                        'timestamp': datetime.utcnow().isoformat() + 'Z',
                        'error': error
                    })
                    # Save to disk after each status update
                    try:
                        save_update_jobs()
                    except Exception as e:
                        logger.warning(f"Failed to save job status to disk: {e}")
            
            # Start update workflow in background thread
            def run_update():
                """Run update workflow in background."""
                try:
                    # Update job status to in-progress
                    update_job_status('in-progress', 'Starting update workflow')
                    
                    # Execute workflow
                    result = execute_update_workflow(
                        target_version=latest_version,
                        job_id=job_id,
                        job_status_callback=update_job_status
                    )
                    
                    # Update final job status
                    if result.get('success'):
                        update_job_status('completed', result.get('message', 'Update completed successfully'))
                        _update_jobs[job_id]['steps'] = result.get('steps', [])
                    else:
                        update_job_status('failed', 'Update failed', result.get('error'))
                        _update_jobs[job_id]['steps'] = result.get('steps', [])
                        _update_jobs[job_id]['rolled_back'] = result.get('rolled_back', False)
                    
                    # Final save after workflow completes
                    save_update_jobs()
                        
                except Exception as e:
                    logger.error(f"Error in update workflow thread: {e}", exc_info=True)
                    update_job_status('failed', 'Update workflow error', str(e))
            
            # Start background thread
            update_thread = threading.Thread(target=run_update, daemon=True)
            update_thread.start()
            
            resp.media = {
                'job_id': job_id,
                'message': 'Update job created and started. Use GET /api/v2/system/update/status/{job_id} to check status.',
                'current_version': current_version,
                'target_version': latest_version
            }
            resp.status = falcon.HTTP_202  # Accepted
            
        except Exception as e:
            logger.error(f"Error applying update: {e}", exc_info=True)
            resp.media = {'error': f'Failed to apply update: {str(e)}'}
            resp.status = falcon.HTTP_500


class SystemUpdateJobStatusResource:
    """Resource for checking update job status."""
    
    def on_get(self, req, resp, job_id):
        """GET /api/v2/system/update/status/{job_id} - Get update job status."""
        try:
            # Try to reload jobs from disk in case they were updated externally
            # (e.g., if container restarted and jobs were reloaded)
            if job_id not in _update_jobs:
                # Reload from disk - might have been persisted before restart
                reloaded_jobs = load_update_jobs()
                if job_id in reloaded_jobs:
                    _update_jobs[job_id] = reloaded_jobs[job_id]
                    logger.info(f"Reloaded job {job_id} from disk")
            
            if job_id not in _update_jobs:
                # Job not found - might have been lost due to container restart
                # or cleaned up after retention period
                resp.media = {
                    'error': f'Job {job_id} not found',
                    'message': 'Job may have been lost due to container restart or cleaned up after retention period',
                    'job_id': job_id
                }
                resp.status = falcon.HTTP_404
                return
            
            job = _update_jobs[job_id].copy()
            # Include steps if available
            if 'steps' in job:
                job['workflow_steps'] = job['steps']
            
            resp.media = job
            resp.status = falcon.HTTP_200
            
        except Exception as e:
            logger.error(f"Error getting job status: {e}", exc_info=True)
            resp.media = {'error': f'Failed to get job status: {str(e)}'}
            resp.status = falcon.HTTP_500


class SystemUpdateSettingsResource:
    """Resource for managing update settings."""
    
    def on_get(self, req, resp):
        """GET /api/v2/settings/update - Get update settings."""
        try:
            env_vars = read_stingar_env()
            update_config = get_update_config()
            
            settings = {
                'update_mode': env_vars.get('UPDATE_MODE', 'manual'),  # manual or auto
                'update_window_start': update_config.get('window_start', '00:00'),
                'update_window_end': update_config.get('window_end', '06:00'),
                'check_interval': update_config.get('check_interval', 10800),
                'service_enabled': update_config.get('enabled', True),
                'compose_file': update_config.get('compose_file'),
                'cleanup_old_images': env_vars.get('CLEANUP_OLD_IMAGES', 'false').lower() == 'true',
                'cleanup_after_hours': int(env_vars.get('CLEANUP_AFTER_HOURS', '24'))
            }
            
            resp.media = settings
            resp.status = falcon.HTTP_200
            
        except Exception as e:
            logger.error(f"Error getting update settings: {e}", exc_info=True)
            resp.media = {'error': f'Failed to get update settings: {str(e)}'}
            resp.status = falcon.HTTP_500
    
    def on_put(self, req, resp):
        """PUT /api/v2/settings/update - Update update settings."""
        try:
            # Require admin authentication (check if user is admin)
            # For now, we'll allow any authenticated user (can be enhanced)
            
            body = req.media
            env_vars = read_stingar_env()
            
            # Update settings
            if 'update_mode' in body:
                env_vars['UPDATE_MODE'] = body['update_mode']  # manual or auto
            
            if 'update_window_start' in body:
                env_vars['UPDATE_WINDOW_START'] = body['update_window_start']
            
            if 'update_window_end' in body:
                env_vars['UPDATE_WINDOW_END'] = body['update_window_end']
            
            if 'check_interval' in body:
                env_vars['UPDATE_CHECK_INTERVAL'] = str(body['check_interval'])
            
            if 'service_enabled' in body:
                env_vars['UPDATE_SERVICE_ENABLED'] = 'true' if body['service_enabled'] else 'false'
            
            if 'cleanup_old_images' in body:
                env_vars['CLEANUP_OLD_IMAGES'] = 'true' if body['cleanup_old_images'] else 'false'
            
            if 'cleanup_after_hours' in body:
                env_vars['CLEANUP_AFTER_HOURS'] = str(body['cleanup_after_hours'])
            
            # Write back to stingar.env
            write_stingar_env(env_vars)
            
            resp.media = {
                'message': 'Update settings saved successfully',
                'settings': {
                    'update_mode': env_vars.get('UPDATE_MODE', 'manual'),
                    'update_window_start': env_vars.get('UPDATE_WINDOW_START', '00:00'),
                    'update_window_end': env_vars.get('UPDATE_WINDOW_END', '06:00'),
                    'check_interval': int(env_vars.get('UPDATE_CHECK_INTERVAL', '10800')),
                    'service_enabled': env_vars.get('UPDATE_SERVICE_ENABLED', 'true').lower() == 'true',
                    'cleanup_old_images': env_vars.get('CLEANUP_OLD_IMAGES', 'false').lower() == 'true',
                    'cleanup_after_hours': int(env_vars.get('CLEANUP_AFTER_HOURS', '24'))
                }
            }
            resp.status = falcon.HTTP_200
            
        except Exception as e:
            logger.error(f"Error updating settings: {e}", exc_info=True)
            resp.media = {'error': f'Failed to update settings: {str(e)}'}
            resp.status = falcon.HTTP_500

