import json
import datetime
import falcon
import logging
from typing import Dict, Any, List
from falcon.media.validators import jsonschema
from resources import db
from util import json_converter
from services.remote_store import SyncRemoteStore, AuthenticationError
from config.remote_store import remote_store_config

logger = logging.getLogger(__name__)


def safe_log_config(config_data: Dict[str, Any], sensitive_keys: List[str] = None) -> Dict[str, Any]:
    """
    Create a safe version of configuration data for logging by removing sensitive keys.
    
    :param config_data: Configuration dictionary to sanitize
    :param sensitive_keys: List of keys to remove (defaults to common sensitive keys)
    :return: Sanitized configuration dictionary
    """
    if sensitive_keys is None:
        sensitive_keys = ['api_key', 'auth_token', 'password', 'secret', 'key', 'token']
    
    safe_config = {}
    for key, value in config_data.items():
        if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
            safe_config[key] = '[REDACTED]'
        elif isinstance(value, dict):
            safe_config[key] = safe_log_config(value, sensitive_keys)
        else:
            safe_config[key] = value
    
    return safe_config


def map_honeypot_fields(honeypot):
    """Map HP_AppStore field names to apiarist database field names."""
    import datetime
    import json
    
    field_mapping = {
        'id': 'remote_id',  # HP_AppStore 'id' -> apiarist 'remote_id'
        'created_at': 'created',  # HP_AppStore 'created_at' -> apiarist 'created'
        'local_created_at': 'local_created',  # HP_AppStore 'local_created_at' -> apiarist 'local_created'
        'local_updated_at': 'local_updated',  # HP_AppStore 'local_updated_at' -> apiarist 'local_updated'
        # Note: download_count stays as download_count for database storage
    }
    
    # Fields that should be stored as JSON strings in the database
    json_fields = ['tags', 'supported_protocols', 'default_ports', 'min_requirements', 'configuration_schema', 'default_configuration']
    
    mapped = {}
    for key, value in honeypot.items():
        # Use mapped field name if it exists, otherwise use original
        mapped_key = field_mapping.get(key, key)
        
        # Convert ISO datetime strings to Python datetime objects for SQLite
        if mapped_key in ['created', 'last_updated', 'local_created', 'local_updated'] and value:
            try:
                if isinstance(value, str):
                    # Parse ISO format datetime string
                    mapped[mapped_key] = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                else:
                    mapped[mapped_key] = value
            except (ValueError, TypeError):
                # If parsing fails, set to None
                mapped[mapped_key] = None
        # Convert list/dict fields to JSON strings for database storage
        elif mapped_key in json_fields and value is not None:
            try:
                mapped[mapped_key] = json.dumps(value)
            except (TypeError, ValueError):
                # If JSON serialization fails, store as empty string
                mapped[mapped_key] = ''
        else:
            mapped[mapped_key] = value
    
    return mapped


def map_honeypot_fields_for_frontend(honeypot):
    """Map database/HP_AppStore field names to frontend field names."""
    import json
    
    field_mapping = {
        'download_count': 'downloads',  # HP_AppStore/database 'download_count' -> frontend 'downloads'
        'hp_type': 'hpType',  # HP_AppStore/database 'hp_type' -> frontend 'hpType'
        'created_at': 'createdAt',  # HP_AppStore 'created_at' -> frontend 'createdAt'
        'created': 'createdAt',  # Database 'created' -> frontend 'createdAt'
        'last_updated': 'updatedAt',  # HP_AppStore 'last_updated' -> frontend 'updatedAt'
        'local_updated': 'updatedAt',  # Database 'local_updated' -> frontend 'updatedAt'
    }
    
    # Fields that are stored as JSON strings in the database but should be objects for frontend
    json_fields = ['tags', 'supported_protocols', 'default_ports', 'min_requirements', 'configuration_schema', 'default_configuration']
    
    mapped = {}
    for key, value in honeypot.items():
        # Use mapped field name if it exists, otherwise use original
        mapped_key = field_mapping.get(key, key)
        
        # Convert JSON strings back to objects for frontend
        if mapped_key in json_fields and value and isinstance(value, str):
            try:
                mapped[mapped_key] = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                # If JSON parsing fails, keep as string
                mapped[mapped_key] = value
        else:
            mapped[mapped_key] = value
    
    return mapped


class StoreResource(object):
    """
    Remote honeypot store API endpoint.
    """

    def on_get(self, req, resp):
        """
        Get available honeypots from remote store with local cache fallback.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Convert query parameters
            params = {}
            for key, value in req.params.items():
                if key in ['category', 'hp_type', 'author']:
                    params[key] = value
            
            # Try to get data from remote store first (if API key exists)
            api_key = config.get('api_key', '')
            if api_key and api_key.strip() != '' and api_key.startswith('hp_ak_'):
                try:
                    remote_store = SyncRemoteStore(
                        base_url=config['base_url'],
                        api_key=api_key,
                        timeout=config['timeout']
                    )
                    
                    results = remote_store.get_honeypots(params)
                    
                    # Cache the results locally
                    self._cache_remote_honeypots(results)
                    
                    # Map fields for frontend response
                    frontend_results = [map_honeypot_fields_for_frontend(honeypot) for honeypot in results]
                    
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": frontend_results, "source": "remote"}, default=json_converter, ensure_ascii=False)
                    return
                    
                except AuthenticationError as e:
                    logger.warning(f"Authentication failed with remote store (using cached data): {e}")
                    logger.debug("Falling back to local cached data")
                    # Don't return here - fall through to cache fallback
                except Exception as e:
                    logger.warning(f"Failed to get honeypots from remote store: {e}")
                    logger.debug("Falling back to local cached data")
            else:
                # No API key - skip remote store, use cache only
                logger.debug("No API key available, using cached data only")
            
            # Fallback to local cached data
            try:
                results = db.get_remote_honeypots(params)
                if results:
                    # Map fields for frontend response and add staleness information
                    from services.cache_validator import CacheValidator
                    validator = CacheValidator(db)
                    
                    frontend_results = []
                    for honeypot in results:
                        mapped_honeypot = map_honeypot_fields_for_frontend(honeypot)
                        # Add staleness information for cached data
                        staleness_info = validator.get_honeypot_staleness_info(honeypot, 24)
                        mapped_honeypot['isStale'] = staleness_info['is_stale']
                        mapped_honeypot['ageHours'] = staleness_info['age_hours']
                        mapped_honeypot['lastUpdated'] = staleness_info['last_updated']
                        frontend_results.append(mapped_honeypot)
                    
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": frontend_results, "source": "cache"}, default=json_converter, ensure_ascii=False)
                else:
                    resp.status = falcon.HTTP_503
                    resp.text = json.dumps({"errors": [
                        {"title": "Service Unavailable",
                         "description": "Remote store unavailable and no cached data available."}]})
            except Exception as e:
                logger.error(f"Failed to get cached honeypots: {e}")
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Unable to connect to remote honeypot store or access cached data."}]})
            
        except Exception as e:
            logger.error(f"Unexpected error in store resource: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})

    def _cache_remote_honeypots(self, honeypots):
        """Cache remote honeypots in local database."""
        try:
            for honeypot in honeypots:
                # Map HP_AppStore field names to apiarist field names
                mapped_honeypot = map_honeypot_fields(honeypot)
                
                # Check if honeypot already exists
                existing = db.get_remote_honeypots({'remote_id': mapped_honeypot.get('remote_id')})
                if existing:
                    # Update existing record
                    db.update_remote_honeypot(existing[0]['id'], **mapped_honeypot)
                else:
                    # Create new record
                    db.create_remote_honeypot(**mapped_honeypot)
            logger.debug(f"Cached {len(honeypots)} honeypots locally")
        except Exception as e:
            logger.error(f"Failed to cache honeypots: {e}")

    def on_get_count(self, req, resp):
        """
        Get count of available honeypots from remote store with local cache fallback.

        :param req: Falcon request
        :param resp: Falcon response
        """
        logger.debug("Count endpoint called")
        try:
            # Get configuration
            config = remote_store_config.get_all()
            # Log config without sensitive information (debug only)
            logger.debug(f"Remote store config: {safe_log_config(config)}")
            
            # Debug: Check if API key is actually present (without logging the full key)
            api_key = config.get('api_key', '')
            if not api_key or api_key.strip() == '':
                logger.warning("API key is empty or missing in remote store config")
                # Try to read directly from stingar.env as a fallback
                try:
                    from resources.store_config import read_stingar_env, get_stingar_env_path
                    env_file_path = get_stingar_env_path()
                    logger.debug(f"Attempting to read API key directly from {env_file_path}")
                    env_vars = read_stingar_env()
                    logger.debug(f"Read {len(env_vars)} variables from stingar.env")
                    direct_api_key = env_vars.get('REMOTE_STORE_API_KEY', '')
                    if direct_api_key and direct_api_key.strip() != '':
                        logger.debug(f"Found API key in stingar.env directly: {direct_api_key[:10]}...")
                        # Update config with the direct value
                        config['api_key'] = direct_api_key
                        api_key = direct_api_key
                    else:
                        logger.warning(f"API key not found in stingar.env file. Available REMOTE_STORE_ keys: {[k for k in env_vars.keys() if k.startswith('REMOTE_STORE_')]}")
                except Exception as e:
                    logger.error(f"Could not read stingar.env directly: {e}", exc_info=True)
            elif not api_key.startswith('hp_ak_'):
                logger.warning(f"API key format appears invalid (doesn't start with 'hp_ak_'): {api_key[:10]}...")
            else:
                logger.debug(f"API key present and format looks valid: {api_key[:10]}...")
            
            if not config['enabled']:
                logger.warning("Remote store is disabled")
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Try to get count from remote store first (if API key exists)
            api_key = config.get('api_key', '')
            if api_key and api_key.strip() != '' and api_key.startswith('hp_ak_'):
                try:
                    remote_store = SyncRemoteStore(
                        base_url=config['base_url'],
                        api_key=api_key,
                        timeout=config['timeout']
                    )
                    
                    results = remote_store.get_honeypots({})
                    count = len(results)
                    
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": {"count": count}, "source": "remote"}, default=json_converter, ensure_ascii=False)
                    return
                    
                except AuthenticationError as e:
                    logger.warning(f"Authentication failed with remote store (using cached data): {e}")
                    logger.debug("Falling back to local cached data")
                    # Don't return here - fall through to cache fallback
                except Exception as e:
                    logger.warning(f"Failed to get honeypot count from remote store: {e}")
                    logger.debug("Falling back to local cached data")
            else:
                # No API key - skip remote store, use cache only
                logger.debug("No API key available, using cached count only")
            
            # Fallback to local cached data
            try:
                logger.debug("Falling back to local cached data")
                results = db.get_remote_honeypots({})
                logger.debug(f"Local results: {results}")
                count = len(results) if results else 0
                logger.debug(f"Count from cache: {count}")
                
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({"data": {"count": count}, "source": "cache"}, default=json_converter, ensure_ascii=False)
                
            except Exception as e:
                logger.error(f"Failed to get cached honeypot count: {e}")
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Unable to connect to remote honeypot store or access cached data."}]})
            
        except Exception as e:
            logger.error(f"Unexpected error in store count resource: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})


class StoreHoneypotResource(object):
    """
    Individual remote honeypot operations.
    """

    def on_get(self, req, resp, ident):
        """
        Get specific remote honeypot details with local cache fallback.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Remote honeypot ID
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Try to get data from remote store first
            try:
                remote_store = SyncRemoteStore(
                    base_url=config['base_url'],
                    api_key=config['api_key'] if config['api_key'] else None,
                    timeout=config['timeout']
                )
                
                results = remote_store.get_honeypot(ident)
                
                if results:
                    # Cache the result locally
                    self._cache_remote_honeypot(results)
                    
                    # Map fields for frontend response
                    frontend_results = map_honeypot_fields_for_frontend(results)
                    
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": frontend_results, "source": "remote"}, default=json_converter, ensure_ascii=False)
                    return
                    
            except Exception as e:
                logger.warning(f"Failed to get honeypot {ident} from remote store: {e}")
                logger.debug("Falling back to local cached data")
            
            # Fallback to local cached data
            try:
                results = db.get_remote_honeypots({'id': int(ident)})
                if results:
                    # Map fields for frontend response
                    frontend_results = map_honeypot_fields_for_frontend(results[0])
                    
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": frontend_results, "source": "cache"}, default=json_converter, ensure_ascii=False)
                else:
                    resp.status = falcon.HTTP_404
                    resp.text = json.dumps({"errors": [
                        {"title": "Honeypot Not Found",
                         "description": f"Remote honeypot with id '{ident}' not found in remote store or cache."}]})
            except Exception as e:
                logger.error(f"Failed to get cached honeypot {ident}: {e}")
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Unable to connect to remote honeypot store or access cached data."}]})
            
        except Exception as e:
            logger.error(f"Unexpected error in store honeypot resource: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})

    def _cache_remote_honeypot(self, honeypot):
        """Cache remote honeypot in local database."""
        try:
            # Map HP_AppStore field names to apiarist field names
            mapped_honeypot = map_honeypot_fields(honeypot)
            
            # Check if honeypot already exists
            existing = db.get_remote_honeypots({'remote_id': mapped_honeypot.get('remote_id')})
            if existing:
                # Update existing record
                db.update_remote_honeypot(existing[0]['id'], **mapped_honeypot)
            else:
                # Create new record
                db.create_remote_honeypot(**mapped_honeypot)
            logger.debug(f"Cached honeypot {mapped_honeypot.get('remote_id')} locally")
        except Exception as e:
            logger.error(f"Failed to cache honeypot: {e}")

    def on_post(self, req, resp, ident):
        """
        Install remote honeypot locally.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Remote honeypot ID
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Create remote store client
            remote_store = SyncRemoteStore(
                base_url=config['base_url'],
                api_key=config['api_key'] if config['api_key'] else None,
                timeout=config['timeout']
            )
            
            # Try to get honeypot details from remote store first
            remote_honeypot = None
            try:
                remote_honeypot = remote_store.get_honeypot(ident)
                if remote_honeypot:
                    logger.info(f"Successfully fetched honeypot {ident} from remote store")
            except Exception as e:
                logger.warning(f"Failed to get honeypot {ident} from remote store: {e}")
                logger.debug("Falling back to local cached data for installation")
            
            # If remote fetch failed, try to get from local cache
            if not remote_honeypot:
                try:
                    cached_honeypots = db.get_remote_honeypots({'id': int(ident)})
                    if cached_honeypots:
                        remote_honeypot = cached_honeypots[0]
                        logger.info(f"Using cached honeypot {ident} for installation")
                    else:
                        resp.status = falcon.HTTP_404
                        resp.text = json.dumps({"errors": [
                            {"title": "Honeypot Not Found",
                             "description": f"Honeypot with id '{ident}' not found in remote store or local cache."}]})
                        return
                except Exception as e:
                    logger.error(f"Failed to get honeypot {ident} from cache: {e}")
                    resp.status = falcon.HTTP_404
                    resp.text = json.dumps({"errors": [
                        {"title": "Honeypot Not Found",
                         "description": f"Honeypot with id '{ident}' not found in remote store or local cache."}]})
                    return
            
            # Get installation data from request
            installation_data = req.media
            
            # Create local config from remote metadata
            default_config = remote_honeypot.get('default_configuration', {})
            logger.info(f"Default configuration type: {type(default_config)}, value: {safe_log_config(default_config) if isinstance(default_config, dict) else default_config}")
            
            # Handle different data types for hp_options
            if isinstance(default_config, str):
                hp_options = default_config  # Already a JSON string
            else:
                hp_options = json.dumps(default_config)  # Convert dict to JSON string
            

            
            # Validate hp_type from remote honeypot
            hp_type = remote_honeypot.get('hp_type')
            logger.info(f"Validating hp_type for honeypot {ident}: '{hp_type}' (type: {type(hp_type)})")
            
            if not hp_type or (isinstance(hp_type, str) and hp_type.strip() == ''):
                logger.error(f"Invalid hp_type for honeypot {ident}: '{hp_type}'")
                resp.status = falcon.HTTP_400
                resp.text = json.dumps({"errors": [
                    {"title": "Invalid Honeypot",
                     "description": f"Remote honeypot is missing required hp_type field. Received: '{hp_type}'"}]})
                return
            
            logger.info(f"Validated hp_type for honeypot {ident}: '{hp_type}'")
            
            # Validate required fields for configuration
            honeypot_name = remote_honeypot.get('name', 'Unknown')
            if not honeypot_name or honeypot_name.strip() == '':
                logger.error(f"Invalid honeypot name for honeypot {ident}: '{honeypot_name}'")
                resp.status = falcon.HTTP_400
                resp.text = json.dumps({"errors": [
                    {"title": "Invalid Honeypot",
                     "description": f"Remote honeypot is missing required name field. Received: '{honeypot_name}'"}]})
                return
            
            # Include docker image information in hp_options
            docker_image = remote_honeypot.get('docker_image')
            docker_tag = remote_honeypot.get('docker_tag', 'latest')
            
            # Log what we received for debugging
            logger.debug(f"Remote honeypot docker_image: '{docker_image}', docker_tag: '{docker_tag}', hp_type: '{remote_honeypot.get('hp_type')}'")
            
            # Construct docker_image from hp_type if docker_image is missing or empty
            if not docker_image or (isinstance(docker_image, str) and docker_image.strip() == ''):
                hp_type = remote_honeypot.get('hp_type', 'unknown')
                # Default pattern: 4warned/{hp_type}:{tag}
                docker_image = f'4warned/{hp_type}'
                logger.info(f"docker_image missing or empty for hp_type '{hp_type}', constructing from hp_type: {docker_image}")
            else:
                # Remove any existing tag from docker_image to avoid double tags
                if ':' in docker_image:
                    docker_image = docker_image.split(':')[0]
            
            # Parse existing hp_options to add docker image info
            if isinstance(hp_options, str):
                try:
                    parsed_hp_options = json.loads(hp_options)
                except json.JSONDecodeError:
                    parsed_hp_options = {}
            else:
                parsed_hp_options = hp_options
            
            # Add docker image information - always include the tag
            parsed_hp_options['docker_image'] = f"{docker_image}:{docker_tag}"
            parsed_hp_options['docker_image_name'] = docker_image
            parsed_hp_options['docker_tag'] = docker_tag
            
            # Convert back to JSON string
            updated_hp_options = json.dumps(parsed_hp_options)
            
            config_data = {
                'name': f"{honeypot_name} (from store)",
                'hp_type': hp_type,
                'hp_options': updated_hp_options
            }
            
            logger.info(f"Creating local config for honeypot {ident}: {safe_log_config(config_data)}")
            
            # Create local configuration
            try:
                local_config = db.create_config(**config_data)
                logger.info(f"Successfully created local config for honeypot {ident}: {safe_log_config(local_config)}")
            except Exception as config_error:
                logger.error(f"Failed to create local config for honeypot {ident}: {config_error}")
                resp.status = falcon.HTTP_500
                resp.text = json.dumps({"errors": [
                    {"title": "Configuration Creation Failed",
                     "description": f"Failed to create local configuration: {str(config_error)}"}]})
                return
            
            # Trigger template download for new honeypot types
            try:
                import asyncio
                from services.template_manager import TemplateManager
                
                template_manager = TemplateManager()
                
                # For HP_AppStore honeypots, always try to download fresh templates first
                # This ensures we get the latest honeypot_config.json with proper hp_options
                logger.info(f"Attempting to download fresh templates from HP App Store for {hp_type}")
                try:
                    # Download templates from HP App Store using synchronous method
                    success, extracted_hp_options = template_manager.download_and_save_templates_sync(
                        hp_type=hp_type,
                        remote_store=remote_store,
                        honeypot_config=remote_honeypot,
                        deployment_info=installation_data
                    )
                    
                    if success:
                        logger.info(f"Successfully downloaded fresh templates for {hp_type}")
                        
                        # Update local configuration with extracted hp_options if available
                        if extracted_hp_options and isinstance(extracted_hp_options, dict):
                            logger.info(f"Updating local config with extracted hp_options: {safe_log_config(extracted_hp_options)}")
                            try:
                                # Reload current hp_options from local_config to get docker_image info
                                current_hp_options_str = local_config.get('hp_options', '{}')
                                if isinstance(current_hp_options_str, str):
                                    try:
                                        current_hp_options = json.loads(current_hp_options_str)
                                    except json.JSONDecodeError:
                                        current_hp_options = {}
                                else:
                                    current_hp_options = current_hp_options_str
                                
                                # Merge extracted_hp_options into current_hp_options to preserve docker_image info
                                # Start with current_hp_options (which has docker_image) and update with extracted_hp_options
                                merged_hp_options = current_hp_options.copy()
                                merged_hp_options.update(extracted_hp_options)
                                
                                # Explicitly preserve docker image information (in case extracted_hp_options overwrote it)
                                if 'docker_image' in current_hp_options:
                                    merged_hp_options['docker_image'] = current_hp_options['docker_image']
                                if 'docker_image_name' in current_hp_options:
                                    merged_hp_options['docker_image_name'] = current_hp_options['docker_image_name']
                                if 'docker_tag' in current_hp_options:
                                    merged_hp_options['docker_tag'] = current_hp_options['docker_tag']
                                
                                logger.debug(f"Merged hp_options: docker_image={merged_hp_options.get('docker_image')}, docker_image_name={merged_hp_options.get('docker_image_name')}, docker_tag={merged_hp_options.get('docker_tag')}")
                                
                                # Update the local configuration with the merged hp_options
                                updated_hp_options = json.dumps(merged_hp_options)
                                db.update_config(local_config['id'], hp_options=updated_hp_options)
                                logger.info(f"Successfully updated local config {local_config['id']} with merged hp_options including docker image info")
                                
                                # Refresh local_config with updated data
                                local_config = db.get_config(local_config['id'])
                            except Exception as update_error:
                                logger.warning(f"Failed to update local config with extracted hp_options: {update_error}")
                        else:
                            logger.warning(f"No valid hp_options extracted from templates for {hp_type}")
                    else:
                        logger.warning(f"Failed to download templates for {hp_type}, falling back to basic templates")
                        # Fall back to creating basic templates locally
                        self._create_basic_templates_for_unknown_type(hp_type, remote_honeypot)
                        logger.info(f"Successfully created basic templates for {hp_type}")
                        
                except Exception as template_error:
                    logger.warning(f"Failed to download templates for {hp_type}: {template_error}, falling back to basic templates")
                    # Fall back to creating basic templates locally
                    try:
                        self._create_basic_templates_for_unknown_type(hp_type, remote_honeypot)
                        logger.info(f"Successfully created basic templates for {hp_type}")
                    except Exception as e:
                        logger.warning(f"Failed to create basic templates for {hp_type}: {e}")
                        # Continue with installation even if template creation fails
                    
            except Exception as template_error:
                logger.warning(f"Failed to download templates for {hp_type}: {template_error}")
                # Continue with installation even if template download fails
            
            # Create installation record
            installation_record = {
                'remote_honeypot_id': int(ident),
                'local_config_id': local_config['id'],
                'version_installed': remote_honeypot.get('version', '1.0.0'),
                'status': 'installed'
            }
            
            installation = db.create_local_installation(**installation_record)
            
            # TODO: Auto-deployment feature - commented out for future implementation
            # Handle auto-deployment if requested
            deployment_result = None
            # if installation_data.get('autoDeploy', False):
            #     try:
            #         logger.info(f"Auto-deployment requested for honeypot {hp_type}")
            #         
            #         # Create deployment data
            #         deployment_data = {
            #             'hp_type': hp_type,
            #             'hp_options': json.loads(hp_options) if isinstance(hp_options, str) else hp_options,
            #             'name': f"{remote_honeypot.get('name', 'Unknown')} (auto-deployed)",
            #             'description': remote_honeypot.get('description', ''),
            #             'tags': remote_honeypot.get('tags', []),
            #             'address': installation_data.get('address', '0.0.0.0'),
            #             'uuid': installation_data.get('uuid', ''),
            #             'auto_deployed': True,
            #             'installation_id': installation['id']
            #         }
            #         
            #         # Create deployment using the deployment resource
            #         from ..resources.deployments import DeploymentsResource
            #         deployment_resource = DeploymentsResource()
            #         
            #         # Create a mock request/response for deployment
            #         class MockRequest:
            #             def __init__(self, media):
            #                 self.media = media
            #         
            #         class MockResponse:
            #             def __init__(self):
            #                 self.status = None
            #                 self.text = None
            #         
            #         mock_req = MockRequest(deployment_data)
            #         mock_resp = MockResponse()
            #         
            #         # Call deployment creation
            #         deployment_resource.on_post(mock_req, mock_resp)
            #         
            #         if mock_resp.status == 201:
            #             deployment_result = json.loads(mock_resp.text)
            #             logger.info(f"Auto-deployment successful for honeypot {hp_type}")
            #         else:
            #             logger.warning(f"Auto-deployment failed for honeypot {hp_type}: {mock_resp.text}")
            #             
            #     except Exception as deploy_error:
            #         logger.warning(f"Auto-deployment failed for honeypot {hp_type}: {deploy_error}")
            
            results = {
                'installation': installation,
                'local_config': local_config,
                'remote_honeypot': remote_honeypot,
                'deployment': deployment_result
            }
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
            
        except ValueError as e:
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [{"title": "Installation Error", "description": str(e)}]})
        except Exception as e:
            logger.error(f"Failed to install honeypot {ident} from remote store: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Installation Failed",
                 "description": f"Failed to install honeypot: {str(e)}"}]})

    def _create_basic_templates_for_unknown_type(self, hp_type, honeypot_config):
        """
        Create basic templates for unknown honeypot types.
        
        Args:
            hp_type: Honeypot type
            honeypot_config: Honeypot configuration
        """
        import os
        from pathlib import Path
        
        # Get template directory
        template_dir = os.environ.get('HONEYPOT_TEMPLATES', 'templates')
        hp_template_dir = Path(template_dir) / hp_type
        hp_template_dir.mkdir(parents=True, exist_ok=True)
        
        # Create basic docker-compose.yml template
        docker_compose_template = f"""version: '2.4'
services:
  fluentbit:
    image: 4warned/fluentbit
    env_file:
      - stingar-hp.env
    ports:
      - "127.0.0.1:24284:24284"
      - "127.0.0.1:24284:24284/udp"

  {hp_type}:
    image: {honeypot_config.get('docker_image', f'4warned/{hp_type}:latest')}
    depends_on:
      - fluentbit
    links:
      - fluentbit:fluentbit
    env_file:
      - stingar-hp.env
    healthcheck:
      test: ["CMD", "python3", "/opt/checkin.py", "-i", "$HONEYPOT_IDENT", "-n", "$HONEYPOT_HOST", "-a", "$HONEYPOT_IP", "-t", "{hp_type}", "--tags", "$TAGS", "--fluent-host", "$FLUENTBIT_HOST", "--fluent-port", "$FLUENTBIT_PORT", "--fluent-app", "$FLUENTBIT_APP"]
      interval: $HONEYPOT_HEALTHCHECK_INTERVAL
      timeout: $HONEYPOT_HEALTHCHECK_TIMEOUT
      retries: 1
"""
        
        # Create basic stingar-hp.env.j2 template (Jinja2 template)
        env_template = """# Generated Environment file for honeypot deployment
# Generated at: {{ generated_at }}
# Deployment ID: {{ deployment.uuid }}

# Honeypot Configuration
HONEYPOT_IDENT={{ deployment.uuid }}
HONEYPOT_HOST={{ deployment.address }}
HONEYPOT_IP={{ honeypot_ip }}
HONEYPOT_ASN={{ deployment.asn }}

# Fluentbit Configuration
FLUENTBIT_HOST=fluentbit
FLUENTBIT_PORT=24284
FLUENTBIT_APP=stingar

# Health Check Configuration
HONEYPOT_HEALTHCHECK_INTERVAL={{ healthcheck_interval }}
HONEYPOT_HEALTHCHECK_TIMEOUT={{ healthcheck_timeout }}

# Tags
TAGS={{ config_info.get("tags", "") }}

# STINGAR Configuration
FLUENTD_HOST={{ fluent_host }}
FLUENTD_PORT={{ fluent_port }}
FLUENTD_KEY={{ fluent_key }}
"""
        
        # Write templates
        docker_compose_path = hp_template_dir / 'docker-compose.yml'
        env_path = hp_template_dir / 'stingar-hp.env.j2'
        
        with open(docker_compose_path, 'w') as f:
            f.write(docker_compose_template)
        
        with open(env_path, 'w') as f:
            f.write(env_template)
        
        logger.info(f"Created basic templates for {hp_type} at {hp_template_dir}")


class StoreSearchResource(object):
    """
    Search remote honeypots.
    """

    def on_get(self, req, resp):
        """
        Search remote honeypots by criteria with local cache fallback.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Extract search parameters
            query = req.params.get('q', '')
            category = req.params.get('category')
            hp_type = req.params.get('hp_type')
            page = int(req.params.get('page', 1))
            per_page = int(req.params.get('per_page', 50))
            
            # Try to search remote store first
            try:
                remote_store = SyncRemoteStore(
                    base_url=config['base_url'],
                    api_key=config['api_key'] if config['api_key'] else None,
                    timeout=config['timeout']
                )
                
                results = remote_store.search_honeypots(query, category, hp_type, page, per_page)
                
                # Cache the results locally
                self._cache_remote_honeypots(results)
                
                # Map fields for frontend response
                frontend_results = [map_honeypot_fields_for_frontend(honeypot) for honeypot in results]
                
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({"data": frontend_results, "source": "remote"}, default=json_converter, ensure_ascii=False)
                return
                
            except Exception as e:
                logger.warning(f"Failed to search honeypots from remote store: {e}")
                logger.debug("Falling back to local cached data")
            
            # Fallback to local cached data
            try:
                # Get all honeypots and filter locally for better search
                all_honeypots = db.get_remote_honeypots({})
                results = []
                
                for honeypot in all_honeypots:
                    # Apply search query filter
                    if query and query.strip():
                        query_lower = query.lower()
                        # Search across multiple fields
                        searchable_fields = [
                            honeypot.get('name', ''),
                            honeypot.get('display_name', ''),
                            honeypot.get('description', ''),
                            honeypot.get('author', ''),
                            honeypot.get('hp_type', '')
                        ]
                        if not any(query_lower in field.lower() for field in searchable_fields):
                            continue
                    
                    # Apply category filter
                    if category and honeypot.get('category') != category:
                        continue
                    
                    # Apply hp_type filter
                    if hp_type and honeypot.get('hp_type') != hp_type:
                        continue
                    
                    results.append(honeypot)
                
                # Apply pagination
                start_idx = (page - 1) * per_page
                end_idx = start_idx + per_page
                results = results[start_idx:end_idx]
                if results:
                    # Map fields for frontend response
                    frontend_results = [map_honeypot_fields_for_frontend(honeypot) for honeypot in results]
                    
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": frontend_results, "source": "cache"}, default=json_converter, ensure_ascii=False)
                else:
                    resp.status = falcon.HTTP_503
                    resp.text = json.dumps({"errors": [
                        {"title": "Service Unavailable",
                         "description": "Remote store unavailable and no cached data available."}]})
            except Exception as e:
                logger.error(f"Failed to search cached honeypots: {e}")
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Unable to connect to remote honeypot store or access cached data."}]})
            
        except Exception as e:
            logger.error(f"Unexpected error in store search resource: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})

    def _cache_remote_honeypots(self, honeypots):
        """Cache remote honeypots in local database."""
        try:
            for honeypot in honeypots:
                # Map HP_AppStore field names to apiarist field names
                mapped_honeypot = map_honeypot_fields(honeypot)
                
                # Check if honeypot already exists
                existing = db.get_remote_honeypots({'remote_id': mapped_honeypot.get('remote_id')})
                if existing:
                    # Update existing record
                    db.update_remote_honeypot(existing[0]['id'], **mapped_honeypot)
                else:
                    # Create new record
                    db.create_remote_honeypot(**mapped_honeypot)
            logger.debug(f"Cached {len(honeypots)} honeypots locally")
        except Exception as e:
            logger.error(f"Failed to cache honeypots: {e}")


class StoreCategoriesResource(object):
    """
    Get available honeypot categories.
    """

    def on_get(self, req, resp):
        """
        Get list of available categories with local cache fallback.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Try to get categories from remote store first
            try:
                remote_store = SyncRemoteStore(
                    base_url=config['base_url'],
                    api_key=config['api_key'] if config['api_key'] else None,
                    timeout=config['timeout']
                )
                
                categories = remote_store.get_categories()
                
                # Cache categories locally
                self._cache_categories(categories)
                
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({"data": categories, "source": "remote"}, default=json_converter, ensure_ascii=False)
                return
                
            except Exception as e:
                logger.warning(f"Failed to get categories from remote store: {e}")
                logger.debug("Falling back to local cached data")
            
            # Fallback to local cached data
            try:
                # Get unique categories from cached honeypots
                honeypots = db.get_remote_honeypots({})
                categories = list(set([hp['category'] for hp in honeypots if hp.get('category')]))
                
                if categories:
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": categories, "source": "cache"}, default=json_converter, ensure_ascii=False)
                else:
                    resp.status = falcon.HTTP_503
                    resp.text = json.dumps({"errors": [
                        {"title": "Service Unavailable",
                         "description": "Remote store unavailable and no cached categories available."}]})
            except Exception as e:
                logger.error(f"Failed to get cached categories: {e}")
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Unable to connect to remote honeypot store or access cached data."}]})
            
        except Exception as e:
            logger.error(f"Unexpected error in store categories resource: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})

    def _cache_categories(self, categories):
        """Cache categories locally (categories are derived from honeypots, so this is mainly for logging)."""
        try:
            logger.debug(f"Cached {len(categories)} categories locally")
        except Exception as e:
            logger.error(f"Failed to cache categories: {e}")


class StoreTagsResource(object):
    """
    Remote honeypot store tags API endpoint.
    """

    def on_get(self, req, resp):
        """
        Get available tags from remote store with local cache fallback.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Try to get tags from remote store first
            try:
                remote_store = SyncRemoteStore(
                    base_url=config['base_url'],
                    api_key=config['api_key'] if config['api_key'] else None,
                    timeout=config['timeout']
                )
                
                tags = remote_store.get_tags()
                
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({"data": tags, "source": "remote"}, default=json_converter, ensure_ascii=False)
                return
                
            except AuthenticationError as e:
                logger.warning(f"Authentication failed with remote store: {e}")
                logger.debug("Falling back to local cached data due to authentication failure")
                # Don't return here - fall through to cached data fallback
            except Exception as e:
                logger.warning(f"Failed to get tags from remote store: {e}")
                logger.debug("Falling back to local cached data")
            
            # Fallback to local cached data
            try:
                # Get unique tags from cached honeypots
                honeypots = db.get_remote_honeypots({})
                all_tags = []
                for hp in honeypots:
                    if hp.get('tags'):
                        all_tags.extend(hp['tags'])
                
                # Remove duplicates and sort
                unique_tags = sorted(list(set(all_tags)))
                
                if unique_tags:
                    resp.status = falcon.HTTP_200
                    resp.text = json.dumps({"data": unique_tags, "source": "cache"}, default=json_converter, ensure_ascii=False)
                else:
                    resp.status = falcon.HTTP_503
                    resp.text = json.dumps({"errors": [
                        {"title": "Service Unavailable",
                         "description": "Remote store unavailable and no cached tags available."}]})
            except Exception as e:
                logger.error(f"Failed to get cached tags: {e}")
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Unable to connect to remote honeypot store or access cached data."}]})
            
        except Exception as e:
            logger.error(f"Unexpected error in store tags resource: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})


class LocalInstallationsResource(object):
    """
    Local installations management.
    """

    def on_get(self, req, resp):
        """
        Get list of local installations.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            results = db.get_local_installations(req.params)
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
        except Exception as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})

    def on_delete(self, req, resp, ident):
        """
        Remove local installation.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Local installation ID
        """
        try:
            results = db.delete_local_installation(ident)
            if not results:
                resp.status = falcon.HTTP_404
                resp.text = json.dumps({"errors": [
                    {"title": "Installation Not Found",
                     "description": f"Local installation with id '{ident}' not found."}]})
                return
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
        except Exception as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Internal Server Error", "description": str(e)}]})


class StoreRequestsResource(object):
    """
    Proxy resource for honeypot requests endpoints.
    Forwards requests to HP App Store.
    """

    def _proxy_request(self, req, resp, method: str, endpoint_suffix: str = ''):
        """
        Proxy request to HP App Store.
        
        :param req: Falcon request
        :param resp: Falcon response
        :param method: HTTP method
        :param endpoint_suffix: Additional path after /store/requests
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Create remote store client
            remote_store = SyncRemoteStore(
                base_url=config['base_url'],
                api_key=config['api_key'] if config['api_key'] else None,
                timeout=config['timeout']
            )
            
            # Build endpoint URL
            endpoint = f'/api/v2/store/requests{endpoint_suffix}'
            
            # Get request body if present
            request_data = None
            if method in ['POST', 'PATCH', 'PUT']:
                try:
                    request_data = req.media
                except:
                    request_data = None
            
            # Make request to HP App Store
            import httpx
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if config['api_key']:
                headers['API-KEY'] = config['api_key']
            
            # Build query parameters
            params = dict(req.params) if req.params else {}
            
            # Make synchronous request
            url = f"{config['base_url'].rstrip('/')}{endpoint}"
            
            with httpx.Client(timeout=config['timeout']) as client:
                if method == 'GET':
                    response = client.get(url, headers=headers, params=params)
                elif method == 'POST':
                    response = client.post(url, headers=headers, json=request_data, params=params)
                elif method == 'PATCH':
                    response = client.patch(url, headers=headers, json=request_data, params=params)
                elif method == 'DELETE':
                    response = client.delete(url, headers=headers, params=params)
                else:
                    resp.status = falcon.HTTP_405
                    resp.text = json.dumps({"errors": [
                        {"title": "Method Not Allowed",
                         "description": f"Method {method} not supported."}]})
                    return
                
                # Forward response
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                try:
                    resp.text = response.text
                    resp.content_type = 'application/json'
                except:
                    resp.text = json.dumps({"errors": [
                        {"title": "Proxy Error",
                         "description": "Failed to proxy request to remote store."}]})
        except Exception as e:
            logger.error(f"Error proxying request to HP App Store: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Proxy Error",
                 "description": f"Failed to proxy request: {str(e)}"}]})

    def on_get(self, req, resp, ident=None):
        """Proxy GET request to HP App Store."""
        if ident:
            self._proxy_request(req, resp, 'GET', f'/{ident}')
        else:
            self._proxy_request(req, resp, 'GET')

    def on_post(self, req, resp, ident=None):
        """Proxy POST request to HP App Store."""
        if ident:
            self._proxy_request(req, resp, 'POST', f'/{ident}')
        else:
            self._proxy_request(req, resp, 'POST')

    def on_patch(self, req, resp, ident):
        """Proxy PATCH request to HP App Store."""
        self._proxy_request(req, resp, 'PATCH', f'/{ident}')

    def on_delete(self, req, resp, ident):
        """Proxy DELETE request to HP App Store."""
        self._proxy_request(req, resp, 'DELETE', f'/{ident}')


class StoreRequestVoteResource(object):
    """
    Proxy resource for honeypot request voting endpoints.
    Forwards requests to HP App Store.
    """

    def _proxy_request(self, req, resp, method: str, ident: str):
        """
        Proxy voting request to HP App Store.
        
        :param req: Falcon request
        :param resp: Falcon response
        :param method: HTTP method
        :param ident: Request ID
        """
        try:
            # Get configuration
            config = remote_store_config.get_all()
            
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            # Build endpoint URL
            endpoint = f'/api/v2/store/requests/{ident}/vote'
            
            # Get request body if present
            request_data = None
            if method in ['POST']:
                try:
                    request_data = req.media
                except:
                    request_data = None
            
            # Make request to HP App Store
            import httpx
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if config['api_key']:
                headers['API-KEY'] = config['api_key']
            
            # Build query parameters
            params = dict(req.params) if req.params else {}
            
            # Make synchronous request
            url = f"{config['base_url'].rstrip('/')}{endpoint}"
            
            with httpx.Client(timeout=config['timeout']) as client:
                if method == 'POST':
                    response = client.post(url, headers=headers, json=request_data, params=params)
                elif method == 'DELETE':
                    response = client.delete(url, headers=headers, params=params)
                elif method == 'GET':
                    response = client.get(url, headers=headers, params=params)
                else:
                    resp.status = falcon.HTTP_405
                    resp.text = json.dumps({"errors": [
                        {"title": "Method Not Allowed",
                         "description": f"Method {method} not supported."}]})
                    return
                
                # Forward response
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                try:
                    resp.text = response.text
                    resp.content_type = 'application/json'
                except:
                    resp.text = json.dumps({"errors": [
                        {"title": "Proxy Error",
                         "description": "Failed to proxy request to remote store."}]})
        except Exception as e:
            logger.error(f"Error proxying vote request to HP App Store: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Proxy Error",
                 "description": f"Failed to proxy request: {str(e)}"}]})

    def on_post(self, req, resp, ident):
        """Proxy POST vote request to HP App Store."""
        self._proxy_request(req, resp, 'POST', ident)

    def on_delete(self, req, resp, ident):
        """Proxy DELETE vote request to HP App Store."""
        self._proxy_request(req, resp, 'DELETE', ident)


class StoreRequestVoteStatusResource(object):
    """
    Proxy resource for honeypot request vote status endpoint.
    Forwards requests to HP App Store.
    """

    def on_get(self, req, resp, ident):
        """Proxy GET vote status request to HP App Store."""
        try:
            config = remote_store_config.get_all()
            if not config['enabled']:
                resp.status = falcon.HTTP_503
                resp.text = json.dumps({"errors": [
                    {"title": "Service Unavailable",
                     "description": "Remote store is disabled."}]})
                return
            
            import httpx
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            if config['api_key']:
                headers['API-KEY'] = config['api_key']
            
            params = dict(req.params) if req.params else {}
            endpoint = f'/api/v2/store/requests/{ident}/vote-status'
            url = f"{config['base_url'].rstrip('/')}{endpoint}"
            
            with httpx.Client(timeout=config['timeout']) as client:
                response = client.get(url, headers=headers, params=params)
                resp.status = getattr(falcon, f'HTTP_{response.status_code}', falcon.HTTP_500)
                resp.text = response.text
                resp.content_type = 'application/json'
        except Exception as e:
            logger.error(f"Error proxying vote status request: {e}")
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Proxy Error",
                 "description": f"Failed to proxy request: {str(e)}"}]}) 