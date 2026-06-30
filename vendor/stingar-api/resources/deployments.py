import json
import datetime
import asyncio
import logging

import falcon
from falcon.media.validators import jsonschema

from config_parser import EnvironmentConfigParser
from resources import db, builders
from schemas import deployment_schema, deployment_status_schema
from util import json_converter
# Import from util.security - import from the util package (directory), not util.py (file)
# The util package __init__.py handles importing from util.py for backward compatibility
from util import security
sanitize_deployment_data = security.sanitize_deployment_data
validate_hp_options = security.validate_hp_options
sanitize_honeypot_config = security.sanitize_honeypot_config
from services.template_manager import TemplateManager
from services.remote_store import SyncRemoteStore
from foundation.generic import GenericFoundation


CONFIG = EnvironmentConfigParser()
logger = logging.getLogger(__name__)


class DeploymentsResource(object):
    """
    Honeypot deployments API endpoint
    """

    def __init__(self):
        # Use container template directory from environment variable
        import os
        template_dir = os.environ.get('HONEYPOT_TEMPLATES', 'templates')
        self.template_manager = TemplateManager(template_dir)
        self.remote_store = None  # Will be initialized when needed

    def _initialize_remote_store(self):
        """Initialize remote store client if not already done."""
        if self.remote_store is None:
            from config.remote_store import remote_store_config
            config = remote_store_config.get_all()
            self.remote_store = SyncRemoteStore(
                base_url=config['base_url'],
                api_key=config['api_key'],
                timeout=config['timeout']
            )

    def _ensure_templates_exist(self, hp_type, honeypot_config, deployment_data):
        """
        Ensure template files exist for the honeypot type.
        Downloads from HP App Store if local templates don't exist.
        
        Args:
            hp_type: Honeypot type
            honeypot_config: Honeypot configuration
            deployment_data: Deployment data
            
        Returns:
            True if templates are available, False otherwise
        """
        # Check if local templates exist
        if self.template_manager.template_exists(hp_type):
            logger.debug(f"Templates already exist for {hp_type}")
            return True
        
        # Try to download templates from HP App Store
        try:
            logger.info(f"Templates not found locally for {hp_type}, attempting to download from remote store")
            self._initialize_remote_store()
            
            # Prepare configuration for template generation
            template_config = {
                'hp_type': hp_type,
                'name': honeypot_config.get('name', hp_type),
                'hp_options': honeypot_config.get('hp_options', {}),
                'docker_image': honeypot_config.get('docker_image', f'4warned/{hp_type}:latest'),
                'ports': honeypot_config.get('ports', []),
                'volumes': honeypot_config.get('volumes', []),
                'environment': honeypot_config.get('environment', {})
            }
            
            # Download and save templates
            success = asyncio.run(self.template_manager.download_and_save_templates(
                hp_type, self.remote_store, template_config, deployment_data
            ))
            
            if success:
                logger.info(f"Successfully downloaded templates for {hp_type}")
                return True
            else:
                logger.warning(f"Failed to download templates for {hp_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error ensuring templates exist for {hp_type}: {e}", exc_info=True)
            return False

    def _get_builder(self, hp_type):
        """
        Get builder for honeypot type, fallback to generic builder if not found.
        
        Args:
            hp_type: Honeypot type
            
        Returns:
            Builder instance
        """
        # Try to get specific builder
        if hp_type in builders:
            return builders[hp_type]
        
        # Fallback to generic builder
        print(f"No specific builder found for {hp_type}, using generic builder")
        return GenericFoundation()

    def on_get(self, req, resp):
        """
        Get honeypot deployment records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.get_deployments(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(deployment_schema)
    def on_post(self, req, resp):
        """
        Create new honeypot deployment record.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            params = req.media
            logger.info(f"Received deployment request: hp_type={params.get('hp_type')}, address={params.get('address')}")
            
            # Sanitize deployment data to prevent command injection
            params = sanitize_deployment_data(params)
            
            # Validate hp_options if present
            if 'hp_options' in params:
                if isinstance(params['hp_options'], str):
                    try:
                        hp_options_dict = json.loads(params['hp_options'])
                        is_valid, error_msg = validate_hp_options(hp_options_dict)
                        if not is_valid:
                            resp.status = falcon.HTTP_400
                            resp.text = json.dumps({"errors": [
                                {"title": "Invalid Configuration",
                                 "description": f"Security validation failed: {error_msg}"}]})
                            return
                    except (json.JSONDecodeError, TypeError):
                        pass  # Will be caught later
                elif isinstance(params['hp_options'], dict):
                    is_valid, error_msg = validate_hp_options(params['hp_options'])
                    if not is_valid:
                        resp.status = falcon.HTTP_400
                        resp.text = json.dumps({"errors": [
                            {"title": "Invalid Configuration",
                             "description": f"Security validation failed: {error_msg}"}]})
                        return
            
            # Check if this is a store configuration deployment
            if 'config_id' in params:
                # Handle store configuration deployment
                config_id = params.pop('config_id')
                config = db.get_config(config_id)
                if config:
                    # Use configuration from store
                    params['hp_type'] = config['hp_type']
                    
                    # Sanitize hp_options from config before using
                    if config['hp_options']:
                        try:
                            config_metadata = json.loads(config['hp_options'])
                            # Sanitize the configuration
                            config_metadata = sanitize_honeypot_config(config_metadata)
                            # Validate the sanitized configuration
                            is_valid, error_msg = validate_hp_options(config_metadata)
                            if not is_valid:
                                resp.status = falcon.HTTP_400
                                resp.text = json.dumps({"errors": [
                                    {"title": "Invalid Store Configuration",
                                     "description": f"Store configuration contains dangerous commands: {error_msg}"}]})
                                return
                            
                            # Add config metadata
                            config_metadata['_store_config'] = {
                                'id': config['id'],
                                'name': config['name'],
                                'source': 'store_config'
                            }
                            params['hp_options'] = json.dumps(config_metadata)
                        except (json.JSONDecodeError, TypeError) as e:
                            resp.status = falcon.HTTP_400
                            resp.text = json.dumps({"errors": [
                                {"title": "Invalid Configuration",
                                 "description": f"Failed to parse store configuration: {str(e)}"}]})
                            return
                    else:
                        params['hp_options'] = '{}'
            
            # Check if this is a remote honeypot installation
            elif 'remote_honeypot_id' in params:
                # Handle remote honeypot deployment
                remote_hp = db.get_remote_honeypot(params['remote_honeypot_id'])
                if remote_hp:
                    # Generate configuration from remote metadata
                    config = self._generate_config_from_remote(remote_hp, params)
                    params['hp_type'] = remote_hp['hp_type']
                    params['hp_options'] = json.dumps(config)
                    
                    # Update installation status
                    installations = db.get_local_installations({
                        'remote_honeypot_id': params['remote_honeypot_id']
                    })
                    if installations:
                        db.update_local_installation(
                            installations[0]['id'],
                            status='deploying',
                            deployment_status=1
                        )
            
            hp_options = json.dumps(params.pop('hp_options', {}))
            tags = params.pop('tags', [])
            
            # Safety check: remove config_id and remote_honeypot_id if they somehow still exist
            # (they should have been popped earlier, but be defensive)
            params.pop('config_id', None)
            params.pop('remote_honeypot_id', None)

            # Ensure templates exist for the honeypot type
            hp_type = params.get('hp_type')
            if hp_type:
                honeypot_config = {
                    'hp_type': hp_type,
                    'hp_options': hp_options,
                    'name': params.get('name', hp_type),
                    'docker_image': params.get('docker_image', f'4warned/{hp_type}:latest')
                }
                
                if not self._ensure_templates_exist(hp_type, honeypot_config, params):
                    resp.status = falcon.HTTP_400
                    resp.text = json.dumps({"errors": [
                        {"title": "Template Not Available",
                         "description": f"No templates available for honeypot type '{hp_type}' and unable to download from remote store."}]})
                    return

            results = db.create_deployment(hp_options=hp_options, **params)
            result_id = results.get('id', None)
            if not results or result_id is None:
                resp.status = falcon.HTTP_400
                resp.text = json.dumps({"errors": [
                    {"title": "Unable to create deployment",
                     "description": "Unable to create honeypot deployment record."}]})
                return

            for tag in tags:
                tag_id = tag.get('id', None)
                if tag_id is None:
                    continue
                results, added = db.add_tag_to_deployment(ident=result_id, tag_id=tag_id)

            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)
            logger.info(f"Deployment created successfully: id={results.get('id')}, uuid={results.get('uuid')}, hp_type={results.get('hp_type')}")
            
        except Exception as e:
            logger.error(f"Error creating deployment: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [{"title": "Deployment Error", "description": str(e)}]})

    def _generate_config_from_remote(self, remote_hp, deployment_data):
        """
        Generate local configuration from remote honeypot metadata.
        
        :param remote_hp: Remote honeypot metadata
        :param deployment_data: Deployment configuration
        :return: Generated configuration
        """
        # Start with default configuration from remote honeypot
        config = json.loads(remote_hp['default_configuration']) if remote_hp['default_configuration'] else {}
        
        # Apply deployment-specific overrides
        if 'hp_options' in deployment_data:
            config.update(deployment_data['hp_options'])
        
        # Add remote honeypot metadata
        config['_remote_honeypot'] = {
            'id': remote_hp['id'],
            'name': remote_hp['name'],
            'version': remote_hp['version'],
            'source': 'remote_store'
        }
        
        return config


class DeploymentsComposeResource(object):
    """
    Honeypot Deployments docker-compose file API endpoint
    """

    @jsonschema.validate(deployment_schema)
    def on_post(self, req, resp):
        """
        Create docker-compose file from deployment data.

        :param req: Falcon request
        :param resp: Falcon response
        """
        params = req.media
        
        # Check if this is a store configuration deployment
        if 'config_id' in params:
            # Handle store configuration deployment - load hp_options from config
            config_id = params.pop('config_id')
            config = db.get_config(config_id)
            if config and config.get('hp_options'):
                try:
                    # Use hp_options from config (which includes docker_image)
                    config_hp_options = json.loads(config['hp_options'])
                    # Merge with any hp_options provided in request (request takes precedence for non-docker fields)
                    request_hp_options = params.pop('hp_options', {})
                    if isinstance(request_hp_options, str):
                        try:
                            request_hp_options = json.loads(request_hp_options)
                        except json.JSONDecodeError:
                            request_hp_options = {}
                    
                    # Merge: start with config (has docker_image), update with request
                    merged_hp_options = config_hp_options.copy()
                    merged_hp_options.update(request_hp_options)
                    
                    # Explicitly preserve docker_image from config
                    if 'docker_image' in config_hp_options:
                        merged_hp_options['docker_image'] = config_hp_options['docker_image']
                    if 'docker_image_name' in config_hp_options:
                        merged_hp_options['docker_image_name'] = config_hp_options['docker_image_name']
                    if 'docker_tag' in config_hp_options:
                        merged_hp_options['docker_tag'] = config_hp_options['docker_tag']
                    
                    params['hp_type'] = config['hp_type']
                    hp_options = json.dumps(merged_hp_options)
                    logger.debug(f"Using config_id {config_id}, merged hp_options includes docker_image: {merged_hp_options.get('docker_image')}")
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse config hp_options for config_id {config_id}: {e}")
                    # Fall back to request hp_options
                    hp_options = json.dumps(params.pop('hp_options', {}))
            else:
                logger.warning(f"Config {config_id} not found or has no hp_options, using request hp_options")
                hp_options = json.dumps(params.pop('hp_options', {}))
        else:
            # No config_id - use hp_options from request
            hp_options = json.dumps(params.pop('hp_options', {}))
        
        params.pop('tags', [])
        # Safety check: remove config_id and remote_honeypot_id if they somehow still exist
        # (they should have been popped earlier, but be defensive)
        params.pop('config_id', None)
        params.pop('remote_honeypot_id', None)
        deployment_results = db.create_deployment_no_save(hp_options=hp_options, **params)

        if not deployment_results:
            resp.text = json.dumps({"errors": [
                {"title": "Unable to create deployment",
                 "description": "Unable to create honeypot deployment record."}]})
        hp_type = deployment_results.get('hp_type')
        template = CONFIG.get("HONEYPOT", "TEMPLATES") + "/" + hp_type + "/docker-compose.yml"
        docker_repository = CONFIG.get("DOCKER", "REPOSITORY")
        
        # Get appropriate builder (specific or generic)
        builder = builders.get(hp_type, GenericFoundation())
        compose_file = builder.build_docker_compose(compose_template=template,
                                                   deployment=deployment_results,
                                                   docker_repository=docker_repository)
        resp.status = falcon.HTTP_200
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = compose_file


class DeploymentsEnvResource(object):
    """
    Honeypot Deployments ENV file API endpoint
    """

    @jsonschema.validate(deployment_schema)
    def on_post(self, req, resp):
        """
        Create ENV file from deployment data.

        :param req: Falcon request
        :param resp: Falcon response
        """
        params = req.media
        
        # Check if this is a store configuration deployment
        if 'config_id' in params:
            # Handle store configuration deployment - load hp_options from config
            config_id = params.pop('config_id')
            config = db.get_config(config_id)
            if config and config.get('hp_options'):
                try:
                    # Use hp_options from config (which includes docker_image)
                    config_hp_options = json.loads(config['hp_options'])
                    # Merge with any hp_options provided in request (request takes precedence for non-docker fields)
                    request_hp_options = params.pop('hp_options', {})
                    if isinstance(request_hp_options, str):
                        try:
                            request_hp_options = json.loads(request_hp_options)
                        except json.JSONDecodeError:
                            request_hp_options = {}
                    
                    # Merge: start with config (has docker_image), update with request
                    merged_hp_options = config_hp_options.copy()
                    merged_hp_options.update(request_hp_options)
                    
                    # Explicitly preserve docker_image from config
                    if 'docker_image' in config_hp_options:
                        merged_hp_options['docker_image'] = config_hp_options['docker_image']
                    if 'docker_image_name' in config_hp_options:
                        merged_hp_options['docker_image_name'] = config_hp_options['docker_image_name']
                    if 'docker_tag' in config_hp_options:
                        merged_hp_options['docker_tag'] = config_hp_options['docker_tag']
                    
                    params['hp_type'] = config['hp_type']
                    hp_options = json.dumps(merged_hp_options)
                    logger.debug(f"Using config_id {config_id}, merged hp_options includes docker_image: {merged_hp_options.get('docker_image')}")
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse config hp_options for config_id {config_id}: {e}")
                    # Fall back to request hp_options
                    hp_options = json.dumps(params.pop('hp_options', {}))
            else:
                logger.warning(f"Config {config_id} not found or has no hp_options, using request hp_options")
                hp_options = json.dumps(params.pop('hp_options', {}))
        else:
            # No config_id - use hp_options from request
            hp_options = json.dumps(params.pop('hp_options', {}))
        
        tags = params.pop('tags', [])
        # Safety check: remove config_id and remote_honeypot_id if they somehow still exist
        # (they should have been popped earlier, but be defensive)
        params.pop('config_id', None)
        params.pop('remote_honeypot_id', None)
        deployment_results = db.create_deployment_no_save(hp_options=hp_options, **params)

        if not deployment_results:
            resp.text = json.dumps({"errors": [
                {"title": "Unable to create deployment",
                 "description": "Unable to create honeypot deployment record."}]})

        for tag in tags:
            tag_id = tag.get('id', None)
            if tag_id is None:
                continue
            results = db.get_tag(ident=tag_id)
            deployment_results['tags'].append(results)

        hp_type = deployment_results.get('hp_type')
        template = CONFIG.get("HONEYPOT", "TEMPLATES") + "/" + hp_type + "/stingar-hp.env.j2"
        fluent_host = CONFIG.get("FLUENTD", "REMOTE_HOST")
        fluent_port = CONFIG.get("FLUENTD", "PORT")
        fluent_key = CONFIG.get("FLUENTD", "KEY")
        
        # Get appropriate builder (specific or generic)
        builder = builders.get(hp_type, GenericFoundation())
        env_file = builder.build_honeypot_env(env_template=template,
                                             deployment=deployment_results,
                                             fluent_host=fluent_host,
                                             fluent_port=fluent_port,
                                             fluent_key=fluent_key)
        resp.status = falcon.HTTP_200
        resp.content_type = falcon.MEDIA_TEXT
        resp.text = env_file


class DeploymentResource(object):
    """
    Honeypot deployments API endpoint
    """

    def on_get(self, req, resp, ident):
        """
        Get single honeypot deployment record by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot deployment record
        :type ident: str
        """
        deployment_results = db.get_deployment(ident=ident)
        if not deployment_results:
            resp.text = json.dumps({"errors": [
                {"title": "Deployment Not Found",
                 "description": "Deployment with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": deployment_results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete single honeypot deployment record by id.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot deployment record
        :type ident: str
        """
        results = db.delete_deployment(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Deployment Not Found",
                 "description": "Deployment with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class DeploymentComposeResource(object):
    """
    Honeypot docker-compose file API endpoint
    """

    def on_get(self, req, resp, ident):
        """
        Get docker-compose.yml file for deployment.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot deployment record
        :type ident: str
        """
        deployment_results = db.get_deployment(ident=ident)
        if not deployment_results:
            logger.warning(f"Deployment not found: id={ident}")
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "Deployment Not Found",
                 "description": "Deployment with id '" + ident + "' not found."}]})
            return
        
        hp_type = deployment_results.get('hp_type')
        template = CONFIG.get("HONEYPOT", "TEMPLATES") + "/" + hp_type + "/docker-compose.yml"
        docker_repository = CONFIG.get("DOCKER", "REPOSITORY")
        
        try:
            logger.debug(f"Generating docker-compose for deployment {ident}, template: {template}")
            # Get appropriate builder (specific or generic)
            builder = builders.get(hp_type, GenericFoundation())
            compose_file = builder.build_docker_compose(compose_template=template,
                                                       deployment=deployment_results,
                                                       docker_repository=docker_repository)
            resp.status = falcon.HTTP_200
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = compose_file
            logger.info(f"Successfully generated docker-compose for deployment {ident}")
        except Exception as e:
            logger.error(f"Error generating docker-compose for deployment {ident}: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Template Error",
                 "description": f"Failed to generate docker-compose file: {str(e)}"}]})


class DeploymentEnvResource(object):
    """
    Honeypot ENV file API endpoint
    """

    def on_get(self, req, resp, ident):
        """
        Get stingar-hp.env file for deployment.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot deployment record
        :type ident: str
        """
        deployment_results = db.get_deployment(ident=ident)
        if not deployment_results:
            logger.warning(f"Deployment not found for env file: id={ident}")
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "Deployment Not Found",
                 "description": "Deployment with id '" + ident + "' not found."}]})
            return
        
        hp_type = deployment_results.get('hp_type')
        template = CONFIG.get("HONEYPOT", "TEMPLATES") + "/" + hp_type + "/stingar-hp.env.j2"
        fluent_host = CONFIG.get("FLUENTD", "REMOTE_HOST")
        fluent_port = CONFIG.get("FLUENTD", "PORT")
        fluent_key = CONFIG.get("FLUENTD", "KEY")
        
        try:
            logger.debug(f"Generating env file for deployment {ident}, template: {template}")
            # Get appropriate builder (specific or generic)
            builder = builders.get(hp_type, GenericFoundation())
            env_file = builder.build_honeypot_env(env_template=template,
                                                 deployment=deployment_results,
                                                 fluent_host=fluent_host,
                                                 fluent_port=fluent_port,
                                                 fluent_key=fluent_key)
            resp.status = falcon.HTTP_200
            resp.content_type = falcon.MEDIA_TEXT
            resp.text = env_file
            logger.info(f"Successfully generated env file for deployment {ident}")
        except Exception as e:
            logger.error(f"Error generating env file for deployment {ident}: {e}", exc_info=True)
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Template Error",
                 "description": f"Failed to generate env file: {str(e)}"}]})


class DeploymentStatusResource(object):
    """
    Honeypot deployment status API endpoint
    """

    @jsonschema.validate(deployment_status_schema)
    def on_post(self, req, resp, ident):
        """
        Update the deployment status of a honeypot deployment record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of the honeypot deployment record
        :type ident: str
        """
        params = req.media
        status = int(params['status'])
        if status not in range(-1, 3):
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"errors": [
                {"title": "Invalid Status",
                 "description": "Invalid status value. Please use -1, 0, or 1."}]})
        elif not db.get_deployment(ident=ident):
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"errors": [
                {"title": "Deployment Not Found",
                 "description": "Deployment with id '" + ident + "' not found."}]})
        else:
            deployed = None
            if status == 2:
                deployed = datetime.datetime.utcnow().isoformat() + "Z"
            results = db.update_deployment(ident, status=status, deployed=deployed)
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class DeployResource(object):
    """
    Honeypot deployment API endpoint for deploying a honeypot. Used by Langstroth.
    """

    def on_post(self, req, resp):
        """
        Fetch next undeployment deployment record.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.next_deployment()
        if not results:
            resp.status = falcon.HTTP_200
            resp.text = {}
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)