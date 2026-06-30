"""
Template Manager Service for Apiarist.

This service manages template files for honeypot deployments, including
local template discovery, remote template download, and caching functionality.
"""

import os
import tempfile
import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional
import asyncio

logger = logging.getLogger(__name__)


class TemplateManager:
    """
    Manages template files for honeypot deployments.
    Handles both local templates and remote template downloads.
    """

    def __init__(self, template_dir: str = None):
        """
        Initialize template manager.
        
        Args:
            template_dir: Directory containing template files (defaults to HONEYPOT_TEMPLATES env var)
        """
        if template_dir is None:
            import os
            template_dir = os.environ.get('HONEYPOT_TEMPLATES', 'templates')
        
        self.template_dir = Path(template_dir)
        self.template_dir.mkdir(parents=True, exist_ok=True)
    
    def get_local_template_paths(self, hp_type: str) -> Dict[str, Optional[Path]]:
        """
        Get paths to local template files for a honeypot type.
        
        Args:
            hp_type: Honeypot type (e.g., 'cowrie', 'dionaea')
            
        Returns:
            Dictionary with template file paths (None if not found)
        """
        hp_template_dir = self.template_dir / hp_type
        hp_template_dir.mkdir(parents=True, exist_ok=True)
        
        return {
            'docker_compose': hp_template_dir / 'docker-compose.yml',
            'environment': hp_template_dir / 'stingar-hp.env.j2',
            'config': hp_template_dir / 'honeypot_config.json'
        }
    
    def template_exists(self, hp_type: str) -> bool:
        """
        Check if local templates exist for a honeypot type.
        
        Args:
            hp_type: Honeypot type
            
        Returns:
            True if core template files exist (docker-compose and environment)
            Config file is optional and not required for template existence check
        """
        paths = self.get_local_template_paths(hp_type)
        # Only require core template files to exist
        # Config file is optional and can be downloaded later
        return (paths['docker_compose'].exists() and 
                paths['environment'].exists())
    
    def config_exists(self, hp_type: str) -> bool:
        """
        Check if configuration file exists for a honeypot type.
        
        Args:
            hp_type: Honeypot type
            
        Returns:
            True if configuration file exists
        """
        paths = self.get_local_template_paths(hp_type)
        return paths['config'].exists()
    
    def has_complete_templates(self, hp_type: str) -> bool:
        """
        Check if all template files exist for a honeypot type.
        
        Args:
            hp_type: Honeypot type
            
        Returns:
            True if all template files exist (docker-compose, environment, and config)
        """
        paths = self.get_local_template_paths(hp_type)
        return (paths['docker_compose'].exists() and 
                paths['environment'].exists() and
                paths['config'].exists())
    
    async def download_and_save_templates(self, hp_type: str, 
                                        remote_store, 
                                        honeypot_config: Dict[str, Any],
                                        deployment_info: Optional[Dict[str, Any]] = None) -> bool:
        """
        Download templates from HP App Store and save them locally.
        
        Args:
            hp_type: Honeypot type
            remote_store: Remote store client instance
            honeypot_config: Honeypot configuration
            deployment_info: Optional deployment information
            
        Returns:
            True if templates were successfully downloaded and saved
        """
        try:
            logger.info(f"Downloading templates for honeypot type: {hp_type}")
            
            # Generate template on HP App Store
            template_result = await remote_store.generate_template(
                honeypot_config, deployment_info
            )
            
            deployment_id = template_result['data'].get('deployment_id', template_result['data']['template_id'])
            logger.debug(f"Generated template with deployment ID: {deployment_id}")
            
            # Download template files
            template_files = await remote_store.download_template_files(deployment_id)
            
            # Save templates locally
            paths = self.get_local_template_paths(hp_type)
            
            # Save docker-compose.yml
            with open(paths['docker_compose'], 'w') as f:
                f.write(template_files['docker_compose'])
            logger.debug(f"Saved docker-compose.yml to: {paths['docker_compose']}")
            
            # Save stingar-hp.env.j2 (convert from .env to .j2 template)
            env_content = self._convert_env_to_template(template_files['environment'])
            with open(paths['environment'], 'w') as f:
                f.write(env_content)
            logger.debug(f"Saved stingar-hp.env.j2 to: {paths['environment']}")
            
            # Save honeypot_config.json if available
            config_path = hp_template_dir / 'honeypot_config.json'
            if 'config' in template_files:
                with open(config_path, 'w') as f:
                    f.write(template_files['config'])
                logger.debug(f"Saved honeypot_config.json to: {config_path}")
            else:
                logger.warning(f"Config file not found in template files for {hp_type}")
            
            logger.info(f"Successfully downloaded and saved templates for {hp_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download templates for {hp_type}: {e}")
            return False
    
    def download_and_save_templates_sync(self, hp_type: str, 
                                       remote_store, 
                                       honeypot_config: Dict[str, Any],
                                       deployment_info: Optional[Dict[str, Any]] = None) -> bool:
        """
        Synchronous version of download_and_save_templates for use in non-async contexts.
        
        Args:
            hp_type: Honeypot type
            remote_store: Remote store client instance
            honeypot_config: Honeypot configuration
            deployment_info: Optional deployment information
            
        Returns:
            True if templates were successfully downloaded and saved
        """
        try:
            logger.info(f"Downloading templates synchronously for honeypot type: {hp_type}")
            
            # Generate template on HP App Store
            template_result = remote_store.generate_template(
                honeypot_config, deployment_info
            )
            
            deployment_id = template_result['data'].get('deployment_id', template_result['data']['template_id'])
            logger.debug(f"Generated template with deployment ID: {deployment_id}")
            
            # Download template files
            template_files = remote_store.download_template_files(deployment_id)
            
            # Save templates locally
            paths = self.get_local_template_paths(hp_type)
            
            # Save docker-compose.yml
            with open(paths['docker_compose'], 'w') as f:
                f.write(template_files['docker_compose'])
            logger.debug(f"Saved docker-compose.yml to: {paths['docker_compose']}")
            
            # Save stingar-hp.env.j2 (convert from .env to .j2 template)
            env_content = self._convert_env_to_template(template_files['environment'])
            with open(paths['environment'], 'w') as f:
                f.write(env_content)
            logger.debug(f"Saved stingar-hp.env.j2 to: {paths['environment']}")
            
            # Save honeypot_config.json if available
            config_path = paths['config']
            if 'config' in template_files:
                with open(config_path, 'w') as f:
                    f.write(template_files['config'])
                logger.debug(f"Saved honeypot_config.json to: {config_path}")
                
                # Extract hp_options from config and update local configuration
                try:
                    config_data = json.loads(template_files['config'])
                    if 'hp_options' in config_data and config_data['hp_options']:
                        logger.info(f"Extracted hp_options from config: {config_data['hp_options']}")
                        # Return the hp_options so the caller can update the local config
                        return True, config_data['hp_options']
                    else:
                        logger.warning(f"No hp_options found in config for {hp_type}")
                        return True, {}
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse config file for {hp_type}: {e}")
                    return True, {}
            else:
                logger.warning(f"Config file not found in template files for {hp_type}")
                return True, {}
            
        except Exception as e:
            logger.error(f"Failed to download templates for {hp_type}: {e}")
            return False, {}
    
    def _convert_env_to_template(self, env_content: str) -> str:
        """
        Convert environment file content to Jinja2 template format.
        
        Args:
            env_content: Raw environment file content
            
        Returns:
            Jinja2 template content
        """
        # Replace static values with template variables
        template_content = env_content.replace(
            'HONEYPOT_IDENT=', 'HONEYPOT_IDENT={{ deployment.uuid }}'
        ).replace(
            'HONEYPOT_HOST=', 'HONEYPOT_HOST={{ deployment.address }}'
        ).replace(
            'HONEYPOT_IP=', 'HONEYPOT_IP={{ honeypot_ip }}'
        ).replace(
            'TAGS=', 'TAGS={{ config_info.get("tags", "") }}'
        )
        
        return template_content
    
    def cleanup_old_templates(self, max_age_days: int = 30) -> Dict[str, Any]:
        """
        Clean up old template files.
        
        Args:
            max_age_days: Maximum age of templates in days
            
        Returns:
            Dictionary with cleanup statistics
        """
        import time
        from datetime import datetime, timedelta
        
        cutoff_time = datetime.now() - timedelta(days=max_age_days)
        cleaned_files = []
        failed_files = []
        
        try:
            for hp_type_dir in self.template_dir.iterdir():
                if not hp_type_dir.is_dir():
                    continue
                
                for template_file in hp_type_dir.iterdir():
                    if not template_file.is_file():
                        continue
                    
                    # Check file modification time
                    mtime = datetime.fromtimestamp(template_file.stat().st_mtime)
                    if mtime < cutoff_time:
                        try:
                            template_file.unlink()
                            cleaned_files.append(str(template_file))
                            logger.debug(f"Cleaned up old template: {template_file}")
                        except Exception as e:
                            failed_files.append(str(template_file))
                            logger.error(f"Failed to clean up template {template_file}: {e}")
            
            logger.info(f"Template cleanup completed: {len(cleaned_files)} files cleaned, {len(failed_files)} failed")
            
            return {
                'cleaned_files': cleaned_files,
                'failed_files': failed_files,
                'total_cleaned': len(cleaned_files),
                'total_failed': len(failed_files)
            }
            
        except Exception as e:
            logger.error(f"Error during template cleanup: {e}")
            return {
                'cleaned_files': [],
                'failed_files': [],
                'total_cleaned': 0,
                'total_failed': 0,
                'error': str(e)
            }
