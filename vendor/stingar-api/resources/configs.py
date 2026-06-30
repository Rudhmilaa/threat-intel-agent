import json
import datetime

import falcon
from resources import db
from util import json_converter


class ConfigsResource(object):
    """
    Configuration templates API endpoint
    """

    def on_get(self, req, resp):
        """
        Get available honeypot configuration templates.

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            # Get all configuration templates
            configs = db.get_configs({})
            
            # Transform configs for frontend consumption
            transformed_configs = []
            for config in configs:
                # Parse hp_options JSON string back to object
                hp_options = {}
                if config.get('hp_options'):
                    try:
                        hp_options = json.loads(config['hp_options'])
                    except (json.JSONDecodeError, TypeError):
                        hp_options = {}
                
                transformed_config = {
                    'id': config['id'],
                    'name': config['name'],
                    'hp_type': config['hp_type'],
                    'hp_options': hp_options,
                    'created': config['created'],
                    'updated': config['updated'],
                    'source': 'store'  # Indicate this is from store installation
                }
                transformed_configs.append(transformed_config)
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": transformed_configs}, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Config Fetch Error", "description": str(e)}]})

    def on_post(self, req, resp):
        """
        Cleanup invalid configurations (remove those with empty hp_type).

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
            action = req.media.get('action')
            
            if action != 'cleanup_invalid':
                resp.status = falcon.HTTP_400
                resp.text = json.dumps({"errors": [
                    {"title": "Invalid Action", "description": "Only 'cleanup_invalid' action is supported."}]})
                return
            
            # Get all configurations
            all_configs = db.get_configs({})
            
            # Find invalid configurations
            invalid_configs = []
            for config in all_configs:
                if not config.get('hp_type') or config['hp_type'].strip() == '':
                    invalid_configs.append(config)
            
            if not invalid_configs:
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({
                    "data": {
                        "message": "No invalid configurations found",
                        "deleted_count": 0,
                        "deleted_configs": []
                    }
                }, default=json_converter, ensure_ascii=False)
                return
            
            # Delete invalid configurations
            deleted_configs = []
            for config in invalid_configs:
                try:
                    result = db.delete_config(config['id'])
                    if result:
                        deleted_configs.append({
                            'id': config['id'],
                            'name': config['name'],
                            'hp_type': config['hp_type']
                        })
                except Exception as e:
                    # Log error but continue with other deletions
                    print(f"Failed to delete config {config['id']}: {e}")
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({
                "data": {
                    "message": f"Successfully deleted {len(deleted_configs)} invalid configurations",
                    "deleted_count": len(deleted_configs),
                    "deleted_configs": deleted_configs
                }
            }, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Cleanup Error", "description": str(e)}]})



class ConfigResource(object):
    """
    Individual configuration template API endpoint
    """

    def on_get(self, req, resp, ident):
        """
        Get specific configuration template by ID.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Configuration ID
        """
        try:
            config = db.get_config(ident)
            if not config:
                resp.status = falcon.HTTP_404
                resp.text = json.dumps({"errors": [
                    {"title": "Not Found", "description": "Configuration template not found."}]})
                return
            
            # Parse hp_options JSON string back to object
            hp_options = {}
            if config.get('hp_options'):
                try:
                    hp_options = json.loads(config['hp_options'])
                except (json.JSONDecodeError, TypeError):
                    hp_options = {}
            
            transformed_config = {
                'id': config['id'],
                'name': config['name'],
                'hp_type': config['hp_type'],
                'hp_options': hp_options,
                'created': config['created'],
                'updated': config['updated'],
                'source': 'store'
            }
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({"data": transformed_config}, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Config Fetch Error", "description": str(e)}]})

    def on_delete(self, req, resp, ident):
        """
        Delete configuration template and related records.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: Configuration ID
        """
        try:
            # Check if config exists
            config = db.get_config(ident)
            if not config:
                resp.status = falcon.HTTP_404
                resp.text = json.dumps({"errors": [
                    {"title": "Not Found", "description": "Configuration template not found."}]})
                return
            
            # Check if config is being used by any deployments
            deployments = db.get_deployments({'config_id': ident})
            if deployments:
                resp.status = falcon.HTTP_400
                resp.text = json.dumps({"errors": [
                    {"title": "Cannot Delete", "description": "Configuration is being used by active deployments. Remove deployments first."}]})
                return
            
            # Check if config is linked to local installations
            installations = db.get_local_installations({'local_config_id': ident})
            if installations:
                # Update installations to remove config reference
                for installation in installations:
                    db.update_local_installation(
                        installation['id'],
                        local_config_id=None,
                        status='uninstalled'
                    )
            
            # Delete the configuration
            result = db.delete_config(ident)
            
            if result:
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({"data": {"message": "Configuration deleted successfully"}}, default=json_converter, ensure_ascii=False)
            else:
                resp.status = falcon.HTTP_500
                resp.text = json.dumps({"errors": [
                    {"title": "Delete Failed", "description": "Failed to delete configuration template."}]})
                
        except Exception as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Delete Error", "description": str(e)}]})
