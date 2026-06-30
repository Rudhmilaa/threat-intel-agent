import json

import falcon
from falcon.media.validators import jsonschema

from resources import db
from schemas import config_schema
from util import json_converter


class HoneypotConfigsResource(object):
    """
    Honeypot config template API endpoint.
    """

    def on_get(self, req, resp):
        """
        Get honeypot config template records.

        :param req: Falcon request
        :param resp: Falcon response
        """
        results = db.get_configs(req.params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(config_schema)
    def on_post(self, req, resp):
        """
        Create new honeypot config template record.

        :param req: Falcon request
        :param resp: Falcon response
        """
        config_params = dict()
        params = req.media

        config_params['name'] = params["name"]
        config_params['hp_type'] = params["hp_type"]
        config_params['hp_options'] = json.dumps(params['hp_options'])
        results = db.create_config(**config_params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    @jsonschema.validate(config_schema)
    def on_put(self, req, resp):
        """
        Update honeypot config template record. THIS NEEDS TO BE MOVED AND UPDATED.

        :param req: Falcon request
        :param resp: Falcon response
        """
        config_params = dict()
        config_params['hp_type'] = "cowrie"
        params = req.media

        config_params['name'] = params.pop("name")
        config_params['hp_options'] = json.dumps(params)
        results = db.update_config(**config_params)
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class HoneypotConfigResource(object):
    """
    Honeypot config template API endpoint.
    """

    def on_get(self, req, resp, ident):
        """
        Get single honeypot config template record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of honeypot config template record
        :type ident: str
        """
        results = db.get_config(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Config Not Found",
                 "description": "Config with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)

    def on_delete(self, req, resp, ident):
        """
        Delete single honeypot config template record.

        :param req: Falcon request
        :param resp: Falcon response
        :param ident: id of honeypot config template record
        :type ident: str
        """
        results = db.delete_config(ident=ident)
        if not results:
            resp.text = json.dumps({"errors": [
                {"title": "Config Not Found",
                 "description": "Config with id '" + ident + "' not found."}]})
        resp.status = falcon.HTTP_200
        resp.text = json.dumps({"data": results}, default=json_converter, ensure_ascii=False)


class ConfigCleanupResource(object):
    """
    Configuration cleanup API endpoint for removing invalid configurations.
    """

    def on_post(self, req, resp):
        """
        Cleanup invalid configurations (remove those with empty hp_type).

        :param req: Falcon request
        :param resp: Falcon response
        """
        try:
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


class StoreCacheCleanupResource(object):
    """
    Store cache cleanup API endpoint for removing stale remote honeypot cache data.
    """

    def on_post(self, req, resp):
        """
        Cleanup stale remote honeypot cache data.

        :param req: Falcon request
        :param resp: Falcon response
        """
        import datetime
        
        try:
            # Get cleanup parameters from request
            request_data = req.media if hasattr(req, 'media') and req.media else {}
            max_age_days = request_data.get('max_age_days', 7)  # Default 7 days
            force_cleanup = request_data.get('force_cleanup', False)  # Clean all cache if True
            
            # Get all remote honeypots from cache
            all_remote_honeypots = db.get_remote_honeypots({})
            
            if not all_remote_honeypots:
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({
                    "data": {
                        "message": "No cached remote honeypots found",
                        "deleted_count": 0,
                        "deleted_honeypots": []
                    }
                }, default=json_converter, ensure_ascii=False)
                return
            
            # Calculate cutoff date for stale data
            cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=max_age_days)
            
            # Find stale honeypots
            stale_honeypots = []
            for honeypot in all_remote_honeypots:
                should_delete = False
                
                if force_cleanup:
                    # Force cleanup - delete all cached data
                    should_delete = True
                else:
                    # Check if cache is older than max_age_days
                    last_updated = honeypot.get('local_updated') or honeypot.get('local_created')
                    if last_updated:
                        if isinstance(last_updated, str):
                            try:
                                last_updated = datetime.datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                            except (ValueError, TypeError):
                                # If we can't parse the date, consider it stale
                                should_delete = True
                        elif isinstance(last_updated, datetime.datetime):
                            if last_updated < cutoff_date:
                                should_delete = True
                    else:
                        # No timestamp, consider it stale
                        should_delete = True
                
                if should_delete:
                    stale_honeypots.append(honeypot)
            
            if not stale_honeypots:
                resp.status = falcon.HTTP_200
                resp.text = json.dumps({
                    "data": {
                        "message": f"No stale cached honeypots found (older than {max_age_days} days)",
                        "deleted_count": 0,
                        "deleted_honeypots": []
                    }
                }, default=json_converter, ensure_ascii=False)
                return
            
            # Delete stale honeypots
            deleted_honeypots = []
            for honeypot in stale_honeypots:
                try:
                    result = db.delete_remote_honeypot(honeypot['id'])
                    if result:
                        deleted_honeypots.append({
                            'id': honeypot['id'],
                            'remote_id': honeypot.get('remote_id'),
                            'name': honeypot.get('name'),
                            'hp_type': honeypot.get('hp_type'),
                            'last_updated': honeypot.get('local_updated') or honeypot.get('local_created')
                        })
                except Exception as e:
                    # Log error but continue with other deletions
                    print(f"Failed to delete remote honeypot {honeypot['id']}: {e}")
            
            resp.status = falcon.HTTP_200
            resp.text = json.dumps({
                "data": {
                    "message": f"Successfully deleted {len(deleted_honeypots)} stale cached honeypots",
                    "deleted_count": len(deleted_honeypots),
                    "deleted_honeypots": deleted_honeypots,
                    "cleanup_type": "force" if force_cleanup else f"stale_older_than_{max_age_days}_days"
                }
            }, default=json_converter, ensure_ascii=False)
            
        except Exception as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"errors": [
                {"title": "Cache Cleanup Error", "description": str(e)}]})
