import json
import logging
import socket
import yaml
import io
from dotenv import dotenv_values
from .ports import apply_transport

logger = logging.getLogger(__name__)


def format_tags(tags):
    tag_list = []
    for tag in tags:
        tag_list.append(tag["name"] + ":" + tag["value"])
    return ",".join(tag_list)


class BaseFoundation(object):

    """
    Class for handling the building of honeypot configuration files.
    """

    def get_docker_ports(self, hp_options):
        """
        Extract docker ports from hp_options format.
        
        :param hp_options: Honeypot options dictionary
        :return: List of port mappings for docker-compose
        """
        try:
            if isinstance(hp_options, str):
                hp_options = json.loads(hp_options)
            
            ports = []
            
            # Extract ports from hp_options format. UDP services (snmp, tftp,
            # sip, ...) must carry a "/udp" suffix or Docker forwards them as
            # TCP only and the listener never receives traffic; apply_transport
            # adds it based on the service name / port (an explicit
            # "{service}_transport" / "{service}_udp" hint overrides).
            for key, value in hp_options.items():
                if key.endswith('_enabled') and value:
                    service_name = key.replace('_enabled', '')
                    port_key = f"{service_name}_port"
                    if port_key in hp_options:
                        port_num = hp_options[port_key]
                        transport = hp_options.get(f"{service_name}_transport")
                        if hp_options.get(f"{service_name}_udp") is True:
                            transport = "udp"
                        ports.extend(apply_transport(
                            f"{port_num}:{port_num}",
                            protocol=service_name,
                            port=port_num,
                            transport=transport))
            
            return ports
        except Exception as e:
            logging.warning(f"Error extracting docker ports from hp_options: {e}")
            return []

    def get_reported_port_envs(self, hp_options):
        return {}
    
    def _get_ports_for_template(self, deployment):
        """
        Extract ports from deployment for template rendering.
        
        :param deployment: Honeypot Deployment object
        :return: List of port dictionaries with external and internal keys
        """
        try:
            hp_options = json.loads(deployment.get('hp_options', '{}'))
            ports = []
            
            # Extract ports from hp_options
            for key, value in hp_options.items():
                if key.endswith('_enabled') and value:
                    service_name = key.replace('_enabled', '')
                    port_key = f"{service_name}_port"
                    if port_key in hp_options:
                        port_num = hp_options[port_key]
                        ports.append({
                            'external': str(port_num),
                            'internal': str(port_num)
                        })
            
            return ports
        except Exception as e:
            logging.warning(f"Error extracting ports from deployment: {e}")
            return []

    def build_docker_compose(self, compose_template, deployment, docker_repository="", env_filename="stingar-hp.env"):
        """
        Builder for honeypot docker-compose.yml file.

        :param compose_template: docker-compose.yml template file for honeypot deployment
        :type compose_template: str
        :param docker_repository: alternate Docker repository for honeypot images
        :type docker_repository: str
        :param env_filename: Filename for ENV file for honeypot configuration
        :type env_filename: str
        :param deployment: Honeypot Deployment object
        :type deployment: Deployment
        :return: text output for docker-compose.yml
        :rtype: str
        """
        # Check if this is a Jinja2 template (contains {{ }} variables or {% %} control structures)
        try:
            with open(compose_template, 'r') as f:
                template_content = f.read()
            
            # Detect Jinja2 templates by checking for both variable syntax and control structures
            is_jinja2_template = (
                ('{{' in template_content and '}}' in template_content) or
                ('{%' in template_content and '%}' in template_content) or
                ('%' in template_content and ('if' in template_content or 'for' in template_content or 'set' in template_content))
            )
            
            if is_jinja2_template:
                # This is a Jinja2 template - render it
                try:
                    # Try importing Environment first (newer Jinja2 versions)
                    try:
                        from jinja2 import Environment
                        env = Environment()
                    except ImportError:
                        # Fallback to SandboxedEnvironment (older versions)
                        from jinja2 import SandboxedEnvironment
                        env = SandboxedEnvironment()
                    
                    template = env.from_string(template_content)
                    
                    # Extract docker_image from hp_options if not directly in deployment
                    docker_image = deployment.get('docker_image')
                    if not docker_image:
                        # Try to extract from hp_options (HP App Store format)
                        hp_options = deployment.get('hp_options', '{}')
                        logger.debug(f"Extracting docker_image from hp_options: {hp_options[:200] if isinstance(hp_options, str) else hp_options}")
                        if isinstance(hp_options, str):
                            try:
                                hp_options_dict = json.loads(hp_options)
                            except (json.JSONDecodeError, TypeError) as e:
                                logger.warning(f"Failed to parse hp_options as JSON: {e}")
                                hp_options_dict = {}
                        else:
                            hp_options_dict = hp_options
                        
                        # Check for docker_image in hp_options
                        if 'docker_image' in hp_options_dict:
                            docker_image = hp_options_dict['docker_image']
                            logger.debug(f"Found docker_image in hp_options: {docker_image}")
                        elif 'docker_image_name' in hp_options_dict and 'docker_tag' in hp_options_dict:
                            docker_image = f"{hp_options_dict['docker_image_name']}:{hp_options_dict['docker_tag']}"
                            logger.debug(f"Constructed docker_image from docker_image_name and docker_tag: {docker_image}")
                        else:
                            # Fallback: construct from hp_type
                            hp_type = deployment.get('hp_type', 'unknown')
                            docker_tag = hp_options_dict.get('docker_tag', 'latest')
                            docker_image = f'4warned/{hp_type}:{docker_tag}'
                            logger.warning(f"docker_image not found in deployment or hp_options, constructed from hp_type: {docker_image}")
                    else:
                        logger.debug(f"Using docker_image from deployment: {docker_image}")
                    
                    # Prepare template context - sanitize data to prevent code execution
                    context = {
                        'honeypot_name': str(deployment.get('hp_type', 'honeypot')),
                        'honeypot_type': str(deployment.get('hp_type', 'unknown')),
                        'docker_image': str(docker_image),
                        'ports': self._get_ports_for_template(deployment),
                        'volumes': list(deployment.get('volumes', [])) if isinstance(deployment.get('volumes'), list) else [],
                        'environment': dict(deployment.get('environment', {})) if isinstance(deployment.get('environment'), dict) else {}
                    }
                    
                    # Render template
                    rendered_content = template.render(**context)
                    
                    # Parse the rendered content as YAML
                    data = yaml.safe_load(io.StringIO(rendered_content))
                    
                except ImportError as import_err:
                    error_msg = (
                        f"Jinja2 template detected but Jinja2 is not available. "
                        f"Template file '{compose_template}' contains Jinja2 syntax that cannot be parsed as static YAML. "
                        f"Please install Jinja2: pip install jinja2"
                    )
                    logging.error(error_msg)
                    raise ValueError(error_msg) from import_err
                except Exception as e:
                    logging.warning(f"Failed to render Jinja2 template: {e}, attempting fallback")
                    # Try to parse as YAML anyway (might work if template is mostly static)
                    try:
                        data = yaml.safe_load(io.StringIO(template_content))
                        logging.warning("Successfully parsed template as static YAML despite Jinja2 syntax")
                    except yaml.YAMLError as yaml_err:
                        error_msg = (
                            f"Template file '{compose_template}' contains Jinja2 syntax but cannot be parsed. "
                            f"Original error: {e}. YAML parse error: {yaml_err}"
                        )
                        logging.error(error_msg)
                        raise ValueError(error_msg) from yaml_err
            else:
                # This is a static YAML file
                data = yaml.safe_load(io.StringIO(template_content))
                
        except Exception as e:
            logging.error(f"Error reading template file {compose_template}: {e}")
            raise

        hp_type = deployment.get('hp_type')
        try:
            data['services']['fluentbit']['env_file'] = env_filename
        except KeyError:
            logging.error("No fluentbit definition found in template file %s.", compose_template)

        try:
            data['services'][hp_type]['env_file'] = env_filename
        except KeyError:
            logging.error("No honeypot definition found in template file %s for honeypot type %s", (compose_template,
                                                                                                    hp_type))
        if docker_repository:
            fluentbit_image = data['services']['fluentbit']['image']
            data['services']['fluentbit']['image'] = docker_repository + "/" + fluentbit_image
            try:
                hp_image = data['services'][hp_type]['image']
                data['services'][hp_type]['image'] = docker_repository + "/" + hp_image
            except KeyError:
                logging.error("No honeypot definition found in template file %s for honeypot type %s",
                              (compose_template,
                               hp_type))

        try:
            hp_options = json.loads(deployment.get('hp_options'))
        except ValueError:
            logging.warning("Unable to parse hp_options:", deployment['hp_options'])
            raise ValueError

        ports = self.get_docker_ports(hp_options)
        data['services'][hp_type]['ports'] = ports

        return yaml.dump(data, default_flow_style=False)

    def build_honeypot_env(self, env_template, deployment, fluent_host, fluent_port, fluent_key):
        """
        Build the ENV file for honeypot configuration.

        :param env_template: ENV template file for honeypot configuration
        :type env_template: string
        :param deployment: Honeypot Deployment object
        :type deployment: Deployment
        :param fluent_host: Fluentd hostname / IP address for sending honeypot events
        :type fluent_host: str
        :param fluent_port: Fluentd port number for sending honeypot events
        :type fluent_port: int
        :param fluent_key: Fluentd secret key for authentication
        :type fluent_key: str
        :return: text output for ENV file
        :rtype: str
        """
        uuid = deployment.get('uuid')
        address = deployment.get('address')
        tags = deployment.get('tags')
        
        # Check if this is a Jinja2 template (contains {{ }} variables)
        try:
            with open(env_template, 'r') as f:
                template_content = f.read()
            
            if '{{' in template_content and '}}' in template_content:
                # This is a Jinja2 template - render it
                try:
                    from jinja2 import SandboxedEnvironment
                    env = SandboxedEnvironment()
                    template = env.from_string(template_content)
                    
                    # Parse hp_options to check for healthcheck settings
                    hp_options = {}
                    try:
                        hp_options = json.loads(deployment.get('hp_options', '{}'))
                    except (json.JSONDecodeError, TypeError):
                        hp_options = {}
                    
                    # Prepare template context - sanitize data to prevent code execution
                    # Only pass safe, scalar values - do not pass entire deployment object
                    context = {
                        'deployment': {
                            'uuid': str(deployment.get('uuid', '')),
                            'address': str(deployment.get('address', '')),
                            'hp_type': str(deployment.get('hp_type', '')),
                            'asn': str(deployment.get('asn', '')) if deployment.get('asn') else ''
                        },
                        'fluent_host': str(fluent_host),
                        'fluent_port': str(fluent_port),
                        'fluent_key': str(fluent_key),
                        'honeypot_ip': str(self._resolve_honeypot_ip(address)),
                        'healthcheck_interval': str(hp_options.get('healthcheck_interval', '60m')),
                        'healthcheck_timeout': str(hp_options.get('healthcheck_timeout', '30s')),
                        'config_info': {
                            'tags': str(format_tags(tags) if tags else '')
                        }
                    }
                    
                    logger.debug(f"Template context healthcheck_interval: {context['healthcheck_interval']}")
                    logger.debug(f"Template context healthcheck_timeout: {context['healthcheck_timeout']}")
                    
                    # Render template
                    rendered_content = template.render(**context)
                    
                    # Parse the rendered content as environment variables
                    # Create a temporary file-like object for dotenv_values
                    hp_env = dotenv_values(stream=io.StringIO(rendered_content))
                    
                except ImportError as import_err:
                    logger.warning(f"Jinja2 not available (ImportError: {import_err}), falling back to static parsing")
                    logger.debug("This may indicate Jinja2 is not installed. Check requirements.txt and Docker image.")
                    hp_env = dotenv_values(dotenv_path=env_template)
                except Exception as e:
                    logger.warning(f"Failed to render Jinja2 template: {e}, falling back to static parsing")
                    hp_env = dotenv_values(dotenv_path=env_template)
            else:
                # This is a static .env file - parse it directly
                hp_env = dotenv_values(dotenv_path=env_template)
                
        except Exception as e:
            logging.error(f"Error reading template file {env_template}: {e}")
            hp_env = {}
        
        # Override with deployment-specific values
        hp_env['FLUENTD_HOST'] = fluent_host
        hp_env['FLUENTD_PORT'] = fluent_port
        hp_env['FLUENTD_KEY'] = fluent_key
        hp_env['HONEYPOT_IDENT'] = uuid
        hp_env['HONEYPOT_HOST'] = address
        hp_env['TAGS'] = format_tags(tags)
        hp_env['HONEYPOT_IP'] = self._resolve_honeypot_ip(address)
        
        return "\n".join(["=".join([key, str(val)]) for key, val in hp_env.items()])
    
    def _resolve_honeypot_ip(self, address):
        """Resolve honeypot IP address from hostname."""
        try:
            honeypot_ip = socket.gethostbyname(address)
        except (socket.gaierror):
            logging.warning("Can't resolve hostname %s", address)
            honeypot_ip = ""
        return honeypot_ip
