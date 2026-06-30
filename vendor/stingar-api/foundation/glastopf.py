from .base import BaseFoundation


WEB_DEFAULT = "80"


class GlastopfFoundation(BaseFoundation):

    def get_docker_ports(self, hp_options):
        """
        Get service ports for Glastopf for use in docker-compose.yml file

        :param hp_options: Honeypot options as returned by Deployment class
        :type hp_options: dict
        :return: Honeypot ports in docker-compose.yml format
        :rtype: str
        """
        ports = []
        if "web_port" in hp_options.keys() and hp_options["web_port"]:
            web_port = str(hp_options['web_port']) + ":80"
        else:
            web_port = WEB_DEFAULT + ":80"
        ports.append(web_port)
        return ports
