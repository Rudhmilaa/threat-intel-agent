from .base import BaseFoundation


RDP_DEFAULT = "3389"


class RDPHoneyFoundation(BaseFoundation):

    def get_docker_ports(self, hp_options):
        """
        Get service ports for RDPhoney for use in docker-compose.yml file

        :param hp_options: Honeypot options as returned by Deployment class
        :type hp_options: dict
        :return: Honeypot ports in docker-compose.yml format
        :rtype: str
        """
        ports = []
        if "rdp_port" in hp_options.keys() and hp_options["rdp_port"]:
            rdp_port = str(hp_options['rdp_port']) + ":3389"
        else:
            rdp_port = RDP_DEFAULT + ":3389"
        ports.append(rdp_port)
        return ports
