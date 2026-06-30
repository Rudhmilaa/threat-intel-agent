from .base import BaseFoundation


HTTP_DEFAULT = "80"
HTTPS_DEFAULT = "443"
S7_DEFAULT = "102"
MODBUS_DEFAULT = "502"
SNMP_DEFAULT = "161"
BACNET_DEFAULT = "47808"
IPMI_DEFAULT = "623"
FTP_DEFAULT = "21"
TFTP_DEFAULT = "69"
ENIP_DEFAULT = "44818"


class ConpotFoundation(BaseFoundation):

    def get_docker_ports(self, hp_options):
        """
        Get service ports for Conpot for use in docker-compose.yml file

        :param hp_options: Honeypot options as returned by Deployment class
        :type hp_options: dict
        :return: Honeypot ports in docker-compose.yml format
        :rtype: str
        """
        ports = []
        if hp_options['http_enabled']:
            if "http_port" in hp_options.keys() and hp_options["http_port"]:
                http_port = str(hp_options['http_port']) + ":8800"
            else:
                http_port = HTTP_DEFAULT + ":8800"
            ports.append(http_port)

        # HTTPS: TLS-terminating web listener (modern ICS device web UIs). conpot
        # binds 8443 in-container (unprivileged) and we publish it as host 443,
        # mirroring how http binds 8800 / publishes 80. .get() keeps this
        # backward-compatible with older conpot honeypot definitions that predate
        # the https_enabled option.
        if hp_options.get('https_enabled'):
            if "https_port" in hp_options.keys() and hp_options["https_port"]:
                https_port = str(hp_options['https_port']) + ":8443"
            else:
                https_port = HTTPS_DEFAULT + ":8443"
            ports.append(https_port)

        if hp_options['s7_enabled']:
            if "s7_port" in hp_options.keys() and hp_options["s7_port"]:
                s7_port = str(hp_options['s7_port']) + ":10201"
            else:
                s7_port = S7_DEFAULT + ":10201"
            ports.append(s7_port)

        if hp_options['modbus_enabled']:
            if "modbus_port" in hp_options.keys() and hp_options["modbus_port"]:
                modbus_port = str(hp_options['modbus_port']) + ":5020"
            else:
                modbus_port = MODBUS_DEFAULT + ":5020"
            ports.append(modbus_port)

        # SNMP, BACnet, IPMI and TFTP are UDP services. Docker maps host ports
        # as TCP unless an explicit "/udp" suffix is given, so without it these
        # listeners never receive any traffic regardless of the cloud firewall
        # (the conpot listener binds UDP internally). The "/udp" suffix must be
        # appended to the *whole* mapping (host:container/udp).
        if hp_options['snmp_enabled']:
            if "snmp_port" in hp_options.keys() and hp_options["snmp_port"]:
                snmp_port = str(hp_options['snmp_port']) + ":16100/udp"
            else:
                snmp_port = SNMP_DEFAULT + ":16100/udp"
            ports.append(snmp_port)

        if hp_options['bacnet_enabled']:
            if "bacnet_port" in hp_options.keys() and hp_options["bacnet_port"]:
                bacnet_port = str(hp_options['bacnet_port']) + ":47808/udp"
            else:
                bacnet_port = BACNET_DEFAULT + ":47808/udp"
            ports.append(bacnet_port)

        if hp_options['ipmi_enabled']:
            if "ipmi_port" in hp_options.keys() and hp_options["ipmi_port"]:
                ipmi_port = str(hp_options['ipmi_port']) + ":6230/udp"
            else:
                ipmi_port = IPMI_DEFAULT + ":6230/udp"
            ports.append(ipmi_port)

        if hp_options['ftp_enabled']:
            if "ftp_port" in hp_options.keys() and hp_options["ftp_port"]:
                ftp_port = str(hp_options['ftp_port']) + ":2121"
            else:
                ftp_port = FTP_DEFAULT + ":2121"
            ports.append(ftp_port)

        if hp_options['tftp_enabled']:
            if "tftp_port" in hp_options.keys() and hp_options["tftp_port"]:
                tftp_port = str(hp_options['tftp_port']) + ":6969/udp"
            else:
                tftp_port = TFTP_DEFAULT + ":6969/udp"
            ports.append(tftp_port)

        if hp_options['enip_enabled']:
            if "enip_port" in hp_options.keys() and hp_options["enip_port"]:
                enip_port = str(hp_options['enip_port']) + ":44818"
            else:
                enip_port = ENIP_DEFAULT + ":44818"
            ports.append(enip_port)
        return ports
