import configparser
from os import environ


def to_environ_key(key):
    return key.upper()


class EnvironmentConfigParser(configparser.ConfigParser):

    def has_option(self, section, option):
        if to_environ_key('_'.join((section, option))) in environ:
            return True
        return super(EnvironmentConfigParser, self).has_option(section, option)

    def get(self, section, option, **kwargs):
        key = to_environ_key('_'.join((section, option)))
        if key in environ:
            return environ[key]
        return super(EnvironmentConfigParser, self).get(section, option, **kwargs)
