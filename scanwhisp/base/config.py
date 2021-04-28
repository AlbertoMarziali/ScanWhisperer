from __future__ import absolute_import
import sys
import logging

# Support for python3
if sys.version_info > (3, 0):
    import configparser as cp
else:
    import six.moves.configparser as cp


class swConfig(object):

    def __init__(self, config_in=None):
        self.config_in = config_in
        self.config = cp.RawConfigParser()
        self.config.read(self.config_in)
        self.logger = logging.getLogger('swConfig')

    def get(self, section, option):
        self.logger.debug('Calling get for {}:{}'.format(section, option))
        return self.config.get(section, option)

    def getbool(self, section, option):
        self.logger.debug('Calling getbool for {}:{}'.format(section, option))
        return self.config.getboolean(section, option)

    def get_sections_with_attribute(self, attribute):
        sections = []
        # TODO: does this not also need the "yes" case?
        check = ["true", "True", "1"]
        for section in self.config.sections():
            try:
                if self.get(section, attribute) in check:
                    sections.append(section)
            except:
                self.logger.warn("Section {} has no option '{}'".format(section, attribute))
        return sections
