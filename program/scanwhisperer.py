#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Alberto Marziali'

import os
import argparse
import sys
import logging
from logging.handlers import RotatingFileHandler
import schedule
import time

# Common
from base.config import swConfig

# Modules
from modules.nessus.nessus import scanWhispererNessus
from modules.tenableio.tenableio import scanWhispererTenableio
from modules.awsinspector.awsinspector import scanWhispererAWSInspector
from modules.niktowrapper.niktowrapper import scanWhispererNiktoWrapper
from modules.bitsight.bitsight import scanWhispererBitSight


def isFileValid(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return arg


def main():

    parser = argparse.ArgumentParser(description=""" ScanWhisperer is designed to create actionable data from\
     your vulnerability scans through aggregation of historical scans.""")
    parser.add_argument('-c', '--config', dest='config', required=False, default='frameworks.ini',
                        help='Path of config file', type=lambda x: isFileValid(parser, x.strip()))
    parser.add_argument('-s', '--section', dest='section', required=False,
                        help='Section in config')
    parser.add_argument('-p', '--purge', dest='purge', action='store_true', default=False,
                        help='Purge the DB')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', default=False,
                        help='Enable detailed logging')
    parser.add_argument('-F', '--fancy', action='store_true',
                        help='Enable colourful logging output')
    parser.add_argument('-l', '--log', dest='logfile', required=False,
                        help='Path of log file')
    parser.add_argument('-D', '--daemon', action='store_true',
                        help='Launch as daemon')
    args = parser.parse_args()

    # First setup logging
    logging.basicConfig(
        stream=sys.stdout,
        #format only applies when not using -F flag for colouring
        format='%(levelname)s:%(name)s:%(funcName)s %(message)s' if args.verbose else '%(name)s %(message)s',
        level=logging.INFO
    )
    logger = logging.getLogger()

    if args.logfile:
        # we set up the logger to log as well to file
        fh = RotatingFileHandler(args.logfile, mode='a', maxBytes=1*1024*1024, backupCount=5, encoding=None, delay=0)
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(funcName)s:%(message)s", "%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)

    if args.fancy:
        import coloredlogs
        coloredlogs.install(level='INFO')

    # warn about db being purged
    if args.purge:
        logger.warn('Requested purge of SQLite DB')

    # Intro
    logger.info('+-+-+-+-+-+-+-+-+-+-+-+-+-+')
    logger.info('|S|c|a|n|W|h|i|s|p|e|r|e|r|')
    logger.info('+-+-+-+-+-+-+-+-+-+-+-+-+-+')
    logger.info('Dev: Alberto Marziali')
    logger.info('Git: https://github.com/AlbertoMarziali/ScanWhisperer')
    logger.info('')

    try:
        # Get sections from argument or from configuration file
        if args.config and not args.section:
            logger.info('No section was specified, scanwhisperer will scrape enabled modules from the config file.')
            
            config = swConfig(config_in=args.config)
            sections = config.get_sections_with_attribute('enabled')
        else:
            logger.info('Section specified: {}'.format(args.section))

            sections = [args.section]

        # Iterate over selected sections and launch or schedule launch for each one
        for section in sections:
            try:
                if section == 'nessus':
                    sw = scanWhispererNessus(   config=args.config,
                                                profile=section,
                                                verbose=args.verbose,
                                                purge=args.purge,
                                                daemon=args.daemon)
                    if sw:
                        schedule.every(1).minutes.do(sw.whisper_nessus)

                elif section == 'tenableio':
                    sw = scanWhispererTenableio(config=args.config,
                                                profile=section,
                                                verbose=args.verbose,
                                                purge=args.purge,
                                                daemon=args.daemon)
                    if sw:
                        schedule.every(1).minutes.do(sw.whisper_tenableio)

                elif section == 'awsinspector':
                    sw = scanWhispererAWSInspector( config=args.config,
                                                    verbose=args.verbose,
                                                    purge=args.purge,
                                                    daemon=args.daemon)
                    if sw:
                        schedule.every(1).minutes.do(sw.whisper_awsinspector)

                elif section == 'niktowrapper':
                    sw = scanWhispererNiktoWrapper( config=args.config,
                                                    verbose=args.verbose,
                                                    daemon=args.daemon)
                    if sw:
                        schedule.every(1).minutes.do(sw.whisper_niktowrapper)

                elif section == 'bitsight':
                    sw = scanWhispererBitSight( config=args.config,
                                                verbose=args.verbose,
                                                daemon=args.daemon)
                    if sw:
                        schedule.every(60).minutes.do(sw.whisperer_bitsight)
    
            except Exception as e:
                logger.error("ScanWhisperer was unable to perform the processing on '{}': {}".format(section, e))

        # Run all scheduled actions 
        schedule.run_all()

        # If daemon, loop, if not, cancel jobs and quit
        if args.daemon:
            # Run when scheduled
            while True:
                schedule.run_pending()
                time.sleep(1)
        else: 
            schedule.clear()

    except Exception as e:
        logger.error('ScanWhisperer fatal error: {}'.format(e))
    
    # Close logging handlers
    for handler in logger.handlers:
        handler.close()
        logger.removeFilter(handler)
   

if __name__ == '__main__':
    main()
