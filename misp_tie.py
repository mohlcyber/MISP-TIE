#!/usr/bin/env python3
#Written by mohlcyber v.0.1

import requests
import sys
import time

from pymisp import ExpandedPyMISP
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxltieclient import TieClient
from dxltieclient.constants import TrustLevel

requests.packages.urllib3.disable_warnings()

misp_url = 'https://1.1.1.1'
misp_key = 'apikey'
misp_verifycert = False
misp_tag = 'TIE Set Reputation'

dxl_config = 'path to dxlclient.config'

# TIE Reputation Level following options:
# TrustLevel.KNOWN_TRUSTED_INSTALLER
# TrustLevel.KNOWN_TRUSTED
# TrustLevel.MIGHT_BE_TRUSTED
# TrustLevel.MOST_LIKELY_TRUSTED
# TrustLevel.UNKNOWN
# TrustLevel.MIGHT_BE_MALICIOUS
# TrustLevel.MOST_LIKELY_MALICIOUS
# TrustLevel.KNOWN_MALICIOUS
# TrustLevel.NOT_SET
tie_rep = TrustLevel.MOST_LIKELY_MALICIOUS

class MISP():

    def __init__(self):
        self.misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
        self.tags = self.misp.tags()
        self.tie = TIE()

    def get_event(self):
        try:
            events = self.misp.search(tags=misp_tag)
            for event in events:
                for attributes in event['Event']['Attribute']:
                    if attributes['type'] == 'md5':
                        print('STATUS: Found MD5 {0} in Event {1}. Trying to set external reputation.'
                              .format(str(attributes['value']),str(event['Event']['id'])))
                        self.tie.set_rep(event['Event']['id'], attributes['value'])

                for objects in event['Event']['Object']:
                    for attributes in objects['Attribute']:
                        if attributes['type'] == 'md5':
                            print('STATUS: Found MD5 {0} in Event {1}. Trying to set external reputation.'
                                  .format(str(attributes['value']), str(event['Event']['id'])))
                            self.tie.set_rep(event['Event']['id'], attributes['value'])

                self.misp.untag(event['Event']['uuid'], misp_tag)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print('ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}'
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))


class TIE():

    def __init__(self):
        self.config = DxlClientConfig.create_dxl_config_from_file(dxl_config)
        self.tie_rep = tie_rep

    def set_rep(self, eventid, hash):
        try:
            with DxlClient(self.config) as client:
                client.connect()
                tie_client = TieClient(client)

                tie_client.set_external_file_reputation(
                    self.tie_rep,
                    {'md5': hash},
                    filename='MISP Hash {0}'.format(str(eventid)),
                    comment='External Reputation set via OpenDXL')

                print('SUCCESS: Successfully pushed MD5 {0} to TIE.'.format(str(hash)))

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print('ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}'
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))


if __name__ == '__main__':
    while True:
        misp = MISP()
        misp.get_event()
        time.sleep(60)