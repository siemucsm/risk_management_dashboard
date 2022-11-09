#!/usr/bin/env python3.9

__AUTHOR__ = 'Michael Hidalgo, Pascal Imthurn'
__CREDITS__ = 'Michael Hidalgo'
__VERSION__ = "1.1 October 2022"

"""
Download all enabled Detection Rules. The goal is to extract all Technique IDs and to import them into an index used by visualisations

Install dependencies with:
pip install -r requirements.txt

Query Detection Engine Rules
curl -X GET "ki_user:ki_pass@ki_hostname:ki_port/api/detection_engine/rules/_find?page=1&per_page=4000&filter=alert.attributes.name:enabled"
"""

import requests
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class KibanaSearch:
    RULE_DATA_QUERY = "/api/detection_engine/rules/_find"
    RULE_DATA_PARAM = {'page': '1', 'per_page': '4000', 'filter': 'alert.attributes.enabled:true', 'sort_field': 'enabled', 'sort_order': 'asc'}

    def query_data(self):
        ki_host     = os.environ['ki_hostname']
        ki_port     = os.environ['ki_port']
        ki_user     = os.environ['ki_user']
        ki_pass     = os.environ['ki_pass']

        if ki_host is None:
            exit('You need to export Kibana hostname')
        if ki_port is None:
            exit('You need to export Kibana port number')
        if ki_user is None:
            exit('You need to export Kibana username')
        if ki_pass is None:
            exit('You need to export Kibana password')

        url = "https://" + ki_user + ":" + ki_pass + "@" + ki_host + ":" + ki_port + self.RULE_DATA_QUERY
        
        return requests.get(url, params = self.RULE_DATA_PARAM, verify = False, auth = (ki_user, ki_pass) )


