#!/usr/bin/env python3.9

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.0 January 2021"

import os
from elasticsearch import Elasticsearch, helpers
#from elasticsearch.connection.http_urllib3.exceptions import InsecureRequestWarning
#elasticsearch.connection.http_urllib3.disable_warnings(InsecureRequestWarning)

class ElasticSearch:
    def __init__(self, index):
        es_host     = os.environ['es_hostname']
        es_port     = os.environ['es_port']
        es_user     = os.environ['es_user']
        es_pass     = os.environ['es_pass']

        if es_host is None:
            exit('You need to export Elasticsearch hostname')
        if es_port is None:
            exit('You need to export Elasticsearch port number')
        if es_user is None:
            exit('You need to export Elasticsearch username')
        if es_pass is None:
            exit('You need to export Elasticsearch password')

        self.es     = Elasticsearch([{'host': es_host, 'port': 9200, 'scheme': 'https'}], ca_certs=False, verify_certs=False, http_auth=(str(es_user), str(es_pass)))
        self.index  = index

    def delete_index(self):
        if self.exists():
            self._result = self.es.indices.delete(index=self.index)
        return self
    
    def exists(self):
        return self.es.indices.exists(index=self.index)
    
    def create_index(self):
        self._result = self.es.indices.create(index=self.index)
        return self

    def add_bulk(self, data):
        actions = []
        for item in data:
            item_data = {
                "_index" :  self.index,
                "_source":  item,
            }
            actions.append(item_data)
        return helpers.bulk(self.es, actions, index=self.index)

    def search(self, query):
        return self.es.search(index=self.index, body=query)
