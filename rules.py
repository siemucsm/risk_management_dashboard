#!/usr/bin/env python3.9

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.2 November 2022"

"""
Process the Detection Rules and extract the Mitre Information. Store the result in Elastic
The script collects all "enabled" rules and extracts all tactics and techniques.

-> Enhancement that filtering in the NIST Dashboard will work. Map Technique ID to the NIST 800-53 Data
-> I suppose we can do a lookup on the mitre_nist_mapping_new index to collect the needed information
-> Will not import the Machine Learning rules (rules need to be enabled, and that is not the case on my test cluster)

Install dependencies with:
pip install -r requirements.txt
"""

import json 
import Kibana_Search
from Elastic_Search import ElasticSearch
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TACTIC_NAME = {
	'TA0001': 'Initial Access',
	'TA0002': 'Execution',
	'TA0003': 'Persistence',
	'TA0004': 'Privilege Escalation',
	'TA0005': 'Defense Evasion',
	'TA0006': 'Credential Access',
	'TA0007': 'Discovery',
	'TA0008': 'Lateral Movement',
	'TA0009': 'Collection',
	'TA0010': 'Exfiltration',
	'TA0011': 'Command and Control',
	'TA0040': 'Impact',
	'TA0042': 'Resource Development',
	'TA0043': 'Reconnaissance'

}
TACTIC_DESC = {
	'TA0001': 'The adversary is trying to get into your network.',
	'TA0002': 'The adversary is trying to run malicious code.',
	'TA0003': 'The adversary is trying to maintain their foothold.',
	'TA0004': 'The adversary is trying to gain higher-level permissions.',
	'TA0005': 'The adversary is trying to avoid being detected.',
	'TA0006': 'The adversary is trying to steal account names and passwords.',
	'TA0007': 'The adversary is trying to figure out your environment.',
	'TA0008': 'The adversary is trying to move through your environment.',
	'TA0009': 'The adversary is trying to gather data of interest to their goal.',
	'TA0010': 'The adversary is trying to steal data.',
	'TA0011': 'The adversary is trying to communicate with compromised systems to control them.',
	'TA0040': 'The adversary is trying to manipulate, interrupt, or destroy your systems and data.',
	'TA0042': 'The adversary is trying to establish resources they can use to support operations.', 
	'TA0043': 'The adversary is trying to gather information they can use to plan future operations.'
}

TACTIC_LINK = 'https://attack.mitre.org/tactics/'

ES_INDEX = "alert-rules"

ES_MAPPING = {}

def extract_technique(data):
	rules = []
	tname = ""
	n800_ctl_name = ""
	n800_ctl_fam_name = ""
	for item in data:
		name = item.get('name')
		rule_id = item.get('rule_id')
		desc = item.get('description')

		if 'threat' in item.keys():
			(tac_id,tec_id,tac_link,tac_name,tac_desc,tname) = ('','','','','','')

			for id in data_extractor(item['threat'], 'id'):
				if 'TA' in id:
					tac_id = id
					tac_link = TACTIC_LINK + tac_id
					tac_name = TACTIC_NAME[tac_id]
					tac_desc = TACTIC_DESC[tac_id]
				else:
					tec_id = id

			attack_tech_data = query_es(tec_id)
			if len(attack_tech_data["hits"]["hits"]) > 0:
				tname = attack_tech_data["hits"]["hits"][0]['_source']['technique_name']

			# Each rule needs to have a mapping to NIST800
			# If rule matches Txxxx, we need all the Txxxx entries from NIST800
			nist800_data = query_es_nist800(tname)
			if len(nist800_data["hits"]["hits"]) > 0:
				#print(rule_id, len(nist800_data["hits"]["hits"]), tname)
				n800_ctl_name = ""
				n800_ctl_fam_name = ""
				for idx, val in enumerate(nist800_data["hits"]["hits"]):
					n800_ctl_name = nist800_data["hits"]["hits"][idx]['_source']['nist800_control_name']
					n800_ctl_fam_name = nist800_data["hits"]["hits"][idx]['_source']['nist800_control_family_name']

					rule_json = {
						'kibana.alert.rule.name': name,
						'kibana.alert.rule.rule_id': rule_id,
						'rule_description': desc,
						'kibana.alert.rule.threat.tactic.id': tac_id,
						'kibana.alert.rule.threat.technique.id': tec_id,
						'kibana.alert.rule.threat.technique.name': tname,
						'kibana.alert.rule.threat.tactic.name': tac_name,
						'tactic_description': tac_desc,
						'kibana.alert.rule.threat.tactic.reference': tac_link,
						'nist800_control_name': n800_ctl_name,
						'nist800_control_family_name': n800_ctl_fam_name
					}
					rules.append(rule_json)
			else:
				rule_json = {
					'kibana.alert.rule.name': name,
					'kibana.alert.rule.rule_id': rule_id,
					'rule_description': desc,
					'kibana.alert.rule.threat.tactic.id': tac_id,
					'kibana.alert.rule.threat.technique.id': tec_id,
					'kibana.alert.rule.threat.technique.name': tname,
					'kibana.alert.rule.threat.tactic.name': tac_name,
					'tactic_description': tac_desc,
					'kibana.alert.rule.threat.tactic.reference': tac_link,
					'nist800_control_name': n800_ctl_name,
					'nist800_control_family_name': n800_ctl_fam_name
				}
				rules.append(rule_json)

	return rules

def upload_data(rules):
	es = ElasticSearch(ES_INDEX, ES_MAPPING).delete_index().create_index()
	return es.add_bulk(rules)

def data_extractor(data, lookup):
	if isinstance(data, dict):
		for k, v in data.items():
			if k == lookup:
				yield v
			else:
				yield from data_extractor(v, lookup)
	elif isinstance(data, list):
		for item in data:
			yield from data_extractor(item, lookup)

def query_es(tid):
	es = ElasticSearch('mitre-attack-techniques', '')
	query = {"query": {"match": {"technique_id": tid}}}
	return es.search(query)

def query_es_nist800(tname):
	es = ElasticSearch('mitre-nist-mapping_new', '')
	query = {"size": 10000, "query": {
    "bool": {
      "must": [
        {
          "bool": {
            "should": [
              {
                "match_phrase": {
                  "kibana.alert.rule.threat.technique.name": tname
                }
              }
            ],
            "minimum_should_match": 1
          }
        }
      ],
      "filter": [],
      "should": [],
      "must_not": []
    }}}
	return es.search(query)

def main():
	ks = Kibana_Search.KibanaSearch()
	rule_data = ks.query_data()

	if rule_data.status_code == 200:
		rules = extract_technique(rule_data.json()['data'])
		upload_data(rules)
	else:
		print(rule_data.text)


if __name__ == "__main__":
    print("Loading configured Detection Rules")
    main()
    print('Done')
