#!/usr/bin/env python3.6

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.0 January 2021"

"""
Process the Detection Rules and extract the Mitre Information. Store the result in Elastic

Install dependencies with:
pip install -r requirements.txt
"""

import json 
import Kibana_Search
from Elastic_Search import ElasticSearch

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
	'TA0043': 'The adversary is trying to gather information they can use to plan future operations.'
}
TACTIC_LINK = 'https://attack.mitre.org/tactics/'

def extract_technique(data):
	rules = []
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

			rule_json = {
				'rule_name': name,
				'rule_id': rule_id,
				'rule_description': desc,
				'tactic_id': tac_id,
				'technique_id': tec_id,
				'technique_name': tname,
				'tactic_name': tac_name,
				'tactic_description': tac_desc,
				'tactic_link': tac_link
			}
			rules.append(rule_json)

	return rules

def upload_data(rules):
	es = ElasticSearch('alert-rules').delete_index().create_index()
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
	es = ElasticSearch('mitre-attack-techniques')
	query = {"query": {"match": {"technique_id": tid}}}
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
