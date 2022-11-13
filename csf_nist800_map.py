#!/usr/bin/env python3.9

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.1 October 2022"

"""
Process the Detection Rules and extract the Mitre Information. Store the result in Elastic

Install dependencies with:
pip install -r requirements.txt
"""

import json 
import utils
from Elastic_Search import ElasticSearch

NIST800_CSF_MAP = 'https://csrc.nist.gov/CSRC/media/Publications/sp/800-53/rev-5/final/documents/csf-pf-to-sp800-53r5-mappings.xlsx'
NIST800_CSF_MAP_NAME = 'csf-pf-to-sp800-53r5-mappings.xlsx'
NIST800_CONTROL_FAM = {
	'AC': 'Access Control',
	'CM': 'Configuration Management',
	'CP': 'Contingency Planning',
	'IA': 'Identification and Authentication',
	'MP': 'Media Protection',
	'RA': 'Risk Assessment',
	'CA': 'Security Assessment and Authorization',
	'SC': 'System and Communications Protection',
	'SI': 'System and Information Integrity',
	'SA': 'System and Services Acquisition',
	'SR': 'Supply Chain Risk Management',
	'PL': 'Planning'
}

ES_INDEX = "csf-nist800-map"

ES_MAPPING = {}

def parse_map(data):
	maps = []
	for item in data:
		function = item.get('Function')
		category = item.get('Category').split(':')
		cat_head = category[0]
		cat_text = category[1]
		subcategory = item.get('Subcategory').split(':')
		sub_head = subcategory[0]
		sub_text = subcategory[1]
		map_list = item.get('NIST SP 800-53, Revision 5 Control').split(',')

		for key in map_list:
			cid = key.strip()
			# Exceptions: "all -1 controls", "-1 controls from all security control families"
			if cid == 'all -1 controls' or cid == '-1 controls from all security control families':
				for famid in NIST800_CONTROL_FAM:
					cid = famid + "-1"
					maps.append(create_json(function, cat_head, cat_text, sub_head, sub_text, cid))
			else:
				maps.append(create_json(function, cat_head, cat_text, sub_head, sub_text, cid))

	return maps

def create_json(function, cat_head, cat_text, sub_head, sub_text, cid):
	rule_json = {
		'csf_function': function,
		'csf_category': cat_head,
		'csf_category_text': cat_text,
		'csf_subcategory': sub_head,
		'csf_subcategory_text': sub_text,
		'nist800_control_id': cid
	}
	return rule_json

def upload_data(map):
	es = ElasticSearch(ES_INDEX, ES_MAPPING).delete_index().create_index()
	return es.add_bulk(map)

def main():
	util = utils.utils(NIST800_CSF_MAP_NAME, NIST800_CSF_MAP)
	csf_nist800_map = util.get_excel_csf()

	map_data = parse_map(csf_nist800_map)
	upload_data(map_data)

if __name__ == "__main__":
    print("Loading CSF & NIST 800-53 Mapping")
    main()
    print('Done')
