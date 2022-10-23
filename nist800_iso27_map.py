#!/usr/bin/env python3.6

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.0 January 2021"

"""
Process the Detection Rules and extract the Mitre Information. Store the result in Elastic

Install dependencies with:
pip install -r requirements.txt
"""

import json 
import utils
from Elastic_Search import ElasticSearch

NIST800_ISO_MAP = 'https://csrc.nist.gov/CSRC/media/Publications/sp/800-53/rev-5/final/documents/sp800-53r5-to-iso-27001-mapping.docx'
NIST800_ISO_MAP_NAME = 'sp800-53r5-to-iso-27001-mappings.docx'
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

def parse_map(data):
	maps = []
	for item in data[1:]:

		control_id = item.get("('Control ID', 0)")
		control_name = item.get("('Control ID', 1)")
		iso_ref = item.get("('Control ID', 2)")

		''' Specials:
			- Remove "Whithdrawn" entries
			- Keep "None" comment
			- Remove "*" from iso_ref
			- Add "*" mentioning as extra field
			- Split the iso_ref field (',')
		''' 
		# If set ti True then the mapping is not fully satisfied. Check the offical documentation (NIST800_ISO_MAP) with the full explanation
		nist800_iso_map_disclaimer = False

		if control_name == 'Withdrawn':
			continue

		if iso_ref != 'None':
			if ',' in iso_ref:
				references = iso_ref.split(',')
				for key in references:
					if '*' in key:
						key = key.replace('*', '')
						nist800_iso_map_disclaimer = True
					maps.append(create_json(control_id, control_name, key, nist800_iso_map_disclaimer))
					nist800_iso_map_disclaimer = False
			else:
				if '*' in iso_ref:
					iso_ref = iso_ref.replace('*', '')
					nist800_iso_map_disclaimer = True
				maps.append(create_json(control_id, control_name, iso_ref, nist800_iso_map_disclaimer))

		else:
			maps.append(create_json(control_id, control_name, iso_ref, nist800_iso_map_disclaimer))

	return maps

def create_json(control_id, control_name, iso, disclaimer):
	rule_json = {
		'nist800_control_id': control_id,
		'nist800_control_name': control_name,
		'iso27001_control_id': iso,
		'nist800_iso_map_disclaimer': disclaimer
	}
	return rule_json

def upload_data(map):
	es = ElasticSearch('nist800-iso-map').delete_index().create_index()
	return es.add_bulk(map)

def main():
	util = utils.utils(NIST800_ISO_MAP_NAME, NIST800_ISO_MAP)
	table = 1
	header = 1
	nist800_iso_map = util.get_word(table, header)

	map_data = parse_map(nist800_iso_map)
	upload_data(map_data)

if __name__ == "__main__":
    print("Loading CSF & NIST 800-53 Mapping")
    main()
    print('Done')
