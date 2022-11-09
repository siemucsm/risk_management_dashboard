#!/usr/bin/env python3.9

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.1 October 2022"

"""
Acquire the Mitre Attack raw data and process to be loaded into ES

Note: NIST 800 Control Families are limited to the disclaimer of the scoping decisions. See https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/tree/master/frameworks/nist800-53-r5
There are exceptions of the exceptions: PL

Install dependencies with:
pip install -r requirements.txt
"""

import utils
import json 
from Elastic_Search import ElasticSearch

MITRE_NIST_MAPPING_NAME = 'mitre_nist.xlsx'
MITRE_NIST_URL = 'https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/raw/main/frameworks/attack_10_1/nist800_53_r5/nist800-53-r5-mappings.xlsx'
#MITRE_NIST_URL = 'https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/raw/master/frameworks/nist800-53-r5/nist800-53-r5-mappings.xlsx'
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
NIST800_CONTROL_RAT = {
	'AC': 'Access Control family is in scope as it provides technical and operational controls for the control and enforcement of system access, accounts, and information.',
	'CM': 'Configuration Management controls are in scope as they maintain technical and operational controls for maintaining secure configuration of information systems.',
	'CP': 'Contingency Planning controls are in scope as they provide operational and technical controls for information protection at the system level.',
	'IA': 'Identification and Authentication controls are in scope as they provide operational and technical controls for managing and enforcing identification and authentication of network and system users and devices.',
	'MP': 'Media Protection family is in scope as it provides technical and operational controls for the control and access of digital system media.',
	'RA': 'Risk Assessment controls are in scope as they provide technical and operational controls and techniques for risk and vulnerability management and maintaining security at the system level.',
	'CA': 'Security Assessment and Authorization controls are in scope as they provide technical and operational controls and techniques for monitoring and assessing security at the system level.',
	'SC': 'System and Communications Protection controls are in scope as they provide technical and operational controls for the separation and protection of systems and information.',
	'SI': 'System and Information Integrity controls are in scope as they provide technical and operational controls and techniques for protecting and analyzing the integrity of software, firmware, and information.',
	'SA': 'System and Services Acquisition are in scope as they provide technical and operational controls for security testing and evaluation of the system development life cycle.',
	'SR': 'Supply Chain Risk Management is in scope as they provide technical and operational controls for security testing and evaluation of supply chain processes and elements.',
	'PL': 'Planning controls are not applicable as they focus on high-level system security plans and are not threat-specific.'
}

def parse_mapping(data):
	map_data = []
	
	es = ElasticSearch('mitre-nist-mapping').delete_index().create_index()
    
	for key in data:
		fam = key['control ID'].split('-')[0]
		map_json = {
			"nist800_control_id": key['control ID'],
			"nist800_control_name": key['control name'],
			"mapping_type": key['mapping type'],
			"technique_id": key['technique ID'],
			"technique_name": key['technique name'],
			"nist800_control_family_id": fam,
			"nist800_control_family_name": NIST800_CONTROL_FAM[fam],
			"nist800_scope_control_rationale": NIST800_CONTROL_RAT[fam]
		}
		map_data.append(map_json)
      
	return es.add_bulk(map_data)

def main():
    util = utils.utils(MITRE_NIST_MAPPING_NAME, MITRE_NIST_URL)
    mitre_nist_map = util.get_excel()

    parse_mapping(mitre_nist_map)

if __name__ == "__main__":
    print("Parsing, indexing Mitre and NIST Mapping")
    main()
    print('Parsing done')
