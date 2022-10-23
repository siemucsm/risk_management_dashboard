#!/usr/bin/env python3.6

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.0 January 2021"

"""
Acquire the Mitre Attack & NIST 800-53 r5 raw data and process to be loaded into ES

=> Missing, add the control name and the technique_name

Install dependencies with:
pip install -r requirements.txt
"""

import utils
import json
import re
import exrex
from Elastic_Search import ElasticSearch

RAW_MAPPING_NAME = 'raw.cvs'
RAW_MAP_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/master/frameworks/nist800-53-r5/input/nist800-53-r5-mappings.tsv'
MITRE_MITIGATIONS = 'https://attack.mitre.org/mitigations/enterprise/'
BASELINE_HIGH = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json'
BASELINE_HIGH_NAME = 'nist_baseline_high.json'
BASELINE_MOD = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json'
BASELINE_MOD_NAME = 'nist_baseline_moderate.json'
BASELINE_LOW = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline_profile.json'
BASELINE_LOW_NAME = 'nist_baseline_low.json'
BASELINE_PRIV = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json'
BASELINE_PRIV_NAME = 'nist_baseline_privacy.json'
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

def parse_mapping(data, mitigations, hbase, mbase, lbase, pbase):
	'''
		data:			Mitre - NIST Mapping data from the "Center for Threat Informed Defense"
		mitigations:	Mitigations data extracted directly from the Mitre Attack web site
		hbase:			NIST 800-53B High Baseline information from USNISTGOV oscal extract
		mbase:			NIST 800-53B Moderate Baseline information from USNISTGOV oscal extract
		lbase:			NIST 800-53B Low Baseline information from USNISTGOV oscal extract
		pbase:			NIST 800-53B Privacy Baseline information from USNISTGOV oscal extract
	'''
	map_data = []	
	es = ElasticSearch('mitre-nist-mapping_new').delete_index().create_index()

	for key in data:
		# techniqueID and ControlID need to be parsed
		technique = reverse_regex(key['techniqueID'])
		control = reverse_regex(key['controlID'])

		for tech in technique:
			for ctrl in control:
				fam = ctrl.split('-')[0]
				mitigation = parse_mitigations(key['mitigationID'], mitigations)
				# Mitre Attack enrichment: Technique Name, Description, Tactic Name
				(tname, tdesc, tacti) = ('','','')
				attack_tech_data = query_es(tech)
				if len(attack_tech_data["hits"]["hits"]) > 0:
					tname = attack_tech_data["hits"]["hits"][0]['_source']['technique_name']
					tdesc = attack_tech_data["hits"]["hits"][0]['_source']['description']
					tacti = attack_tech_data["hits"]["hits"][0]['_source']['tactic_name']
				# NIST 800-53B enrichment
				high = parse_baseline(ctrl, hbase)
				mod = parse_baseline(ctrl, mbase)
				low = parse_baseline(ctrl, lbase)
				privacy = parse_baseline(ctrl, pbase)
				map_json = {
					"attack_mitigation_id": key['mitigationID'],
					"attack_mitigation_name": mitigation['Name'],
					"attack_mitigation_desc": mitigation['Description'],
					"technique_id": tech,
					"technique_name": tname,
					"technique_desc": tdesc,
					"tactic_name": tacti,
					"nist800_control_id": ctrl,
					"nist800_control_family_id": fam,
					"nist800_control_family_name": NIST800_CONTROL_FAM[fam],
					"nist800_scope_control_rationale": NIST800_CONTROL_RAT[fam],
					"nist800_baseline_high": high,
					"nist800_baseline_moderate": mod,
					"nist800_baseline_low": low,
					"nist800_baseline_privacy": privacy
				}
				map_data.append(map_json)

	return es.add_bulk(map_data)

def reverse_regex(id):
	# There are bugs in the list.
	# - The dots before the second and third or values are misplaced: T1110(\.(001|.003|.004))?
	# - The dot is in the wrong spot: T1557(\.001\.|002)?
	regexstr = id.strip()
	if regexstr == "T1110(\\.(001|.003|.004))?": regexstr = "T1110(\\.(001|003|004))?"
	if regexstr == "T1557(\\.001\\.|002)?": regexstr = "T1557(\\.001|\\.002)?"
	return list(exrex.generate(regexstr))

def parse_mitigations(miti, data):
	for key in data:
		if key['ID'] == miti:
			return key

def parse_baseline(controlid, data):
	for key in data:
		if key['control-id'] == controlid.lower():
			return True

def query_es(tid):
	es = ElasticSearch('mitre-attack-techniques')
	query = {"query": {"match": {"technique_id": tid}}}
	return es.search(query)

def get_baseline(name, url):
	util = utils.utils(name, url)
	baseline = util.get_json()
	baseline = baseline['profile']['imports'][0]['include']['calls']
	return baseline

def main():
	# Data Acquisition
	util = utils.utils(RAW_MAPPING_NAME, RAW_MAP_URL)
	mitre_nist_map = util.get_tsv()

	util = utils.utils('', MITRE_MITIGATIONS)
	mitigations = util.get_table('table-bordered')

	high_baseline = get_baseline(BASELINE_HIGH_NAME, BASELINE_HIGH)
	low_baseline = get_baseline(BASELINE_LOW_NAME, BASELINE_LOW)
	mod_baseline = get_baseline(BASELINE_MOD_NAME, BASELINE_MOD)
	priv_baseline = get_baseline(BASELINE_PRIV_NAME, BASELINE_PRIV)

	# Parsing and Data import
	parse_mapping(mitre_nist_map, mitigations, high_baseline, mod_baseline, low_baseline, priv_baseline)


if __name__ == "__main__":
    print("Parsing, indexing Mitre and NIST Mapping")
    main()
    print('Parsing done')