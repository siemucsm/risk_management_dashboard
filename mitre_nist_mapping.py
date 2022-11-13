#!/usr/bin/env python3.9

__AUTHOR__ = 'Pascal Imthurn'
__VERSION__ = "1.2 November 2022"

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
RAW_MAP_URL = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/attack-control-framework-mappings/main/data/mappings/attack-10-1-to-nist800-53-r5-mappings.tsv'
MITRE_MITIGATIONS = 'https://attack.mitre.org/mitigations/enterprise/'
BASELINE_HIGH = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_HIGH-baseline_profile.json'
BASELINE_HIGH_NAME = 'nist_baseline_high.json'
BASELINE_MOD = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json'
BASELINE_MOD_NAME = 'nist_baseline_moderate.json'
BASELINE_LOW = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_LOW-baseline_profile.json'
BASELINE_LOW_NAME = 'nist_baseline_low.json'
BASELINE_PRIV = 'https://raw.githubusercontent.com/usnistgov/oscal-content/master/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_PRIVACY-baseline_profile.json'
BASELINE_PRIV_NAME = 'nist_baseline_privacy.json'
#
# https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/raw/main/frameworks/attack_10_1/nist800_53_r4/nist800-53-r4-mappings.xlsx
# Read out column A and Column B and do a unique sort
#
# The following page shows what Control Families are in Scope. The dict will contain both scopes.
# https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings/tree/main/frameworks/attack_10_1/nist800_53_r5
NIST800_CONTROL_FAM = {
	'AC': 'Access Control',
	'AT': 'Awareness and Training',
	'AU': 'Audit and Accountability',
	'CM': 'Configuration Management',
	'CP': 'Contingency Planning',
	'IA': 'Identification and Authentication',
	'IR': 'Incident Response',
	'MA': 'Maintenance',
	'MP': 'Media Protection',
	'PE': 'Physical and Environmental Protection',
	'PL': 'Planning',
	'PM': 'Program Management',
	'PS': 'Personnel Security',
	'PT': 'PII Processing and Transparency',
	'RA': 'Risk Assessment',
	'CA': 'Security Assessment and Authorization',
	'SC': 'System and Communications Protection',
	'SI': 'System and Information Integrity',
	'SA': 'System and Services Acquisition',
	'SR': 'Supply Chain Risk Management'
}
NIST800_CONTROL_RAT = {
	'AC': 'Access Control family is in scope as it provides technical and operational controls for the control and enforcement of system access, accounts, and information.',
	'AT': 'Awareness and Training controls are not applicable as they are for general security awareness training and not specific threat mitigations.',
	'AU': 'Audit and Accountability controls are not applicable as they do not provide mitigations of specific threats, but instead detect successful attacks.',
	'CM': 'Configuration Management controls are in scope as they maintain technical and operational controls for maintaining secure configuration of information systems.',
	'CP': 'Contingency Planning controls are in scope as they provide operational and technical controls for information protection at the system level.',
	'IA': 'Identification and Authentication controls are in scope as they provide operational and technical controls for managing and enforcing identification and authentication of network and system users and devices.',
	'IR': 'Incident Response controls are not applicable as they do not provide mitigations of specific threats but rather provide detection of security incident occurrences.',
	'MA': 'Maintenance controls are not applicable as they are related to the procedural management of information system maintenance and are not threat-specific.',
	'MP': 'Media Protection family is in scope as it provides technical and operational controls for the control and access of digital system media.',
	'PE': 'Physical and Environmental Protection controls are not applicable as they are related to the management and protection of physical space.',
	'PL': 'Planning controls are not applicable as they focus on high-level system security plans and are not threat-specific.',
	'PM': 'Program Management controls are not applicable as they focus on programmatic, organization-wide information security requirements for managing information security programs.',
	'PS': 'Personnel security controls are not applicable as they are related to the procedural management of individuals.',
	'PT': 'PII Processing and Transparency controls are not applicable as they are procedural in nature.',
	'RA': 'Risk Assessment controls are in scope as they provide technical and operational controls and techniques for risk and vulnerability management and maintaining security at the system level.',
	'CA': 'Security Assessment and Authorization controls are in scope as they provide technical and operational controls and techniques for monitoring and assessing security at the system level.',
	'SC': 'System and Communications Protection controls are in scope as they provide technical and operational controls for the separation and protection of systems and information.',
	'SI': 'System and Information Integrity controls are in scope as they provide technical and operational controls and techniques for protecting and analyzing the integrity of software, firmware, and information.',
	'SA': 'System and Services Acquisition are in scope as they provide technical and operational controls for security testing and evaluation of the system development life cycle.',
	'SR': 'Supply Chain Risk Management is in scope as they provide technical and operational controls for security testing and evaluation of supply chain processes and elements.'
}

ES_INDEX = "mitre-nist-mapping_new"

ES_MAPPING = {
  "properties": {
      "kibana": {
        "properties": {
          "alert": {
            "properties": {
              "rule": {
                "properties": {
                  "threat": {
                    "properties": {
                      "tactic": {
                        "properties": {
                          "name": {
                            "type": "keyword"
                          }
                        }
                      },
                      "technique": {
                        "properties": {
                          "id": {
                            "type": "keyword"
                          },
                          "name": {
                            "type": "keyword"
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
  }
}

def parse_mapping(data, mitigations, hbase, mbase, lbase, pbase, controlname):
	'''
		data:			Mitre - NIST Mapping data from the "Center for Threat Informed Defense"
		mitigations:	Mitigations data extracted directly from the Mitre Attack web site
		hbase:			NIST 800-53B High Baseline information from USNISTGOV oscal extract
		mbase:			NIST 800-53B Moderate Baseline information from USNISTGOV oscal extract
		lbase:			NIST 800-53B Low Baseline information from USNISTGOV oscal extract
		pbase:			NIST 800-53B Privacy Baseline information from USNISTGOV oscal extract
		controlname:	NIST 800-53B Control ID and Control Names
	'''
	map_data = []	
	es = ElasticSearch(ES_INDEX, ES_MAPPING).delete_index().create_index()

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
					"kibana.alert.rule.threat.technique.id": tech,
					"kibana.alert.rule.threat.technique.name": tname,
					"technique_desc": tdesc,
					"kibana.alert.rule.threat.tactic.name": tacti,
					"nist800_control_id": ctrl,
					"nist800_control_name": controlname[ctrl],
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
	# - Misisng pipe: T1053(\.002|\.005|\.006\.007)?
	# - Missing pipe: T1505(\.002|\.001\.004)?
	# - Missing pipe: T1543(\.003\.004)?
	# - Missing backslash: T1547.013
	# - Missing backslash: T1552.007
	# - Missing backslash: T1204.003
	# - Maping error: AC-(2|3|4|6|16|17|20|28) -> AC-28 does not exist, its SC-28
	# - Missing pipe: (CM-(2|6|8)|SI-7|IA-(2-9)|SI-(7|14)|SA-10|SR-(4|5|6|11))
	# - Missing pipe: (CA-8|RA-5|CM-(2|6|8|11)|SI-(3-4-7)|SA-(10|11))
	regexstr = id.strip()
	if regexstr == "T1110(\\.(001|.003|.004))?": regexstr = "T1110(\\.(001|003|004))?"
	if regexstr == "T1557(\\.001\\.|002)?": regexstr = "T1557(\\.001|\\.002)?"
	if regexstr == "T1053(\\.002|\\.005|\\.006\\.007)?": regexstr = "T1053(\\.002|\\.005|\\.006|\\.007)?"
	if regexstr == "T1505(\\.002|\\.001\\.004)?": regexstr = "T1505(\\.002|\\.001|\\.004)?"
	if regexstr == "T1543(\\.003\\.004)?": regexstr = "T1543(\\.003|\\.004)?"
	if regexstr == "T1547.013": regexstr = "T1547\\.013"
	if regexstr == "T1552.007": regexstr = "T1552\\.007"
	if regexstr == "T1204.003": regexstr = "T1204\\.003"
	if regexstr == "AC-(2|3|4|6|16|17|20|28)": regexstr = "(AC-(2|3|4|6|16|17|20)|SC-28)"
	if regexstr == "(CM-(2|6|8)|SI-7|IA-(2-9)|SI-(7|14)|SA-10|SR-(4|5|6|11))": regexstr = "(CM-(2|6|8)|SI-7|IA-(2|9)|SI-(7|14)|SA-10|SR-(4|5|6|11))"
	if regexstr == "(CA-8|RA-5|CM-(2|6|8|11)|SI-(3-4-7)|SA-(10|11))": regexstr = "(CA-8|RA-5|CM-(2|6|8|11)|SI-(3|4|7)|SA-(10|11))"
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
	es = ElasticSearch('mitre-attack-techniques', '')
	query = {"query": {"match": {"technique_id": tid}}}
	return es.search(query)

def get_baseline(name, url):
	util = utils.utils(name, url)
	baseline = util.get_json()
	baseline = baseline['profile']['imports'][0]['include']['calls']
	return baseline

def get_control_name(name, url):
	# The file has been created manually from nist800-53-r4-mappings.xlsx. Keep column A and B and do a unique sort
	util = utils.utils(name, url)
	control = util.read_txt_file()
	return control

def main():
	# Data Acquisition
	util = utils.utils(RAW_MAPPING_NAME, RAW_MAP_URL)
	mitre_nist_map = util.get_tsv()

	util = utils.utils('', MITRE_MITIGATIONS)
	mitigations = util.get_table('table-bordered')

	control = get_control_name('NIST800_Control_Name.csv', '')

	high_baseline = get_baseline(BASELINE_HIGH_NAME, BASELINE_HIGH)
	low_baseline = get_baseline(BASELINE_LOW_NAME, BASELINE_LOW)
	mod_baseline = get_baseline(BASELINE_MOD_NAME, BASELINE_MOD)
	priv_baseline = get_baseline(BASELINE_PRIV_NAME, BASELINE_PRIV)

	# Parsing and Data import
	parse_mapping(mitre_nist_map, mitigations, high_baseline, mod_baseline, low_baseline, priv_baseline, control)


if __name__ == "__main__":
    print("Parsing, indexing Mitre and NIST Mapping")
    main()
    print('Parsing done')
