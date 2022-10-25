# Introduction
On the 15th of December, the Center for Threat-Informed Defense (mitre-engenuity.org/ctid/) has released a set of mappings between Mitre Attack (https://attack.mitre.org/) and NIST Special Publications 800-53 (https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final). Tiffany Bergeron and Jon Baker have written a post (https://medium.com/mitre-engenuity/security-control-mappings-a-bridge-to-threat-informed-defense-2e42a074f64a) detailing some of the benefits of the mapping activity. Check out also their github repository (https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings), where you can access all the related work.

The work by the CTID team is the missing piece to my previous work (https://www.siemucsm.com). In my master thesis I was focusing the mapping on the data sources of thr Mitre Attack Framework. Due to time and resource constraints it would have never been an option to map all Attack Techniques to an individual security control standard such as NIST SP800-53, ISO 27001 or NIST CSF.

This has now been solved :)

So what to do with this data?


# Use Cases


# Types of Dashboards

## NIST 800-53 r5 Dashboard
Filters: Control Family, Control Name, Tactic, Technique, Priorities


# Installation

cd DIR
virtualenv env
source env/bin/activate
pip3 install -r requirements.txt 
export es_hostname="192.168.1.55"
export es_port=9200
export es_user="elastic"
export es_pass="b6ae2r"
export ki_hostname="192.168.1.55"
export ki_port=5601
export ki_user="elastic"
export ki_pass="b6ae2r"


# Technical stuff

I am no programmer.. and never will be. It might be a great source for a drinking game. For every piece of code you find a more efficient way of writing it.. take a shot. Seriously, this can be improved in mmany ways.


/usr/share/elastic-agent/bin# ./elastic-agent enroll http://localhost:5601 V09xYTRYWUJKWnFiU05OS2J4QVg6NExaSHU1dmNUR0dsNTQtMDAtQTFkZw== --path.config /etc/elastic-agent/ --insecure

sudo service elastic-agent start

f7wQ7zEIP9Pn5IvUj5GlF841


# A better way to visualize, filter and search MITRE ATT&CK matrix

This program exports MITRE ATT&amp;CK enterpise matrix into a ELK dashboard. Check out [this blog post entry](https://blog.michaelhidalgo.info/2019/01/mitre-att-as-kibana-dashboard-part-ll.html) for having better understanding on the benefits of exporting the ATT&CK enterprise matrix into ELK.

![Alt text](/img/platform.jpg?raw=true "MITRE ATT&CK Dashboard")

# Visualizing the relationship between MITRE ATT&CK Tactics, Techniques, Groups and Software

![Alt text](/img/dashboard-software-groups.jpg?raw=true "ELK artifacts")


# Filtering out by MITRE ATT&CK Techniques

![Alt text](/img/ps-filter.jpg?raw=true "ELK artifacts")

# Installation
1. Clone or fork this repo git@github.com:michaelhidalgo/attack-to-elk.git
2. Create a virtual environment using virtualenv:
```
virtualenv env
```

3. Activate the virtual environment running source env/bin/activate from the root folder.
5. Install dependencies from requirements file pip3 install -r requirements.txt
5. Export following environment variables with Elasticsearch IP address and port:
 ```
   export es_hostname='Your ELK IP'
   export es_port='Your ELK port (9200 by default)'
  ```
6. Run the program using Python3:
``` python
python3 attack-to-elk.py
```
# Importing ELK artifacts

All visualizations, index patterns and dashboards were exported into an [artifact JSON file](https://github.com/michaelhidalgo/attack-to-elk/tree/master/elk-artifacts).

Once you've run the script and indexing the matrix, you can go to Kibana Management -> Saved Objects and Import. From there you can choose the artifacts JSON described above and that's it.


![Alt text](/img/artifact-import.jpg?raw=true "ELK artifacts")






Get a quick overview
cat gaga |awk -F"technique" '{print $3}'|awk -F"'" '{print $1 " " $5}'|sort|uniq -c
     79  
      5 s/T1003/ OS Credential Dumping
      1 s/T1015/ Accessibility Features
      2 s/T1016/ System Network Configuration Discovery
      5 s/T1021/ Remote Services
      3 s/T1033/ System Owner/User Discovery
      2 s/T1035/ Service Execution
      7 s/T1036/ Masquerading
      1 s/T1040/ Network Sniffing
     15 s/T1043/ Commonly Used Port
      1 s/T1044/ File System Permissions Weakness
      1 s/T1049/ System Network Connections Discovery
      2 s/T1050/ New Service
      3 s/T1053/ Scheduled Task/Job
      5 s/T1055/ Process Injection
      2 s/T1057/ Process Discovery
      9 s/T1059/ Command and Scripting Interpreter
      4 s/T1064/ Scripting
      2 s/T1068/ Exploitation for Privilege Escalation
      3 s/T1070/ Indicator Removal on Host
      2 s/T1071/ Application Layer Protocol
     10 s/T1078/ Valid Accounts
      1 s/T1081/ Credentials in Files
      3 s/T1082/ System Information Discovery
      2 s/T1085/ Rundll32
      1 s/T1087/ Account Discovery
      2 s/T1088/ Bypass User Account Control
     19 s/T1089/ Disabling Security Tools
      1 s/T1093/ Process Hollowing
     12 s/T1098/ Account Manipulation
      1 s/T1100/ Web Shell
      5 s/T1105/ Ingress Tool Transfer
      6 s/T1107/ File Deletion
      3 s/T1108/ Redundant Access
      4 s/T1110/ Brute Force
      1 s/T1111/ Two-Factor Authentication Interception
      1 s/T1116/ Code Signing
      1 s/T1117/ Regsvr32
      1 s/T1118/ InstallUtil
      1 s/T1121/ Regsvcs/Regasm
      7 s/T1127/ Trusted Developer Utilities Proxy Execution
      2 s/T1133/ External Remote Services
      3 s/T1136/ Create Account
      2 s/T1138/ Application Shimming
      4 s/T1140/ Deobfuscate/Decode Files or Information
      1 s/T1142/ Keychain
      1 s/T1145/ Private Keys
      1 s/T1146/ Clear Command History
      2 s/T1158/ Hidden Files and Directories
      2 s/T1166/ Setuid and Setgid
      1 s/T1169/ Sudo
      1 s/T1170/ Mshta
      6 s/T1190/ Exploit Public-Facing Application
      1 s/T1192/ Spearphishing Link
      3 s/T1193/ Spearphishing Attachment
      1 s/T1204/ User Execution
      2 s/T1210/ Exploitation of Remote Services
      1 s/T1211/ Exploitation for Defense Evasion
      2 s/T1215/ Kernel Modules and Extensions
      1 s/T1218/ Signed Binary Proxy Execution
      2 s/T1219/ Remote Access Software
      2 s/T1220/ XSL Script Processing
      3 s/T1222/ File and Directory Permissions Modification
      2 s/T1223/ Compiled HTML File
      1 s/T1483/ Domain Generation Algorithms
      5 s/T1485/ Data Destruction
      1 s/T1489/ Service Stop
      1 s/T1490/ Inhibit System Recovery
      3 s/T1492/ Stored Data Manipulation
      1 s/T1498/ Network Denial of Service
      1 s/T1500/ Compile After Delivery
      1 s/T1526/ Cloud Service Discovery
      2 s/T1528/ Steal Application Access Token
      4 s/T1530/ Data from Cloud Storage Object
      6 s/T1531/ Account Access Removal
      2 s/T1537/ Transfer Data to Cloud Account
      1 s/T1548/ Abuse Elevation Control Mechanism
      7 s/T1562/ Impair Defenses

