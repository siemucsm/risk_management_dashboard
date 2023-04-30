![Alt text](/img/NIST800-53-Dashboard.png?raw=true "NIST800-53 Dashboard")

# Introduction
The work for this project started more than 2 years ago. I have been procastinating and putting my focus on other things. I am glad to finally been able to close this one of the list.

The Center for Threat-Informed Defense (mitre-engenuity.org/ctid/) has released a set of mappings between the Mitre Attack Framework (https://attack.mitre.org/) and NIST Special Publications 800-53 (https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final). Tiffany Bergeron and Jon Baker have written a post (https://medium.com/mitre-engenuity/security-control-mappings-a-bridge-to-threat-informed-defense-2e42a074f64a) detailing some of the benefits of the mapping activity. Check out also their github repository (https://github.com/center-for-threat-informed-defense/attack-control-framework-mappings), where you can access all the related work.

The work by the CTID team is the missing piece to my previous work (https://www.siemucsm.com). In my master thesis I came to the conclusion, that mappings from the Mitre Attack Framework to various Security Standards can help to define a strategie to deploy SIEM Use Cases but also will allow a business centric approach to view a very technical driven subject (https://www.siemucsm.com/methodology/). Due to my time and resource constraints it would not have been an option to map all Attack Techniques to an individual security control standard such as NIST SP800-53, ISO 27001 or NIST CSF.

Well, that seems to be out of the way :)

So what can we do with that data?


# Use Cases - implemented and ready to be played with

One of my area of interest is defining and building security monitoring infrastructures. From a subject matter expertise I believe I do have a solid know how, experience and expertise to build these environments. However, it always has been a challenge to provide all stakeholders an understandable reasoning behind decisions on defining a cyber monitoring strategy and how to prioritise and define cyber security monitoring roadmap.

By combining the data mentioned in the introduction, I wanted to explore use cases with the goal to assist the design process and have visualisations of your cyber detection programe for technical or business oriented stakeholders.

Key questions to be answered:
* Our management does not understand why we are focusing our effort on a particular piece of technology to detect cyber threats. How can we communicate our technical expertise with a business centric logic?
* We have developed this great cyber detection programe. How can we show how that program protects the business?
* What area of our infrastructure is the most vulnerable and how can we decide what to invest ressources for our cyber detection programme?
* The cyber detection infrastructure produces data, can we correlate that to our business information or business risks?
* We know what our risks are, how can we correlate that to actual cyber threats against our infrastructure?
* Can I relate our risk controls to actual cyber detection capabilities?

## Cyber Risk coverage map (Part of this release)
There are many ways of how to answer the question of what at risk is. The answer always depends on who is answering that question. What us the Mitre Attack Framework and a Secuirty Framework such as NIST800-53 permits to do, is to visualise variable scenarios. Depending on the standpoint, the data helps to draw conconlusions or to drive a discussion.

What is impacted by an attack?

Example:
![Alt text](/img/NIST800-53-Dashboard-Show-impact-of-alert.png?raw=true "Mitre Att&ck Framework Dashboard")

By filtering for a specific Attack Technique (Command and Scripting Interpreter T1059), we can start working with the data.
* In the first graph (1), there are all related NIST 800-53 control families shown. The color is darkened by the number of impacted Control Names. Just below that graph, the individual Control Names are shown (2).
* There are a few KPI panels (3) providing a quick overview of the relationship of that Attack Technique. These include the number of NIST Control Families, the NIST Controls, the number of SIEM Alert Rules and the number of detected cyber attacks against that threat.
* Depending on how data needs to be represented, the relationship of Attack Technique and NIST Control Families and individual Controls can be shown as a Map or a Donut graph (4). The drill down from these graphs can provide a very profound view of related Techniques, Mitigations, Detections or SIEM Alert Rules.
* The selected Technique is shown (5).
* The list of related SIEM Use Cases are show. These SIEM Use cases help to detect that specific Attack Technique (6).
* A very helpful item is shown in (7), which is a list of recommended mitigations against that Attack Technique. That information is even more useful, when a NIST Control is s used as a filter and you want to know what measures are recommended to mitigate against threats impacting that NIST Control.
* And last but not least, the actual detections in relation to the Attack Technique.

That information helps your organisation to understand what is impacted on the technical level but also, and most probaly more relevant, what part of the business is impacted.

Example:
![Alt text](/img/Core_Business_Process_Risks.png?raw=true "Core Business Process Risks")


## Attack Mitigation (Part of this release)
Select one or more NIST 800-53 Controls to list the recommended mitigations.

![Alt text](/img/NIST800-53-Dashboard-Mitigation.png?raw=true "NIST800-53 Mitigations")


## Identify an area for which you do not have coverage for


## Mitre Attack Dashboard (Part of this release)
Visualise the dataset of the Mitra Attack Framework.

## NIST 800-53 Dashboard (Part of this release)


# More Use Case ideas - not yet fully implemented

## ISO 27001
## NIST CSF
## ## Business Risk Map (Top Business Drivers)

# Dashboards
Following dashboards are available to support the above use cases.

## Mitre Attack Dashboard
The Mitre Attack Framework (https://attack.mitre.org/) offers a security professional various ways of doing research. Since I need the Mitre Attack data to relate the other security framework data for my project, it made sense to include also a dashboard just for the Mitre Attack Framework. For example to visualise which platforms are impacted by the Defense Evasion tactic.
I stumbed across the project done by Michael Hidalgo https://github.com/michaelhidalgo/attack-to-elk and decided to use import mechanism.

![Alt text](/img/Mitre-Attack-Dashboard.png?raw=true "Mitre Att&ck Framework Dashboard")

Using Filters to understand relationships

![Alt text](/img/Mitre-Attack-Dashboard-Tactic-Selection.png?raw=true "Exfiltration Tactic")


## NIST 800-53 Coverage Map
Real-time visualisation of Attacks against Security Controls

Real/time visualisation of Attacks against the Mitre Attack Framework

![Alt text](/img/NIST800-53-Dashboard.png?raw=true "NIST800-53 Dashboard")


# Types of Dashboards

## NIST 800-53 r5 Dashboard
Filters:
- NIST Control Family
- NIST Control Name
- Mitre Tactic Name
- Mitre Technique Name


# Installation

The installation of the dashboards in this data package requires a running *Elasticsearch* and *Kibana* instance. I tested the dashboard on v8.4.3.

If you do not have an Elastic Stack up and running, then you have several options. You can head over to [Elastic|https://www.elastic.co] and try a free trial. Another option is to run a local stack, the [Elastic Container Project|https://www.elastic.co/security-labs/the-elastic-container-project] is right for you.

Since we work with a document oriented database and the data used for this project is not engineered from the ground up, we need to apply a few steps mimic relationships. You will notice that these relationships are driven by the use cases. Additonal needs require to add more relationships to make these work such as particular aggregations or drill downs within the dashboards.

You also need Python ;)

## Clone or fork the project
```
git clone https://github.com/siemucsm/risk_management_dashboard.git
```

## Set up the environment
As mentioned, you need a working Elasticsearch and Kibana instance running, before you can load any data.

```
cd risk_management_dashboard
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
```

## Load data
The dashboard needs various datasets to be loaded into Elasticsearch.

### Mitre Attack Framework
We start with the Mitre Attack Framework data. This will also come with its own dashboard (See screenshot). Big thanks to Michael Hidalgo. I added some minor additions to load the latest Mitre dataset (v12) and to allow data cross referencing. I also gave the visualisations a minor overhaul.
```
attack-to-elk.py
```

### Mapping of CSF to NIST 800-53 Rev.5
The next data package is the mapping data of CSF to NIST 800-53 Rev.5. The data is directly loaded from the [NIST media publications|https://csrc.nist.gov/CSRC/media/Publications/sp/800-53/rev-5/final/documents/csf-pf-t
o-sp800-53r5-mappings.xlsx] and inserted into an Elasticsearch index. The data is used for data lookups.
```
csf_nist800_map.py
```

### Mapping of Security Control Framework to Attack v2 (enhancement) -> Own Dashboard
In this step we are loading the 
```
mitre_nist_mapping.py
```

[TESTED] Mapping of ISO27001 to NIST 800-53 Rev.5
nist800_iso27_map.py

Now we need the alert index. The script will collect all "enabled" rules and extract all tactics and techniques
I needs the mitre_nist_mapping_new index to function.
[TESTED] python rules.py

alert-rules
.siem-signals-default

## Load Artifacts
All visualizations, index patterns and dashboards were exported into an [artifact JSON file](https://github.com/michaelhidalgo/attack-to-elk/tree/master/elk-artifacts).

Kibana Management -> Saved Objects and Import. From there you can choose the artifacts JSON described above and that's it.


![Alt text](/img/artifact-import.jpg?raw=true "ELK artifacts")



Now you are done and can start using the dashboards.


# Usage


# NIST 800-53 r5 Dashboard

## Usage
Filters:
- NIST Control Family
- NIST Control Name
- Mitre Tactic Name
- Mitre Technique Name


# Mitre Attack Dashboard

## Usage


## Data Sources
The overal count of Data Sources is currently 39 (v12). The graphs include also the sub categories, which ammounts to 109 sources.

## Techniques


# Technical stuff

I am no programmer.. and never will be. It might be a great source for a drinking game. For every piece of code you find a more efficient way of writing it.. take a shot. Seriously, this can be improved in mmany ways.


/usr/share/elastic-agent/bin# ./elastic-agent enroll http://localhost:5601 V09xYTRYWUJKWnFiU05OS2J4QVg6NExaSHU1dmNUR0dsNTQtMDAtQTFkZw== --path.config /etc/elastic-agent/ --insecure

sudo service elastic-agent start

f7wQ7zEIP9Pn5IvUj5GlF841


# A better way to visualize, filter and search MITRE ATT&CK matrix

This program exports MITRE ATT&amp;CK enterpise matrix into a ELK dashboard. Check out [this blog post entry](https://michaelhidalgocr.blogspot.com/2019/01/mitre-att-as-kibana-dashboard-part-ll.html) for having better understanding on the benefits of exporting the ATT&CK enterprise matrix into ELK.

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

