<a name="0.1.0"></a>
# 0.1.0 (2023-08-31)

### Release Highlights
The initial release for testing and understanding what data the community is interested in accessing. This release contains a single JSON file containing high-level scores and values for each vulnerability (CVE) and a single notebook that introduces some basic plots that can be produced using the available data.

* A more detailed cve_cpe.json file available to download from ```https://kazepublic.blob.core.windows.net/cvefree/cve_cpe.json```

### Data Sources

* All officially published vulnerabilities identified by CVE ID.
* Offical description published by the NVD for each CVE.
* Kaze's V-Scoring system - Using a weighted formula of various informative components about each CVE, a prioritisation score is calculated.
* EPSS - A value predicting the likelihood of a vulnerability being exploted in the next 30days. This score has been produced by a gradient boost machine learning model with evidence suggesting it to be highly accurate.
* CVSS -  The official defacto severity scoring system that the NVD attempts to calculate using experts for all published CVEs.
* CTI Count - Number of times a vulnerability is mentioned in the feeds of credible Cyber Threat Intelligence reports and articles being monitored on the web.
* Social Media Audience - An estimate on the potential exposure of vulnerabilities to people on twitter and reddit.
* Vendors - List of vendors that are effected by the vulnerability.


### Future Plans

* Improve serving of JSON data files (Potentially hosting on blob storage end-point).
* More data connected to each CVE, such as all CVSS scoring component, tweets and reddit posts mentioning each CVE in the last 30 days, and more.