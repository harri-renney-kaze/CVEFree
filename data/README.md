# Data

Full breakdown and description of the data provided by this open repository.

## Data Fields

| Commit | Type | Description |
| -- | -- | -- |
| [cve](https://www.cve.org) | String  | Official unique identifier for vulnerabilities published by the NVD |
| description | String  | Official description for the CVE published by the NVD |
| vendors | \[String\]  | List of vendors effected by the CVE |
| [cvssv2](https://www.first.org/cvss/) | Decimal [0.0-10.0]  | Version 2 of the official defacto severity scoring of CVEs, produced by "experts" filling out ordinal scales. Can use Version 2 as compromise if version 3 doesn't exist. |
| [cvssv3](https://www.first.org/cvss/) | Decimal [0.0-10.0]  | Version 3 of the official defacto severity scoring of CVEs, produced by "experts" filling out ordinal scales. Use Version 3 over 2 when possible. |
| [epss](https://www.first.org/epss/#:~:text=The%20Exploit%20Prediction%20Scoring%20System,better%20prioritize%20vulnerability%20remediation%20efforts.) | Decimal [0.0-1.0]  | Predictive score that a CVE is exploited in the next 30 days, produced by a gradient boosted machine learning model |
| vendors | \[String\]  | List of vendors effected by the CVE |
| cti_count | Number  | Count of the number of times a CVE has been found in a collection of monitored cyber threat intelligence report and articles feeds. |
| social_media_audience | Number  | Estimate for the number of people who have seen a CVE being discussed on social media platforms (currently Twitter & Reddit) |
| software_cpes | [String]  | List of the CPEs that are effected by the CVE vunlreabuility. CPE is the common platform enumeration, a standard for identifying software and hardware. (Currently file too large for github, use alternative storage end-point to get this) |

## Full data

For full data include software CPEs related to the CVEs, request the JSON file from the following publicly accessible end-point:

'''
https://kazepublic.blob.core.windows.net/cvefree/cve_cpe.json
'''