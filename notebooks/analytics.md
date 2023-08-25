# Histogram
Build out histrograms to count distributions of scores for comparison. Notice how CVSS is heavily weight towards alerting critical CVEs. This becomes overwhelming and evidence shows that distributions that have less criticals to prioritise improves remediation efforts.


```python
import json

# Opening JSON file
f = open('../full_history_test.json')
 
# returns JSON object as
# a dictionary
data = json.load(f)
 
# Iterating through the json list and populate histograms
x_two = []
x_three = []
for i in data['cves']:
    if 'cvssv2_base_score' in i:
        x_two.append(i['cvssv2_base_score'])
    if 'cvssv3_base_score' in i:
        x_three.append(i['cvssv3_base_score'])

plt.hist(x_two)
plt.xlabel("CVSS v2 Score")
plt.ylabel("CVE Count")
plt.show()
plt.hist(x_three)
plt.xlabel("CVSS v3 Score")
plt.ylabel("CVE Count")
plt.show()
 
# Closing file
f.close()
```


    
![png](analytics_files/analytics_1_0.png)
    



    
![png](analytics_files/analytics_1_1.png)
    



```python

```
