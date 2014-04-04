Virustotal Module - VirusTotal Public API 2.x

The Virustotal module is a python API module for the Virustotal.com Public API.

Prerequisites:
- json - default module with python
- python requests module - http://docs.python-requests.org/en/latest/

This module can be used to upload, scan, submit, comment and grab reports from the
Virustotals public API. Special thing about this module is, you are giving the
user full control on how to present the return results as well as it being cross
compatible.

In the virustotal.py, be sure to insert you Virustotal APIKEY in order to query
API. If you do not have a key, you can register for one at the site below.

http://virustotal.com

So without further adie, I will present a few simple functions that the module can
perform.

## Usage:
### Grab latest report
```python
>>> # Grab latest report of HASH and only pull certain values
>>> from virustotal import *
>>> rsc = "9c064772651a14ca8936d02d98f843ed" # Hash of resource to look up
>>>
>>> v = Virustotal()
>>> results = v.rscReport(rsc)
>>> for item in results:
...         if item == "resource":
...                 print "Grabbing last submitted report for:", results[item]
...         if item == "permalink":
...                 print "Report link:", results[item]
...         if item == "md5":
...                 print "md5sum:", results[item]
...         if item == "scan_date":
...                 print  "Last scanned:", results[item]
...         if item == "positives":
...                 print "Positive hits:", results[item]
...         if item == "total":
...                 print "Total AVs tested:", results[item]
...
Report link: https://www.virustotal.com/file/b7ab5bcd4edfd8ac7be17dd0650e01c4d519814784609851be9b2df571e501f3/analysis/1396511495/
Grabbing last submitted report for: 9c064772651a14ca8936d02d98f843ed
Last scanned: 2014-04-03 07:51:35
Total AVs tested: 50
Positive hits: 48
md5sum: 9c064772651a14ca8936d02d98f843ed
```

### Post comment
```python
>>> # Post comment about resource
... from virustotal import *
>>> rsc = "9c064772651a14ca8936d02d98f843ed" # Hash of resource to post comment about
>>> comment = "Captured with #honeypot #dionaea"
>>> v = Virustotal()
>>> results = v.postComment(rsc, comment)
Your comment was successfully posted
Report link: https://www.virustotal.com/file/b7ab5bcd4edfd8ac7be17dd0650e01c4d519814784609851be9b2df571e501f3/analysis/1396511495/
```

### Get URL report or submit for scan
```python
>>> # Check domain for report if no results submit it for a scan
>>> v = Virustotal()
>>> dchk = v.domainReport(rsc)
>>> if dchk["response_code"] == 0:
...         print "No dataset found for %s" %(rsc)
...         print "Running scan for resource..."
...         results = v.scanURL(rsc)
...         for item in results:
...                 if item == "permalink":
...                         print "Check link below for results:"
...                         print results[item]
... else:
...         for item in dchk:
...                 if item == "scan_date":
...                         print "Last scanned:", dchk[item]
...                 if item == "permalink":
...                         print "Results link:", dchk[item]
...
No dataset found for www.norcaljazzfestival.com
Running scan for resource...
Check link below for results:
https://www.virustotal.com/url/d5a5c2532462ed8dda2324f1967916dc4c5c1aa828dce4c5cd7459c8084f7084/analysis/1396592916/
```
