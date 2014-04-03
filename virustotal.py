# Virustotal Module
# Jacolon walker
#
# Below are Virustotal.com's API options/tags (for k:v responses)
# response_code, verbose_msg
# resource, scan_id, md5, sha1, sha256
# scan_date
# scans

import requests
import json

class Virustotal():
	""" Virustotal API module """
	def __init__(self):
		self.host = "www.virustotal.com"
		self.base = "https://www.virustotal.com/vtapi/v2/"
		self.apikey = "Your Virustotal APIKEY"

	def rscReport(self, rsc):
		""" Get latest report of resource """

		base = self.base + 'file/report'
		parameters = {"resource":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def urlReport(self, rsc, scan=0):
		""" Get latest report URL scan report of resource """

		base = self.base + 'url/report'
		parameters = {"resource":rsc, "scan":scan, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def ipReport(self, rsc):
		""" Get latest report for IP Address """

		base = self.base + 'ip-address/report'
		parameters = {"ip":rsc, "apikey":self.apikey}
		r = requests.get(base, params=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def domainReport(self, rsc):
		""" Get latest report for IP Address """

		base = self.base + 'domain/report'
		parameters = {"domain":rsc, "apikey":self.apikey}
		r = requests.get(base, params=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results
		
	def scanURL(self, rsc):

		""" Send RSC/URL for scanning; Its encouraged to check for last scanusing urlReport()
		To submit batch rsc should be example.com\nexample2.com"""

		base = self.base + 'url/scan'
		parameters = {"url":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results

	def rscSubmit(self, rsc):

		""" Submit potential malicious file to virustotal for analyzing """
		base = self.base + 'file/scan'
		f = open(rsc, 'rb')
		parameters = {"apikey":self.apikey}
		r = requests.post(base, data=parameters, files={'file':f})
		resp = r.json()
		results = parse_resp(resp)
		return results

	def rscRescan(self, rsc):

		""" Rescan potential malicious file to virustotal for analyzing without uploading the file again """
		base = self.base + 'file/rescan'
		parameters = {"resource":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		results = parse_resp(resp)
		return results


def parse_resp(resp):
	""" Parses the response from the requests.gets/posts()
	then returns the data back to the function """
	buf = {}
	for item in resp:
		buf[item] = resp[item]

	return buf
