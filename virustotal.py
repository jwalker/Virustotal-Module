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
		self.apikey = "435e55fcc864a1b74457ae08c7415b096deeb82c445d6d19092f4e29a7ec1a87"

	def rscReport(self, rsc):
		""" Get latest report of resource """

		buf = {}
		base = self.base + 'file/report'
		parameters = {"resource":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		for item in resp:
			buf[item] = resp[item]

		return buf

	def urlReport(self, rsc, scan=0):
		""" Get latest report URL scan report of resource """

		buf = {}
		base = self.base + 'url/report'
		parameters = {"resource":rsc, "scan":scan, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		for item in resp:
			buf[item] = resp[item]

		return buf

	# ipReport()/domainReport() both return 404 / Errors related to get to the API
	def ipReport(self, rsc):
		""" Get latest report for IP Address """

		buf = {}
		base = self.base + 'ip-address/report'
		parameters = {"ip":rsc, "apikey":self.apikey}
		r = requests.get(base, data=parameters)
		resp = r.text
		return resp
		
	def domainReport(self, rsc):
		""" Get latest report for IP Address """

		buf = {}
		base = self.base + 'domain/report'
		parameters = {"domain":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.text
		return resp
		

	def scanURL(self, rsc):
		""" Send RSC/URL for scanning; Its encouraged to check for last scanusing urlReport()
		To submit batch rsc should be example.com\nexample2.com"""

		buf = {}
		base = self.base + 'url/scan'
		parameters = {"url":rsc, "apikey":self.apikey}
		r = requests.post(base, data=parameters)
		resp = r.json()
		for item in resp:
			buf[item] = resp[item]

		return buf

	def rscSubmit(self, rsc):
		pass

