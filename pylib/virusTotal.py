#!/usr/bin/python
import sys
import requests

class virustotal(object):

	#apikey='46b28d72edf5ba21d5801b4ec062777a58f2be10b86370f538dd92022eddbf15'
	apikey='1c5341e35ba5efb4ec63990c1915d5735308a658a13e77075a13ee932c182cf3'

	def __init__(self):
		print("_init_.virustotal")

	def upfile(self, mfile):
		params={'apikey' : self.apikey}
		files = {'file': (mfile, open(mfile, 'rb'))}
		response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
		return response.json()

	def report(self, resource):
		params = {'apikey':  self.apikey , 'resource': resource}
		headers = {
			  "Accept-Encoding": "gzip, deflate",
			  "User-Agent" : "gzip,  My Python requests library example client or username"
			  }
		response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
		print(response.status_code)#, response.text)
		if response.status_code!=200:
			return None
		return response.json()


def main(argv):
	print "rasta",argv[0],argv[1]

	vt=virustotal()

	json = vt.upfile(argv[1])

	print(json)	

	print "Resurce: ", json["resource"]

	res = vt.report(json["resource"])
	
	print(res)	

	print "Positives: ", res["positives"]

	print "Total: ", res["total"]

	print " fin "


if __name__ == "__main__":
	main(sys.argv)
