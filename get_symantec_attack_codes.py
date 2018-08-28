#!/usr/bin/python
###################################
# Script Author: Steven Landy (@landw1re)
# Name: get_symantec_codes
# Description: This Python script scrapes the Symantec Attack Signature site and produces a .csv file
# that can be used to import into a lookup table for use in Splunk to assist with enriching 
# Symantec Endpoint Protection log event data
# License: MIT
###################################
from urllib.request import urlopen
from bs4 import BeautifulSoup
import re
import time
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import random
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NetworkError(RuntimeError):
	pass

def retryer(max_retries=10, timeout=5):
	def wraps(func):
		request_exceptions = (
			requests.exceptions.Timeout,
			requests.exceptions.ConnectionError,
			requests.exceptions.HTTPError
		)
		def inner(*args, **kwargs):
			for i in range(max_retries):
				try:
					result = func(*args, **kwargs)
				except request_exceptions:
					time.sleep(timeout)
					continue
				else:
					return result
			else:
				raise NetworkError
		return inner
	return wraps

def requests_retry_session(
	retries=3,
	backoff_factor=0.3,
	status_forcelist=(500, 502, 504),
	session = None,
	):
	
	session = session or requests.Session()
	retry = Retry(
		total = retries,
		read = retries,
		connect = retries,
		backoff_factor = backoff_factor,
		status_forcelist = status_forcelist,
	)
	
	adapter = HTTPAdapter(max_retries = retry)
	session.mount('http://', adapter)
	session.mount('https://', adapter)
	return session	

@retryer(max_retries=7, timeout=12)
def main():
    attack_signatures = requests_retry_session().get("https://www.symantec.com/security_response/attacksignatures/", verify=False)
    attack_signature_obj = BeautifulSoup(attack_signatures.text, "html5lib")

    with open('symantec_attack_signatures.csv', 'w') as out:
        out.write("SignatureID,severity,SignatureStr,signature_detail_url\n")
        
        for link in attack_signature_obj.find_all('a', attrs={'href': re.compile("/security_response/attacksignatures/detail.jsp\?asid=")}):
            search_sig_code = re.search('/security_response/attacksignatures/detail.jsp\?asid=([0-9]{1,10})', link.get('href'), re.IGNORECASE)
            sig_code = search_sig_code.group(1)
            #time.sleep(round(random.uniform(0.01, 0.09),2))

            sig_detail = requests_retry_session().get("https://www.symantec.com" + link.get('href'), verify=False)
            sig_detail_obj = BeautifulSoup(sig_detail.text, "html5lib")

            severity = "unknown"
            for h in sig_detail_obj.find_all('h3'):
                search_severity = re.search('severity:\s([a-z].*)', str(h), re.IGNORECASE)

                if search_severity is not None:
                    severity = str(search_severity.group(1)).lower().strip()

            out.write("{},{},{},https://www.symantec.com{}\n".format(sig_code, severity, link.contents[0], link.get('href')))

if __name__=='__main__':
	main()
