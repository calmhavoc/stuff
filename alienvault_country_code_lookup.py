# curl https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general -H "X-OTX-API-KEY: <MYKEY>"


import requests
import ipaddress
import json
import sys


def ip_lookup(ip,apikey):
    ''' Accepts a single domain and outputs a list of breach data records '''
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {'X-OTX-API-KEY': apikey }
    r = requests.get(url,headers=headers)
    if r.status_code == "401":
        #raise
        print("Check 401 failure") 
    d = r.content.decode()
    data = json.loads(d)
    try:
        cc = data['country_code']
        # print(f"{ip}:{cc}")
        return cc
    except KeyError:
        cc = None
        return cc

ip = sys.argv[1]
apikey = ''  # needs your API key
try: 
    valid = ipaddress.ip_address(ip)
except ValueError:
    valid = "invalid IP"
finally:
    cc = ip_lookup(ip,apikey)
    print(f"{ip}:{cc}")
