import requests
import json
import sys

'''
API allows only 4 calls per minute, and a max of like 1000/day
sleep isn't defined in this script, I ran it with:
sudo find ./ -type f -executable -exec sh -c "file -i '{}' |grep -q 'x-executable; charset=binary'" \; -print > files.list
sha1deep -e -f files.list > hashes
for h in $(cat hashes|awk '{print $1}');do echo $h;python vttest.py $h >> vtresults.txt;sleep 15;done
'''



# VTAPIKEY="YOU MUST SET THIS"
# hash = "57f0839433234285cc9df96198a6ca58248a4707"  # nc.exe test hash
# hash = "abb99dda64e906dba4127d660177be9983edafab" random clean hash

def hash_lookup(hash):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": f"{VTAPIKEY}"
    }
    response = requests.get(url, headers=headers)
    jdata = json.loads(response.text)
    get_data(jdata,hash)
    # return jdata


def get_data(data, hash):
    if "error" in data.keys():
        try:
            if "not found" in data['error']['message']:
                print(f'{hash}: not found')
        except KeyError as e:
            print(f'{hash}: error {str(e)}, needs manual eval')
    elif "data" in data.keys():
        hash = hash
        count = data['data']['attributes']['last_analysis_stats']['malicious']
        if count > 0:
            threatname = data['data']['attributes']['bytehero_info']
        else: threatname="not found"

        print(f'{hash},{threatname},{count}')
    else:
        print(f'{hash}: needs manual eval')


hash = sys.argv[1]
hash_lookup(hash)
