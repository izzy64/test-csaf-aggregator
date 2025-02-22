import requests
import json
import os 

from rolie_config import rolie_feeds

for rolie_name, rolie_url in rolie_feeds.items():
    try:
        rolie_response = requests.get(
            rolie_url, allow_redirects=True, verify=True
        )
        rolie = rolie_response.json()["feed"]
        if rolie:
            if not os.path.exists("./"+rolie_name): 
                os.makedirs("./"+rolie_name)
            with open(f"./{rolie_name}/{rolie['id']}.json", "w") as outfile: # Should there be additional folders by publication year?
                json.dump(rolie, outfile, indent=2, sort_keys=True)
            if rolie["entry"]:
                for entry in rolie["entry"]:
                    csaf_response = requests.get(entry["content"]["src"])
                    csaf = csaf_response.json()
                    if csaf:
                        with open(f"./{rolie_name}/{entry['id']}.json", "w") as outfile: # Should there be additional folders by publication year?
                            json.dump(csaf, outfile, indent=2, sort_keys=True)
                    for link in entry["link"]:
                        if link["rel"] == "signature":
                            ghhg
                        if link["rel"] == "hash":
                            ghhg

            else:
                print("ROLIE missing critical information")
    except Exception as e:
        print(e)






        



    
 