import requests
import json
import os 

from rolie_config import rolie_feeds

for rolie_name, rolie_url in rolie_feeds.items():
    try:
        print(rolie_url)
        rolie_response = requests.get(
            rolie_url, allow_redirects=True, verify=True
        )
        rolie = rolie_response.json()["feed"]
        if rolie:
            if rolie["title"]:
                if not os.path.exists("../"+rolie["title"]):
                    os.makedirs("../"+rolie["title"])
            else:
                print("ROLIE missing critical information")
            if rolie["entry"]:
                with open(f"../{rolie['title']}/{rolie['id']}.json", "w") as outfile: # Should there be additional folders by publication year?
                    json.dump(rolie, outfile, indent=2, sort_keys=True)
                # for entry in rolie["entry"]:
                #     csaf_response = requests.get(entry["content"]["src"])
                #     csaf = csaf_response.json()
                #     if csaf:
                #         with open(f"../{rolie['title']}/{entry['id']}.json", "w") as outfile: # Should there be additional folders by publication year?
                #             json.dump(csaf, outfile, indent=2, sort_keys=True)
            else:
                print("ROLIE missing critical information")
    except Exception as e:
        print(e)






        



    
 