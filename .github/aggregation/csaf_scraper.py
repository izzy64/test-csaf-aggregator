import requests
import json
import os 

try:
    with open("./aggregator.json", "r") as agg:
        contents = agg.read()
        aggregator = json.loads(contents)
except:
    print("aggregator.json not found")

for provider in aggregator["csaf_providers"]:
    pm_url = provider["metadata"]["url"]
    publisher_name = provider["metadata"]["publisher"]["name"]
    pm_response = requests.get(
            pm_url, allow_redirects=True, verify=True
        )
    provider_metadata = pm_response.json()
    # save the provider metadata
    if not os.path.exists("./"+publisher_name): 
        os.makedirs("./"+publisher_name)
    path_start = "./"+publisher_name
    with open(f"{path_start}/provider_metadata.json", "w") as outfile:
        json.dump(provider_metadata, outfile, indent=2, sort_keys=True)

    # scrape the rolie feeds
    for distro in provider_metadata["distributions"]:
        if "rolie" in distro.keys():
            for feed in distro["rolie"]["feeds"]:
                try:
                    rolie_response = requests.get(
                        feed["url"], allow_redirects=True, verify=True
                    )
                    rolie = rolie_response.json()["feed"]
                    if rolie:
                        path_start = path_start+"/"+rolie['id']
                        with open(f"{path_start}/{rolie['id']}.json", "w") as outfile:
                            json.dump(rolie, outfile, indent=2, sort_keys=True)
                        if rolie["entry"]:
                            for entry in rolie["entry"]:
                                csaf_response = requests.get(entry["content"]["src"])
                                csaf = csaf_response.json()
                                if csaf:
                                    with open(f"{path_start}/{entry['id']}.json", "w") as outfile:
                                        json.dump(csaf, outfile, indent=2, sort_keys=True)
                                # for link in entry["link"]:
                                #     if link["rel"] == "signature":
                                #         # save_sig()
                                #     if link["rel"] == "hash":
                                #         # save_hash()

                        else:
                            print("ROLIE missing critical information")
                except Exception as e:
                    print(e)
                








        



    
 