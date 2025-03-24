import requests
import json
import os
import hashlib
import pgpy

github_owner = "izzy64"
repo_name = "test-csaf-aggregator"

def clean_key(key):
    lines = key.splitlines()
    filtered_list = [x for x in lines if not any(y in x for y in ["Version", "Comment", "MessageID", "Hash", "Charset"])]
    filtered_key = "\n".join(filtered_list).replace("\n\n", "\n")
    return filtered_key

try:
    with open("./aggregator.json", "r") as agg:
        contents = agg.read()
        aggregator = json.loads(contents)
except:
    print("aggregator.json not found")

for i, provider in enumerate(aggregator["csaf_providers"]):
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
    aggregator["csaf_providers"][i]["mirrors"][0] = f"https://raw.githubusercontent.com/{github_owner}/{repo_name}/main/{publisher_name}/provider_metadata.json".replace(" ", "%20")

    # keep the provider public keys
    provider_keys = provider_metadata["public_openpgp_keys"]
    for j, key in enumerate(provider_keys):
        provider_keys[j]["blob"] = clean_key(requests.get(
            provider_keys[j]["url"], allow_redirects=True, verify=True
        ).text)

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
                        if not os.path.exists(path_start+"/"+rolie['id']): 
                            os.makedirs(path_start+"/"+rolie['id'])
                        feed_path = path_start+"/"+rolie['id']
                        with open(f"{feed_path}/{rolie['id']}.json", "w") as outfile:
                            json.dump(rolie, outfile, indent=2, sort_keys=True)
                        if rolie["entry"]:
                            for entry in rolie["entry"]:
                                csaf_response = requests.get(entry["content"]["src"])
                                csaf = csaf_response.json()
                                if csaf:
                                    with open(f"{feed_path}/{entry['id']}.json", "w") as outfile:
                                        json.dump(csaf, outfile, indent=2, sort_keys=True)
                                for link in entry["link"]:
                                    if link["rel"] in ["hash", "signature"]:
                                        link_response = requests.get(
                                            link["href"], allow_redirects=True, verify=True
                                        ).text
                                        # check sig
                                        if link["rel"] == "signature":
                                            for key in provider_keys:
                                                pub_key, _ = pgpy.PGPKey.from_blob(key["blob"])
                                                if bool(pub_key.verify(csaf_response.text, pgpy.PGPSignature.from_blob(link_response))):
                                                    with open(f"{feed_path}/{link['href'].split('/')[-1]}", "w") as outfile:
                                                        outfile.write(link_response)
                                                else:
                                                    print("Provider signature does not match")
                                        # check hash
                                        if link["rel"] == "hash":
                                            if link["href"].split(".")[-1] == "sha256":
                                                if hashlib.sha256(csaf_response.text.encode('UTF-8')).hexdigest() == link_response.split(" ")[0]:
                                                    with open(f"{feed_path}/{link['href'].split('/')[-1]}", "w") as outfile:
                                                        outfile.write(link_response)
                                            elif link["href"].split(".")[-1] == "sha512":
                                                if hashlib.sha512(csaf_response.text.encode('UTF-8')).hexdigest() == link_response.split(" ")[0]:
                                                    with open(f"{feed_path}/{link['href'].split('/')[-1]}", "w") as outfile:
                                                        outfile.write(link_response)
                                            else:
                                                print("hashing method not supported")

                        else:
                            print("ROLIE missing critical information")
                except Exception as e:
                    print(e)

with open("./aggregator.json", "w") as outfile:
    json.dump(aggregator, outfile, indent=2, sort_keys=True)           








        



    
 