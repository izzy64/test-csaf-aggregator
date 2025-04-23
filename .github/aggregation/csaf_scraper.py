import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib3

import json
import os
import hashlib
import pgpy
from datetime import datetime
import dateutil.parser as parser

from helpers import time_convert, clean_key
import env

####################################################################
# Title: CSAF Scraper for CSAF Aggregator
# Author: Israel Bentley & Matthew Stradling
# Org: Idaho National Laboratory on behalf of 
#       Cypersecurity and Infrastructure Security Agency (CISA)
####################################################################
if not env.verify:
    urllib3.disable_warnings(InsecureRequestWarning)

now = datetime.now()

def load_aggregator():
    '''Load Aggregator
    Load the Aggregator.json file and read it into a dictionary.

    Args:
        None
    Returns:
        aggregator: as a dictionary object.
    '''
    try:
        with open(f"./{env.aggregator_name}", "r") as agg:
            contents = agg.read()
            aggregator = json.loads(contents)
    except:
        print("aggregator.json not found")
        aggregator = {}
    return aggregator
def verify_signature(link, keys, signature, csaf, feed_path):
    '''Verify Signature
    Using a CSAF Provider's OpenPGP Public Key, save a signature file for a given CSAF
    if it passes verification.

    Args:
        link: The URL from a CSAF Provider's ROLIE feed.
        keys: A list of OpenPGP Public Keys from the CSAF Provider's Metadata.
        signature: The signature file for the given CSAF.
        csaf: The CSAF itself.
        feed_path: The folder path to the mirrored location in the aggregator.
    Returns:
        None
    '''
    for key in keys:
        pub_key, _ = pgpy.PGPKey.from_blob(key["blob"])
        if bool(pub_key.verify(csaf.text, pgpy.PGPSignature.from_blob(signature))):
            with open(f"{feed_path}/{link['href'].split('/')[-1]}", "w") as outfile:
                outfile.write(signature)
        else:
            print("Provider signature does not match")
def verify_hash(link, hash, csaf, feed_path):
    '''Verify Hash
    Verify the hash files to a given CSAF file, saving if valid.

    Args:
        link: The URL from a CSAF Provider's ROLIE feed.
        hash: The hash file for the given CSAF.
        csaf: The CSAF itself.
        feed_path: The folder path to the mirrored location in the aggregator.
    Returns:
        None
    '''
    if link["href"].split(".")[-1] == "sha256":
        if hashlib.sha256(csaf.text.encode('UTF-8')).hexdigest() == hash.split(" ")[0]:
            with open(f"{feed_path}/{link['href'].split('/')[-1]}", "w") as outfile:
                outfile.write(hash)
    elif link["href"].split(".")[-1] == "sha512":
        if hashlib.sha512(csaf.text.encode('UTF-8')).hexdigest() == hash.split(" ")[0]:
            with open(f"{feed_path}/{link['href'].split('/')[-1]}", "w") as outfile:
                outfile.write(hash)
    else:
        print("hashing method not supported")
def get_provider_pgp_keys(metadata:dict, num_requests:int):
    '''Get Provider PGP Keys
    Download the OpenPGP Keys of a CSAF Provider from their Metadata.

    Args:
        metadata: The data of a provider's metadata as a dictionary.
        num_requests: An integer keeping track of the number of web requests made.
    Returns:
        provider_keys: list of dictionaries containing the Provider's OpenPGP Keys
        num_requests: An updated count of web requests made.
    '''
    provider_keys = json.loads(json.dumps(metadata["public_openpgp_keys"]))
    for j, key in enumerate(provider_keys):
        provider_keys[j]["blob"] = clean_key(requests.get(
            provider_keys[j]["url"], allow_redirects=True, verify=env.verify
        ).text)
        num_requests += 1
    return provider_keys, num_requests
def aggregate_provider_files(provider:dict, n_requests:int=0):
    '''Aggregate Provider Files
    Using a Provider's metadata, the aggregator will make web requests to download the ROLIE
    feed of the Provider and call additional functions to grab OpenPGP Keys.

    After reading in the ROLIE feed, the aggregator will download and mirror files from the Provider's
    CSAF distribution.

    Args:
        provider: a dictionary with data on the CSAF Provider and their Metadata.
        n_requests: an integer keeping track of the number of web requests made.
    Returns:
        n_requests: an updated integer of the number of web requests made.
    '''
    pm_url = provider["metadata"]["url"]
    publisher_name = provider["metadata"]["publisher"]["name"]
    print(f"Fetching results for provider {publisher_name}")
    path_start = "./"+publisher_name
    pm_response = requests.get(
        pm_url, allow_redirects=True, verify=env.verify
    )
    n_requests += 1
    provider_metadata = pm_response.json()
    # update provider metadata
    provider_metadata["canonical_url"] = f"{env.github_raw_path_start}/{env.github_owner}/{env.repo_name}/{env.branch}/{publisher_name}/provider_metadata.json".replace(" ", "%20")
    provider_metadata["last_updated"] = now.strftime(env.dt_format)
    provider["metadata"]["last_updated"] = now.strftime(env.dt_format)

    # keep the provider public keys
    provider_keys, n_requests = get_provider_pgp_keys(provider_metadata, n_requests)

    # scrape the rolie feeds
    for distro in provider_metadata["distributions"]:
        if "rolie" in distro.keys():
            for feed in distro["rolie"]["feeds"]:
                try:
                    # fetch rolie
                    rolie_response = requests.get(
                        feed["url"], allow_redirects=True, verify=env.verify
                    )
                    n_requests += 1
                    rolie = rolie_response.json()
                    if rolie:
                        print(f"Fetching results for ROLIE feed {rolie['feed']['id']}")
                        if not os.path.exists(path_start+"/"+rolie["feed"]['id']): 
                            os.makedirs(path_start+"/"+rolie["feed"]['id'])
                        feed_path = path_start+"/"+rolie["feed"]['id']
                        rolie_copy = json.loads(json.dumps(rolie)) # equivalent to deep copy
                        try:
                            with open(f"{feed_path}/{rolie['feed']['id']}.json", "r") as old_file:
                                old_rolie = json.loads(old_file.read())
                        except:
                            old_rolie = {}

                        if rolie["feed"]["id"] == "siemens-security-advisories-csaf-feed-tlp-white":
                            rolie = old_rolie

                        feed["url"] = f"{env.github_raw_path_start}/{env.github_owner}/{env.repo_name}/{env.branch}/{publisher_name}/{rolie['feed']['id']}/{rolie['feed']['id']}.json".replace(" ", "%20")

                        rolie_dict = {item['id']:item|{"update":True} for item in rolie.get("feed",{}).get("entry",[])}
                        old_rolie_dict = {it['id']:it|{"update":True} for it in old_rolie.get("feed",{}).get("entry",[])}

                        # Cull already fetched csafs from fetch pool
                        if rolie.get("feed",{}).get("entry",[]):
                            for entry in rolie["feed"]["entry"]:
                                if entry["id"] in old_rolie_dict.keys():
                                    try:
                                        updated_time = parser.parse(rolie_dict.get(entry["id"],{}).get("updated",""))
                                        old_updated_time = parser.parse(old_rolie_dict.get(entry["id"],{}).get("updated",""))
                                    except Exception as e:
                                        print("Error here: "+str(e))
                                        continue
                                    if updated_time >= old_updated_time:
                                        rolie_dict[entry["id"]]["update"] = False

                        # fetch csafs for update
                        for advid, entry in rolie_dict.items():
                            if entry["update"]:
                                print(f"Fetching data for {entry['id']}")
                                try:
                                    csaf_response = requests.get(
                                        entry["content"]["src"], allow_redirects=True, verify=env.verify
                                    )
                                    n_requests += 1
                                    csaf = csaf_response.json()
                                    if csaf:
                                        with open(f"{feed_path}/{entry['id']}.json", "w") as outfile:
                                            print(f"Saving {entry['id']}")
                                            json.dump(csaf, outfile, indent=2, sort_keys=True)
                                    for link in entry["link"]:
                                        if link["rel"] in ["hash", "signature"]:
                                            link_response = requests.get(
                                                link["href"], allow_redirects=True, verify=env.verify
                                            ).text
                                            n_requests += 1

                                            # check sig
                                            if link["rel"] == "signature":
                                                verify_signature(link,provider_keys,link_response,csaf_response,feed_path)
                                            # check hash
                                            if link["rel"] == "hash":
                                                verify_hash(link,link_response,csaf_response,feed_path)
                                except Exception as e:
                                    print(e)
                                    pass

                        # update mirrored ROLIE
                        if rolie_copy.get("feed",{}).get("link",[]):
                            rolie_copy["feed"]["link"] = [
                                {
                                    "rel": "self",
                                    "href": f"{env.github_raw_path_start}/{env.github_owner}/{env.repo_name}/{env.branch}/{publisher_name}/{rolie_copy['feed']['id']}.json".replace(" ", "%20")
                                },
                            ]
                        if rolie_copy.get("feed",{}).get("updated",""):
                            rolie_copy["feed"]["updated"] = now.strftime(env.dt_format)

                        # Save mirrored ROLIE
                        with open(f"{feed_path}/{rolie_copy['feed']['id']}.json", "w") as outfile:
                            print(f"Saving ROLIE {rolie_copy['feed']['id']}")
                            json.dump(rolie_copy, outfile, indent=2, sort_keys=True)

                except Exception as e:
                    print(e)
                    pass
                    
    # save the mirrored provider metadata
    if not os.path.exists("./"+publisher_name): 
        os.makedirs("./"+publisher_name)
    with open(f"{path_start}/provider_metadata.json", "w") as outfile:
        print(f"Saving Provider Metadata for {publisher_name}")
        json.dump(provider_metadata, outfile, indent=2, sort_keys=True)
    return n_requests
def parse_aggregator(aggregator:dict):
    '''Parse Aggregator
    Read through the Aggregator.json file and then fetch the following resources 
    from a mirrored CSAF Provider listed in the json file:
    > Provider Metadata
    > OpenPGP Public Keys (not mirrored)
    > ROLIE feed
    > CSAF files, hashs, signatures

    Args:
        aggregator: a dictionary holding the data from the aggregator.json
    Returns:
        None
    '''
    n_requests = 0
    for i, provider in enumerate(aggregator["csaf_providers"]):
        n_requests = aggregate_provider_files(provider, n_requests)
        publisher_name = provider["metadata"]["publisher"]["name"]
        aggregator["csaf_providers"][i]["mirrors"][0] = f"{env.github_raw_path_start}/{env.github_owner}/{env.repo_name}/{env.branch}/{publisher_name}/provider_metadata.json".replace(" ", "%20")

    print(f"The Aggregator made {n_requests} external requests")
def update_aggregator(aggregator:dict):
    '''Update Aggregator
    Update the aggregator.json file with new links to the mirrored folder locations.

    Args:
        aggregator: a dictionary holding the data from the aggregator.json
    Returns:
        None
    '''
    with open(f"./{env.aggregator_name}", "w") as outfile:
        json.dump(aggregator, outfile, indent=2, sort_keys=True)           
def main():
    '''Main
    Load the aggregator.json.
    Parse the aggregator.
    Update the aggregator.json.

    Args:
        None
    Returns:
        None
    '''
    agg = load_aggregator()
    if agg:
        parse_aggregator(agg)
        update_aggregator(agg)

if __name__=="__main__":
    main()
