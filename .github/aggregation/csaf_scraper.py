####################################################################
# Title: CSAF Scraper for CSAF Aggregator
# Author: Israel Bentley & Matthew Stradling
# Org: Idaho National Laboratory on behalf of 
#       Cybersecurity and Infrastructure Security Agency (CISA)
####################################################################
##########################
# Python Standard Library
##########################
import json
import os
from datetime import datetime
import hashlib
##########################
# Apache Software License
##########################
import requests
##########################
# BSD License
##########################
import pgpy
import dateutil.parser as parser # Apache Software License also
##########################
# MIT License
##########################
from urllib3.exceptions import InsecureRequestWarning
import urllib3
##########################
# Custom Local Files
##########################
import env

if not env.verify:
    urllib3.disable_warnings(InsecureRequestWarning)

now = datetime.now()
workingdir = os.getcwd()

def clean_key(key):
    lines = key.splitlines()
    filtered_list = [x for x in lines if not any(y in x for y in ["Version", "Comment", "MessageID", "Hash", "Charset"])]
    filtered_key = "\n".join(filtered_list).replace("\n\n", "\n")
    return filtered_key

def load_aggregator():
    '''Load Aggregator
    Load the Aggregator.json file and read it into a dictionary.

    Args:
        None
    Returns:
        aggregator: as a dictionary object.
    '''
    try:
        # Read in Aggregator.json
        with open(workingdir+os.sep+f"{env.aggregator_name}", "r") as agg:
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
    verified = False
    # Load CSAF content
    csaf_data = json.loads(csaf.text)
    save_name = csaf_data['document']['tracking']['id'].lower()
    for key in keys:
        # Grab public PGP Key
        pub_key, _ = pgpy.PGPKey.from_blob(key["blob"])
        try:
            # Attempt to verify PGP signature against CSAF contents
            if bool(pub_key.verify(csaf.text, pgpy.PGPSignature.from_blob(signature))):
                verified = True
            else:
                continue
        except Exception as e:
            print(e)
            continue
    if verified: # Save signature file to mirror folder if verified
        with open(f"{feed_path}"+os.sep+f"{save_name}"+".json.asc", "w") as outfile:
            outfile.write(signature)
    else:
        # Save provider's signature file but log that it is unverified
        print(f"PGP signature verification failed for CSAF {link['href'].split('/')[-1]}\n")
        with open("logs.txt", "a") as f:
            f.write(f"PGP signature verification failed for CSAF {link['href'].split('/')[-1]}\n")
        with open(f"{feed_path}"+os.sep+f"{save_name}"+".json.asc", "w") as outfile:
            outfile.write(signature)
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
    # Load CSAF content
    csaf_data = json.loads(csaf.text)
    save_name = csaf_data['document']['tracking']['id'].lower()
    if link["href"].split(".")[-1] == "sha256": # SHA 256 Hash
        # Verify checksum
        if hashlib.sha256(csaf.text.encode('UTF-8')).hexdigest() == hash.split(" ")[0]:
            with open(f"{feed_path}"+os.sep+f"{save_name}"+".json.sha256", "w") as outfile:
                outfile.write(hash)
        else:
            # Log that the verification failed
            print(f"sha256 Hash match failed for CSAF {link['href'].split('/')[-1]}\n")
            with open("logs.txt", "a") as f:
                f.write(f"sha256 Hash match failed for CSAF {link['href'].split('/')[-1]}\n")
            # Save provider's hash
            with open(f"{feed_path}"+os.sep+f"{save_name}"+".json.sha256", "w") as outfile:
                outfile.write(hash)

    elif link["href"].split(".")[-1] == "sha512": # SHA 512 Hash
        # Verify checksum
        if hashlib.sha512(csaf.text.encode('UTF-8')).hexdigest() == hash.split(" ")[0]:
            with open(f"{feed_path}"+os.sep+f"{save_name}"+".json.sha512", "w") as outfile:
                outfile.write(hash)
        else:
            # Log that the verification failed
            print(f"sha512 Hash match failed for CSAF {link['href'].split('/')[-1]}\n")
            with open("logs.txt", "a") as f:
                f.write(f"sha512 Hash match failed for CSAF {link['href'].split('/')[-1]}\n")
            # Save provider's hash
            with open(f"{feed_path}"+os.sep+f"{save_name}"+".json.sha512", "w") as outfile:
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
    # Request the provider's Public PGP Keys
    provider_keys = json.loads(json.dumps(metadata["public_openpgp_keys"]))
    for j, key in enumerate(provider_keys):
        provider_keys[j]["blob"] = clean_key(requests.get(
            provider_keys[j]["url"], allow_redirects=True, verify=env.verify
        ).text)
        num_requests += 1 # Keep track of number of requests
    return provider_keys, num_requests
def get_csaf_updated_time(path:str):
    '''Get CSAF Updated Time
    Load the csaf.json file and return the time it was updated.

    Args:
        path: The path of the csaf to check.
    Returns:
        updated_time: A datetime string.
    '''
    if "-10-" in path:
        print("Here")
    try:
        # Grab timestamp of local copy of CSAF
        if os.path.isfile(path):
            with open(path, "r") as file:
                contents = file.read()
                csaf = json.loads(contents)
                updated_time = csaf.get("document", {}).get("tracking", {}).get("current_release_date", "1980-01-01T09:00:00.000Z")
        else:
            # If file isn't present, force a fresh download/update
            updated_time = "1980-01-01T09:00:00.000Z"
        if not os.path.isfile(path+".asc"):
            # If signature file is missing, force a fresh download/update
            updated_time = "1980-01-01T09:00:00.000Z"
        if not (os.path.isfile(path+".sha256") or os.path.exists(path+".sha512")):
            # If hash files are missing, force a fresh download/update
            updated_time = "1980-01-01T09:00:00.000Z"
    except:
        # If there are errors during parsing, force a fresh download/update
        updated_time = "1980-01-01T09:00:00.000Z"
    return updated_time
def updateROLIEURLs(rolie_copy:dict,feed_path:str):
    for i, entry in enumerate(rolie_copy["feed"]["entry"]):
        advid = entry['id'].lower()
        baseURL = feed_path+advid+'.json'
        # Update Content URL
        entry['content']['src']=baseURL
        # Update Links
        for j, link in enumerate(entry["link"]):
            # Update Self Link
            if link['rel']=='self' or link['href'].endswith('.json'):
                entry["link"][j]['href']=baseURL
            # Update Signature Link
            if link['rel']=='signature' or link['href'].endswith('.asc'):
                entry["link"][j]['href']=baseURL+'.asc'
            # Update Hash Links
            if link['rel']=='hash':
                if link['href'].endswith('.sha256'):
                    entry["link"][j]['href']=baseURL+'.sha256'
                if link['href'].endswith('.sha512'):
                    entry["link"][j]['href']=baseURL+'.sha512'
        # Save
        rolie_copy["feed"]["entry"][i]=entry
    return rolie_copy
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
    # Fetch the Provider's metadata
    pm_url = provider["metadata"]["url"]
    publisher_name = provider["metadata"]["publisher"]["name"]
    print(f"Fetching results for provider {publisher_name}")
    path_start = workingdir+os.sep+publisher_name
    pm_response = requests.get(
        pm_url, allow_redirects=True, verify=env.verify
    )
    print(f"{publisher_name} response: {pm_response}")

    # If the fetch was successful, continue parsing and retrieving needed files.
    if pm_response.status_code == 200:
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
                        # If rolie is successful, continue parsing and retrieving needed files.
                        if rolie_response.status_code == 200:
                            n_requests += 1
                            rolie = rolie_response.json()
                            if rolie:
                                print(f"Fetching results for ROLIE feed {rolie['feed']['id']}")
                                if not os.path.exists(path_start+os.sep+rolie["feed"]['id']): 
                                    os.makedirs(path_start+os.sep+rolie["feed"]['id'])
                                feed_path = path_start+os.sep+rolie["feed"]['id']
                                rolie_copy = json.loads(json.dumps(rolie)) # equivalent to deep copy
                                try:
                                    with open(f"{feed_path}"+os.sep+f"{rolie['feed']['id']}.json", "r") as old_file:
                                        old_rolie = json.loads(old_file.read())
                                except:
                                    old_rolie = {}

                                # Mirror URL for local copy of rolie feed
                                feed["url"] = f"{env.github_raw_path_start}/{env.github_owner}/{env.repo_name}/{env.branch}/{publisher_name}/{rolie['feed']['id']}/{rolie['feed']['id']}.json".replace(" ", "%20")

                                rolie_dict = {item['id']:item|{"update":False} for item in rolie.get("feed",{}).get("entry",[])}

                                # Cull already fetched csafs from fetch pool
                                if rolie.get("feed",{}).get("entry",[]):
                                    for entry in rolie["feed"]["entry"]:
                                        try:
                                            updated_time = parser.parse(rolie_dict.get(entry["id"],{}).get("updated",""))
                                            old_updated_time = parser.parse(get_csaf_updated_time(f"{feed_path}"+os.sep+f"{entry['id'].lower()}.json"))
                                        except Exception as e:
                                            print("Error here: "+str(e))
                                            continue
                                        # If timestamp is newer than what is stored locally, mark for update
                                        if updated_time > old_updated_time:
                                            rolie_dict[entry["id"]]["update"] = True
                                            if "-10-" in entry["id"]:
                                                print(rolie_dict[entry["id"]])

                                # fetch csafs for update
                                for advid, entry in rolie_dict.items():
                                    if entry["update"]:
                                        print(f"Fetching data for {entry['id']}")
                                        if "-10-" in advid:
                                            print("Here")
                                        try:
                                            # Fetch new/updated CSAFs
                                            csaf_response = requests.get(
                                                entry["content"]["src"], allow_redirects=True, verify=env.verify
                                            )
                                            n_requests += 1
                                            # If fetch is successful, fetch signatures and hashes
                                            if csaf_response.status_code == 200:
                                                try:
                                                    csaf = csaf_response.json()
                                                except:
                                                    break
                                                if csaf:
                                                    # Save CSAF
                                                    with open(f"{feed_path}"+os.sep+f"{entry['id'].lower()}.json", "w", encoding='utf-8') as outfile:
                                                        print(f"Saving {entry['id'].lower()}")
                                                        outfile.write(csaf_response.text)
                                                        # json.dump(csaf, outfile, indent=2, sort_keys=True, ensure_ascii=False)
                                                for link in entry["link"]:
                                                    if link["rel"] in ["hash", "signature"]:
                                                        link_response = requests.get(
                                                            link["href"], allow_redirects=True, verify=env.verify
                                                        )
                                                        # If fetch is successful, attempt to verify.
                                                        if link_response.status_code == 200:
                                                            n_requests += 1
                                                            # check sig
                                                            if link["rel"] == "signature":
                                                                verify_signature(link,provider_keys,link_response.text,csaf_response,feed_path)
                                                            # check hash
                                                            if link["rel"] == "hash":
                                                                verify_hash(link,link_response.text,csaf_response,feed_path)
                                                        else:
                                                            # Record issues in log file.
                                                            with open("logs.txt", "a") as f:
                                                                if link["rel"] == "signature":
                                                                    f.write(f"{publisher_name} CSAF Signature File request for {advid} FAILED with code [{link_response.status_code}] and message: {link_response.text}\n")
                                                                elif link["rel"] == "hash":
                                                                    f.write(f"{publisher_name} CSAF Hash File request for {advid} FAILED with code [{link_response.status_code}] and message: {link_response.text}\n")
                                            else:
                                                with open("logs.txt", "a") as f:
                                                    f.write(f"{publisher_name} CSAF request for {advid} FAILED with code [{csaf_response.status_code}] and message: {csaf_response.text}\n")
                                        except Exception as e:
                                            print(e)
                                            with open("logs.txt", "a") as f:
                                                f.write(f"{publisher_name} CSAF File Fetch requests for {advid} FAILED due to error: {str(e)}\n")
                                            continue

                                # update mirrored ROLIE
                                if rolie_copy.get("feed",{}).get("link",[]):
                                    rolie_copy["feed"]["link"] = [
                                        {
                                            "rel": "self",
                                            "href": f"{env.github_raw_path_start}/{env.github_owner}/{env.repo_name}/{env.branch}/{publisher_name}/{rolie_copy['feed']['id']}/{rolie_copy['feed']['id']}.json".replace(" ", "%20")
                                        },
                                    ]
                                if rolie_copy.get("feed",{}).get("updated",""):
                                    rolie_copy["feed"]["updated"] = now.strftime(env.dt_format)

                                mirrorURL = f"{env.github_raw_path_start}/{env.github_owner}/{env.repo_name}/{env.branch}/{publisher_name}".replace(" ", "%20")
                                updateROLIEURLs(rolie_copy,f"{mirrorURL}/{rolie_copy['feed']['id']}/")

                                with open(f"{feed_path}"+os.sep+f"{rolie_copy['feed']['id']}.json", "w") as outfile:
                                    print(f"Saving ROLIE {rolie_copy['feed']['id']}")
                                    json.dump(rolie_copy, outfile, indent=2, sort_keys=True)
                        else:
                            # A failed fetch is recorded in a log file.
                            with open("logs.txt", "a") as f:
                                f.write(f"{publisher_name} ROLIE request FAILED with code [{rolie_response.status_code}] and message: {rolie_response.text}\n")
                    except Exception as e:
                        print(e)
                        with open("logs.txt", "a") as f:
                            f.write(f"{publisher_name} ROLIE request FAILED due to error: {str(e)}\n")
                        continue
                        
        # Save the mirrored provider metadata
        if not os.path.exists(workingdir+os.sep+publisher_name): 
            os.makedirs(workingdir+os.sep+publisher_name)
        with open(f"{path_start}"+os.sep+"provider_metadata.json", "w") as outfile:
            print(f"Saving Provider Metadata for {publisher_name}")
            json.dump(provider_metadata, outfile, indent=2, sort_keys=True)
    else:
        # A failed fetch is recorded in a log file.
        with open("logs.txt", "a") as f:
            f.write(f"{publisher_name} Provider-Metadata request FAILED with code [{pm_response.status_code}] and message: {pm_response.text}\n")
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
    # Loop through each provider identified to mirror in the aggregator
    for i, provider in enumerate(aggregator["csaf_providers"]):
        # Aggregate the files of each provider and record number of requests
        n_requests = aggregate_provider_files(provider, n_requests)
        publisher_name = provider["metadata"]["publisher"]["name"]
        # Update the local mirror URL to the mirrored repo
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
    # Update and save the aggregator.json file
    with open(f"{env.aggregator_name}", "w") as outfile:
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
    # Load the local aggregator.json
    agg = load_aggregator()
    if agg:
        # Parse the contents of the aggregator
        parse_aggregator(agg)
        # Update links and timestamps of the aggregator
        update_aggregator(agg)

if __name__=="__main__":
    main()
