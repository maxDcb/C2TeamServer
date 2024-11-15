import requests
import json

BatcaveUrl = "https://github.com/exploration-batcave/batcave"

def getLatestRelease(githubUrl: str):
    owner = githubUrl.split("/")[3]
    repo = githubUrl.split("/")[4]
    return f"https://api.github.com/repos/{owner}/{repo}/releases/latest"


def fetchBatcaveJson():
    urlToFetch = getLatestRelease(BatcaveUrl)
    response = requests.get(urlToFetch)

    res = {}
    if response.status_code == 200:
        release_data = response.json()
        for asset in release_data.get("assets", []):
            if asset["name"].endswith(".json"):
                json_url = asset["browser_download_url"]
                print(json_url)
            
                json_response = requests.get(json_url)
                if json_response.status_code == 200:
                    json_data = json_response.json()
                    print(json_data)
                    return json_data
    print("Failed to Fetch Json")
    return {}

def searchForGadget(name: str):
    batcaveJson = fetchBatcaveJson()
    gadgetList = batcaveJson.get("gadgets", [])
    bundleList = batcaveJson.get("bundles", [])

    # Searching in Gadgets
    resGadget = []
    for gadget in gadgetList:
        if name.lower() in gadget.get("name", "").lower():
            resGadget.append(gadget.get("name"))

    # Searching in Bundles
    resBundle = []
    for bundle in bundleList:
        bundleName = next(iter(bundle))
        if name.lower() in bundleName.lower():
            resBundle.append(bundleName)

    result = ""
    if resGadget != []:
        result += "Found the Following BatGadget that may correspond:\n"
        for gadget in resGadget:
            result += f"  - Batcave install {gadget}\n"
    else:
        result += "No BatGadget Found ... It is ok, Don't be the mask\n"

    result += "\n"

    if resBundle != []:
        result += "Found the Following BatBundle that may correspond:\n"
        for gadget in resBundle:
            result += f"  - Batcave bundleInstall {gadget}\n"
    else:
        result += "No Bundles Found ... It is ok, Don't be the mask\n"
    return result



fetchBatcaveJson()


