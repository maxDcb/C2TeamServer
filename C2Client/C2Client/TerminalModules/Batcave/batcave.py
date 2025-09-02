from pathlib import Path
import requests
import json
import zipfile
import os

BatcaveUrl = "https://github.com/exploration-batcave/batcave"
BatcaveCache = os.path.join(Path(__file__).parent, 'cache') 

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
            
                json_response = requests.get(json_url)
                if json_response.status_code == 200:
                    json_data = json_response.json()
                    return json_data
    print("Failed to Fetch Json")
    return {}


def searchTheBatcave(name: str):
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
            resBundle.append(bundle)

    result = ""
    if resGadget != []:
        result += "Found the Following BatGadget that may correspond:\n"
        for gadget in resGadget:
            result += f"  - Batcave Install {gadget}\n"
    else:
        result += "No BatGadget Found ... It is ok, Don't be the mask\n"

    result += "\n"

    if resBundle != []:
        result += "Found the Following BatBundle that may correspond:\n"
        for bundle in resBundle:
            bundleName = next(iter(bundle))
            result += f"  - Batcave BundleInstall {bundleName} - - - > {bundle.get(bundleName)}\n"
    else:
        result += "No Bundles Found ... It is ok, Don't be the mask\n"
    return result


def saveZipInLocalCache(releaseURL: str):
    os.makedirs(BatcaveCache, exist_ok=True)
    response = requests.get(releaseURL)
    if response.status_code == 200:
        release_data = response.json()
        for asset in release_data.get("assets", []):
            if asset["name"].endswith(".zip"):  # Assuming the file is a ZIP
                zip_url = asset["browser_download_url"]
                zip_file_path = os.path.join(BatcaveCache, asset["name"])
                with requests.get(zip_url, stream=True) as r:
                    r.raise_for_status()
                    with open(zip_file_path, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
                return zip_file_path
    return ""


def unzipFile(zipfilepath: str):
    extractDir = os.path.join(BatcaveCache, "extracted")
    os.makedirs(extractDir, exist_ok=True)
    with zipfile.ZipFile(zipfilepath, "r") as zip_ref:
        zip_ref.extractall(extractDir)
        extractedFiles = zip_ref.namelist()

    if len(extractedFiles) != 1:
        print("Weird, we should have 1 file per zip but got this " + str(extractedFiles))
        print("Will take the first and continue with the life, but check the logs")
    return os.path.join(extractDir, extractedFiles[0])


def downloadBatGadget(name: str):
    batcaveJson = fetchBatcaveJson()
    gadgetList = batcaveJson.get("gadgets", [])
    for gadget in gadgetList:
        if name.lower() == gadget.get("name", "").lower():
            batUrl = gadget.get("url")
            batReleaseUrl = getLatestRelease(batUrl)
            zipPath = saveZipInLocalCache(batReleaseUrl)
            unzipedFile = unzipFile(zipPath)
            return unzipedFile
    return ""


def downloadBatBundle(name: str):
    batcaveJson = fetchBatcaveJson()
    bundleList = batcaveJson.get("bundles", [])
    for bundle in bundleList:
        bundleName = next(iter(bundle))
        res = []
        if name.lower() == bundleName.lower():
            for gadgetName in bundle.get(bundleName):
                batGadgetPath = downloadBatGadget(gadgetName)
                if  batGadgetPath != "":
                    res.append(batGadgetPath)
            return res
    return []
