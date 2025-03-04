import requests
import time
import math
import re
import json
import statistics
from colorama import Fore

print("start")

def requeteCustom(requete):
    proxyRequestFailed = False

    while True:
        try:
            reponse = requests.get(requete, timeout=3600)

            if reponse.status_code > 399:
                if not proxyRequestFailed:
                    print(Fore.RED + r"Local request failed /!\ Switching to proxy request")
                    print(Fore.WHITE, end='')
                    data = requeteProxy(requete)  # Call proxy request

                    if data:  # Ensure proxy response is valid
                        print(Fore.GREEN + r"Proxy request success")
                        print(Fore.WHITE, end='')
                        return data  
                    else:
                        proxyRequestFailed = True  # Mark proxy as failed, retry local request
                        print(Fore.YELLOW + r"Proxy request failed, retrying local request...")
                        print(Fore.WHITE, end='')
                        time.sleep(3)
                        continue  # Retry local request

            else:
                print(Fore.GREEN + r"Local request success")
                print(Fore.WHITE, end='')
                return reponse.json()  # Return JSON if local request works

        except Exception as e:
            print(Fore.RED + r"Request failed: {e} /!\ Retrying in 5 seconds...")
            print(Fore.WHITE, end='')
            time.sleep(5)  # Delay before retrying
            continue  # Keep retrying indefinitely
    
def requeteProxy(requete):
    payload = { 'api_key': '252dd5baed7ee7f1ebb16aca7abe8aac', 'url': requete}
    response = requests.get('https://api.scraperapi.com/', params=payload)
    return jsonify(response)

def jsonify(data):
    res = None
    try:
        raw_text = data.text
        raw_text = re.sub(r'[\x00-\x1F\x7F]', '', raw_text)  # Remove control characters
        res = json.loads(raw_text)  # Manually parse JSON
    except Exception as e:
        print(f"JSON Decode Error: {e}")
        print(Fore.RED + "Switching to local request")
        print(Fore.WHITE, end='')
        return None
    return res

def incrementationDataNIST(offset, nbCVE):
    i = 0
    j = 1
    nbReq = math.ceil(nbCVE / offset[0])
    request_times = []  # Liste pour stocker les temps de chaque requête
    while i < nbCVE:
        if i + offset[0] < nbCVE:
            offset[1] = i
            print("Request n°", j, "of", str(nbReq))
            functime = funcDataNIST(offset)
            j = j + 1
            i = i + offset[0]
            request_times.append(functime)  # Ajouter le temps de la requête à la liste
            medianTimeOfRequest = statistics.median(request_times)  # Calculer la médiane
            remainingTime = medianTimeOfRequest * (nbReq - j)
            print("Current request:", round(functime, 2), "s")
            # Afficher le temps restant estimé basé sur la médiane
            minutes = round(remainingTime // 60)
            seconds = round(remainingTime % 60)
            print(Fore.BLUE + "Estimated remaining time: ", minutes, "m", seconds, "s")
            print(Fore.WHITE, end='')
        else:
            offset[0] = nbCVE - i  # Nombre de résultats que l'on veut pour la dernière requête
            offset[1] = 1  # Index final
            print("Request n°", j, "of", str(nbReq))
            functime = funcDataNIST(offset)
            j = j + 1
            i = i + offset[0]

def funcDataNIST(offset):
    start = time.time()
    requeteCVE = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=' + str(offset[0]) + '&startIndex=' + str(offset[1])
    data=requeteCustom(requeteCVE)
    CVEtableUnit = None

    with open("CVE_CVSS_Results.txt", "a") as file:
        for i in range(len(data["vulnerabilities"])):
            result = data["vulnerabilities"][i]["cve"]["metrics"]
            paramCVSS = len(result)
            if paramCVSS != 0:
                cvssDict = {}
                for metrics in result:
                    if metrics == "cvssMetricV2":
                        cvssDict[metrics] = (result[metrics][0]["baseSeverity"]), (result[metrics][0]["cvssData"]["baseScore"])
                    if metrics == "cvssMetricV30" or metrics == "cvssMetricV31":
                        cvssDict[metrics] = (result[metrics][0]["cvssData"]["baseSeverity"]), (result[metrics][0]["cvssData"]["baseScore"])

                # Get the best metrics
                cvssMetric, cvssBaseseverity, cvssBaseScore = compareMetrics(cvssDict)
                
                # If a valid severity is found, write it to the file
                if cvssBaseseverity != 0:
                    cve = data["vulnerabilities"][i]["cve"]["id"]
                    CVEtableUnit = { 'CVE': cve, 'CVSS': cvssMetric, 'CVSS version': cvssBaseScore }
                    CVE_CVSS_EPSS_table.append(CVEtableUnit)
                    
                    # Write the information to the file at the end (append mode)
                    file.write(f"CVE: {cve}, CVSS Metric: {cvssMetric}, CVSS Version: {cvssBaseScore}\n")

    end = time.time()
    return (end - start)

def compareMetrics(cvssDict): #Fonction qui permet de récupérer les CVSSMetrics les plus récentes Ou de gérer le
    if len(cvssDict) == 1:
        if cvssDict["cvssMetricV2"][0] != "LOW":
            return "cvssMetricV2", cvssDict["cvssMetricV2"][0], cvssDict["cvssMetricV2"][1]
    if len(cvssDict) > 1:
        cvssMetricToCompare = "cvssMetricV31"
        if "cvssMetricV30" in cvssDict and "cvssMetricV31" not in cvssDict:
            cvssMetricToCompare = "cvssMetricV30"
        if cvssDict[cvssMetricToCompare][0] == "LOW" and cvssDict["cvssMetricV2"][0] == "HIGH":
            return "cvssMetricV2", cvssDict["cvssMetricV2"][0], cvssDict["cvssMetricV2"][1]
        if cvssDict[cvssMetricToCompare][0] != "LOW":
            return cvssMetricToCompare, cvssDict[cvssMetricToCompare][0], cvssDict[cvssMetricToCompare][1]
        else:
            return 0,0,0
    else:
        return 0,0,0

def funcNbCVEglobal():
    requete = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0"
    reponse = requests.get(requete, timeout=3600)
    data = reponse.json()
    nbCVEglobal = data["totalResults"]
    return nbCVEglobal


nbCVEglobal = funcNbCVEglobal()
CVE_CVSS_EPSS_table = []
offsetGlobal = [2000,0] 
print("Ready to launch", (math.ceil(nbCVEglobal/offsetGlobal[0])), "requests to NIST's API")
incrementationDataNIST (offset = [2000,0], nbCVE = nbCVEglobal)
