import requests
import time
import math
import csv
import re
import json
import statistics
from colorama import Fore

def constructionRequeteEPSS(debut,fin):
    ListeCVE = []
    for n in range(fin-debut):
        ListeCVE.append(CVE_CVSS_EPSS_table[debut+n]['CVE'])
    while True:
        try:
            requeteEPSS = "https://api.first.org/data/v1/epss?cve="+",".join(ListeCVE)
            break
        except:
            time.sleep(10)
            continue
    return requeteEPSS

def remplissageEPSS():
    i=0
    while i < len(CVE_CVSS_EPSS_table):
        if i+80 < len(CVE_CVSS_EPSS_table):
            reponseEPSS = requests.get(constructionRequeteEPSS(debut=i, fin=i+80))
            print("récupération ds EPPS jusqu'à la CVE", str(i+80))
            donneesGlobales = reponseEPSS.json()
            EPSStable = donneesGlobales.get("data")
            
            for o in range(len(EPSStable)):
                for p in range(len(EPSStable)):
                    if CVE_CVSS_EPSS_table[i+o]['CVE'] == EPSStable[p]['cve']:
                        CVE_CVSS_EPSS_table[i+o]['EPSS'] = EPSStable[p]['epss']
                        CVE_CVSS_EPSS_table[i+o]['EPSS percentile'] = EPSStable[p]['percentile']
                        break
            i += 80

        else: 
            reponseEPSS = requests.get(constructionRequeteEPSS(debut=i,fin=len(CVE_CVSS_EPSS_table)))
            print("récupératin des EPSS jusqu'à la CVE", str(len(CVE_CVSS_EPSS_table)))
            donneesGlobales = reponseEPSS.json()
            EPSStable = donneesGlobales.get("data")

            for o in range(len(EPSStable)):
                for p in range(len(EPSStable)):
                    if CVE_CVSS_EPSS_table[i+o]['CVE'] == EPSStable[p]['cve']:
                        CVE_CVSS_EPSS_table[i+o]['EPSS'] = EPSStable[p]['epss']
                        CVE_CVSS_EPSS_table[i+o]['EPSS percentile'] = EPSStable[p]['percentile']
                        break
            i = len(CVE_CVSS_EPSS_table)


def estimateTotalTime(nbReq):
    print("Estimating total running time...")
    requestTimes = []
    for i in range(4):
        start = time.time()
        requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&startIndex=0' , timeout=3600)
        end = time.time()
        requestTimes.append(end - start)
    medianTimeOfRequest = statistics.median(requestTimes)
    if medianTimeOfRequest<6.1:
        remainingTime = 6.1 * nbReq
    else:
        remainingTime = medianTimeOfRequest * nbReq
    print(Fore.BLUE + "Estimated total running time: ", round(remainingTime // 60), "m", round(remainingTime % 60), "s")
    print(Fore.WHITE, end='')
    print("Preparing to launch", nbReq, "requests to NIST's API")
    time.sleep(30)

def requeteCustom(requete):
    while True:
        try:
            start = time.time()
            reponse = requests.get(requete, timeout=3600)
            end = time.time()
            reponseTime = end - start
            if reponse.status_code > 399:
                    print(Fore.RED + r"Request failed ! Waiting 30 seconds due to NIST API restriction")
                    print(Fore.WHITE, end='')
                    time.sleep(30)
                    continue
            if reponseTime < 6.1:
                print(Fore.GREEN+ r"Request response time :", round(reponseTime, 2), "s", end="")
                print(Fore.YELLOW + r" Request response time too fast! Waiting due to NIST API restriction")
                print(Fore.WHITE, end='')
                time.sleep(6.1-reponseTime)
                reponseTime = 6.1
                break
            if reponseTime > 12:
                print(Fore.GREEN+ r"Request response time :", round(reponseTime, 2), "s", end="")
                print(Fore.CYAN + r" Request response time too slow! Turned off limitation")
                print(Fore.WHITE, end='')
                break

        except:
            print(Fore.RED + r"Request failed ! Waiting for connection...")
            print(Fore.WHITE, end='')
            time.sleep(30)  # Delay before retrying
            continue  # Keep retrying indefinitely
    return reponse

def incrementationDataNIST(offset, nbCVE):
    i = 0
    j = 1
    nbReq = math.ceil(nbCVE / offset[0])
    while i < nbCVE:
        if i + offset[0] < nbCVE:
            offset[1] = i
            print("Request n°", j, "of", str(nbReq))
            funcDataNIST(offset)
            j = j + 1
            i = i + offset[0]
        else:
            offset[0] = nbCVE - i  # Nombre de résultats que l'on veut pour la dernière requête
            offset[1] = 1  # Index final
            print("Request n°", j, "of", str(nbReq))
            funcDataNIST(offset)
            j = j + 1
            i = i + offset[0]
            

def funcDataNIST(offset):
    requeteCVE = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=' + str(offset[0]) + '&startIndex=' + str(offset[1])
    reponse = requeteCustom(requeteCVE)
    data=reponse.json()
    CVEtableUnit = None

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


            cvssMetric, cvssBaseseverity, cvssBaseScore = compareMetrics(cvssDict)
                
            if cvssBaseseverity != 0:
                cve = data["vulnerabilities"][i]["cve"]["id"]
                CVEtableUnit = { 'CVE': cve, 'CVSS version': cvssMetric, 'CVSS': cvssBaseScore }
                CVE_CVSS_EPSS_table.append(CVEtableUnit)
                    

def compareMetrics(cvssDict):
    # Ordre de priorité des CVSS (du plus récent au plus ancien)
    metric_order = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    
    # Vérifier s'il y a au moins une métrique non-LOW
    non_low_metrics = {metric: cvssDict[metric] for metric in metric_order if metric in cvssDict and cvssDict[metric][0] != "LOW"}

    if not non_low_metrics:
        return 0, 0, 0  # Si toutes les métriques sont LOW, on renvoie (0,0,0)

    # Prendre la plus récente parmi celles qui ne sont pas LOW
    for metric in metric_order:
        if metric in non_low_metrics:
            return metric, non_low_metrics[metric][0], non_low_metrics[metric][1]

    return 0, 0, 0  # Par sécurité (même si normalement jamais atteint)


def funcNbCVEglobal():
    requete = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0"
    reponse = requests.get(requete, timeout=3600)
    data = reponse.json()
    nbCVEglobal = data["totalResults"]
    return nbCVEglobal


#nbCVEglobal = funcNbCVEglobal()
nbCVEglobal = 1000
CVE_CVSS_EPSS_table = []
GlobalBlackList = []
offsetGlobal = [2000,0] 
nbReq = math.ceil(nbCVEglobal/ offsetGlobal[0])

#estimateTotalTime(nbReq)
incrementationDataNIST (offset = [2000,0], nbCVE = nbCVEglobal)

print("Extracting EPSS data")
remplissageEPSS()

with open("./CVSS_EPSS_Global_List/GlobalList.csv", mode="w", newline='') as csvfileFinal:
    headers= ['CVE', 'CVSS', 'CVSS version', 'EPSS', 'EPSS percentile']
    writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
    writer.writeheader()
    writer.writerows(CVE_CVSS_EPSS_table)

print("Swag")
