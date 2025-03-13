import requests
import time
import math
import statistics
import csv
from colorama import Fore

def requeteEPSS(CVE):
    response = requests.get("https://api.first.org/data/v1/epss?cve=" + CVE)
    donneesGlobales = response.json()
    EPSStable = donneesGlobales.get("data")

    for i in range(len(CVE_CVSS_table)):
        for j in range(len(EPSStable)):
            if CVE_CVSS_table[i]['CVE'] == EPSStable[j]['cve']:
                CVE_CVSS_EPSS_table.append({ 'CVE': CVE_CVSS_table[i]['CVE'], 'CVSS version': CVE_CVSS_table[i]['CVSS version'], 'CVSS': CVE_CVSS_table[i]['CVSS'], 
                    "EPSS": EPSStable[j]['epss'],"EPSS percentile" : EPSStable[j]['percentile']})
                break
        
    CVE_CVSS_table.clear()


def zoneSort():
    BlackZone = []
    RedZone = []

    for i in range(len(CVE_CVSS_EPSS_table)):
        if (CVE_CVSS_EPSS_table[i][2]) >= 9 and (CVE_CVSS_EPSS_table[i][3]) >= 0.7:
            final = { 'CVE': CVE_CVSS_EPSS_table[i][0], 'CVSS version': CVE_CVSS_EPSS_table[i][1], 'CVSS': CVE_CVSS_EPSS_table[i][2],
                'EPSS':CVE_CVSS_EPSS_table[i][3],'EPSS percentile':CVE_CVSS_EPSS_table[i][4] }
            BlackZone.append(final)

    for i in range(1, len(CVE_CVSS_EPSS_table)):
        if float(CVE_CVSS_EPSS_table[i][2]) >= 4 and float(CVE_CVSS_EPSS_table[i][3]) >= 0.9:
            final = { 'CVE': CVE_CVSS_EPSS_table[i][0], 'CVSS version': CVE_CVSS_EPSS_table[i][1], 'CVSS': CVE_CVSS_EPSS_table[i][2],
                'EPSS':CVE_CVSS_EPSS_table[i][3],'EPSS percentile':CVE_CVSS_EPSS_table[i][4] }
            if final not in BlackZone :
                RedZone.append(final)

    with open("./CVSS_EPSS_Global_List/Black_Zone.csv", mode="w", newline='') as csvfileFinal:
        headers= ['CVE', 'CVSS version', 'CVSS', 'EPSS', 'EPSS percentile']
        writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
        writer.writeheader()
        writer.writerows(BlackZone)

    with open("./CVSS_EPSS_Global_List/Red_Zone.csv", mode="w", newline='') as csvfileFinal:
        headers= ['CVE', 'CVSS version', 'CVSS', 'EPSS', 'EPSS percentile']
        writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
        writer.writeheader()
        writer.writerows(RedZone)


def requeteCustom(requete):
    while True:
        try:
            reponse = requests.get(requete, timeout=3600)
            if reponse.status_code > 399:
                    print(Fore.RED + r" Request failed ! Waiting 10 seconds due to NIST API restriction")
                    print(Fore.WHITE, end='')
                    time.sleep(10)
                    continue
            else :
                break

        except:
            print(Fore.RED + r" Request failed ! Waiting for connection...")
            print(Fore.WHITE, end='')
            time.sleep(10)  # Delay before retrying
            continue  # Keep retrying indefinitely
    return reponse

def incrementationDataNIST(offset, nbCVE):
    i = 0
    j = 1
    nbReq = math.ceil(nbCVE / offset[0])
    while i < nbCVE:
        if i + offset[0] < nbCVE:
            offset[1] = i
            print("Request n°", j, "of", str(nbReq), end='')
            funcDataNIST(offset)
            j = j + 1
            i = i + offset[0]
        else:
            offset[0] = nbCVE - i  # Nombre de résultats que l'on veut pour la dernière requête
            offset[1] = 1  # Index final
            print("Request n°", j, "of", str(nbReq), end='')
            funcDataNIST(offset)
            j = j + 1
            i = i + offset[0]

def funcDataNIST(offset):
    start = time.time()
    listcve = ""
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
                cvssDict[metrics] = (result[metrics][0]["cvssData"]["baseScore"])

            cvssMetric, cvssBaseScore = compareMetrics(cvssDict)
                
            if cvssBaseScore != 0:
                cve = data["vulnerabilities"][i]["cve"]["id"]
                listcve += str(cve + ",")
                CVEtableUnit = { 'CVE': cve, 'CVSS version': cvssMetric, 'CVSS': cvssBaseScore }
                CVE_CVSS_table.append(CVEtableUnit)
                if len(CVE_CVSS_table) == 100:
                    requeteEPSS(listcve)
                    listcve = ""

    requeteEPSS(listcve)
    listcve = ""

    end = time.time()

    totaltime = (end - start)
    if totaltime < 6.1 :
        print(Fore.GREEN + r" Response time too short ",end='')
        print(Fore.WHITE, end='')
        time.sleep(6.1-totaltime)
    print("Total time elapsed", round((end - start),2),"s")

def compareMetrics(cvssDict):
    metric_order = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]

    selected_metric = None
    selected_score = 0

    for metric in metric_order:
        if metric in cvssDict:
            score = cvssDict[metric]

            if score < 4:
                continue

            if selected_metric is None or score > selected_score:
                selected_metric = metric
                selected_score = score

    if selected_metric is None:
        return 0,0
    
    return selected_metric, selected_score

def funcNbCVEglobal():
    requete = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0"
    reponse = requests.get(requete, timeout=3600)
    data = reponse.json()
    nbCVEglobal = data["totalResults"]
    return nbCVEglobal

nbCVEglobal = funcNbCVEglobal()
nbCVEglobal = 4001
CVE_CVSS_EPSS_table = []
CVE_CVSS_table = []
offsetGlobal = [2000,0] 
nbReq = math.ceil(nbCVEglobal/ offsetGlobal[0])

incrementationDataNIST(offset = [2000,0], nbCVE = nbCVEglobal)

with open("./CVSS_EPSS_Global_List/Global_List.csv", mode="w", newline='') as csvfileFinal:
    headers= ['CVE', 'CVSS version', 'CVSS', 'EPSS', 'EPSS percentile']
    writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
    writer.writeheader()
    writer.writerows(CVE_CVSS_EPSS_table)

zoneSort()