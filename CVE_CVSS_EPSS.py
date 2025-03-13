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

    requeteCVE = 'https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=' + str(offset[0]) + '&startIndex=' + str(offset[1])
    reponse = requeteCustom(requeteCVE)
    data=reponse.json()
    CVEtableUnit = None
    listcve = ""

    for i in range(len(data["vulnerabilities"])):
        result = data["vulnerabilities"][i]["cve"]["metrics"]
        paramCVSS = len(result)
        if paramCVSS != 0:
            for metrics in result:
                cve = data["vulnerabilities"][i]["cve"]["id"]
                listcve += str(cve + ",")
                cvss = result[metrics][0]["cvssData"]["baseScore"]
                CVEtableUnit = { 'CVE': cve, 'CVSS version': metrics, 'CVSS': cvss }
                CVE_CVSS_table.append(CVEtableUnit)
                if len(CVE_CVSS_table) == 100:
                    requeteEPSS(listcve)
                    listcve = ""

    requeteEPSS(listcve)
    listcve = ""

def funcNbCVEglobal():
    requete = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0"
    reponse = requests.get(requete, timeout=3600)
    data = reponse.json()
    nbCVEglobal = data["totalResults"]
    return nbCVEglobal


#nbCVEglobal = funcNbCVEglobal()
nbCVEglobal = 10000
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
