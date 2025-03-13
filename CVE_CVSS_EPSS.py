import requests
import time
import math
import statistics
import csv
from colorama import Fore


def requeteCustom(requete):
    while True:
        try:
            start = time.time()
            reponse = requests.get(requete, timeout=3600)
            end = time.time()
            reponseTime = end - start
            if reponse.status_code > 399:
                    print(Fore.RED + r" Request failed ! Waiting 10 seconds due to NIST API restriction")
                    print(Fore.WHITE, end='')
                    time.sleep(10)
                    continue
            if reponseTime < 6.1:
                print("TOO FAST")
                time.sleep(6.1 - reponseTime)
                reponseTime = 6.1
                break
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

    for i in range(len(data["vulnerabilities"])):
        result = data["vulnerabilities"][i]["cve"]["metrics"]
        paramCVSS = len(result)
        if paramCVSS != 0:
            cvssDict = {}
            for metrics in result:
                cve = data["vulnerabilities"][i]["cve"]["id"]
                cvss = result[metrics][0]["cvssData"]["baseScore"]
                CVEtableUnit = { 'CVE': cve, 'CVSS version': metrics, 'CVSS': cvss }
                CVE_CVSS_table.append(CVEtableUnit)

def funcNbCVEglobal():
    requete = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&startIndex=0"
    reponse = requests.get(requete, timeout=3600)
    data = reponse.json()
    nbCVEglobal = data["totalResults"]
    return nbCVEglobal


nbCVEglobal = funcNbCVEglobal()
CVE_CVSS_EPSS_table = []
CVE_CVSS_table = []
offsetGlobal = [2000,0] 
nbReq = math.ceil(nbCVEglobal/ offsetGlobal[0])

incrementationDataNIST(offset = [2000,0], nbCVE = nbCVEglobal)

with open("./CVSS_EPSS_Global_List/Global_List.csv", mode="w", newline='') as csvfileFinal:
    headers= ['CVE', 'CVSS version', 'CVSS']
    writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
    writer.writeheader()
    writer.writerows(CVE_CVSS_table)
