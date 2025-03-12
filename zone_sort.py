import csv

globalBlackList = []
globalRedList = []

def makeBlackRedList():
    with open('./CVSS_EPSS_Global_List/Global_List.csv', newline='') as f:
        reader = csv.reader(f)
        data = list(reader)

    for i in range(1, len(data)):
        try:
            if float(data[i][1]) >= 9 and float(data[i][3]) >= 0.7:
                final = { 'CVE': data[i][0], 'CVSS version': data[i][1], 'CVSS': data[i][2],
                 'EPSS':data[i][3],'EPSS percentile':data[i][4] }
                globalBlackList.append(final)
            if i == len(data):
                break
            else:
                continue
        except:
            continue

    for i in range(1, len(data)):
        try:
            if float(data[i][1]) >= 4 and float(data[i][3]) >= 0.9:
                final = { 'CVE': data[i][0], 'CVSS version': data[i][1], 'CVSS': data[i][2],
                 'EPSS':data[i][3],'EPSS percentile':data[i][4] }
                if final not in globalBlackList :
                    globalRedList.append(final)
            if i == len(data):
                break
            else:
                continue
        except:
            continue

    with open("./CVSS_EPSS_Global_List/Black_Zone.csv", mode="w", newline='') as csvfileFinal:
        headers= ['CVE', 'CVSS version', 'CVSS', 'EPSS', 'EPSS percentile']
        writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
        writer.writeheader()
        writer.writerows(globalBlackList)

    with open("./CVSS_EPSS_Global_List/Red_Zone.csv", mode="w", newline='') as csvfileFinal:
        headers= ['CVE', 'CVSS version', 'CVSS', 'EPSS', 'EPSS percentile']
        writer = csv.DictWriter(csvfileFinal, fieldnames=headers)
        writer.writeheader()
        writer.writerows(globalRedList)

makeBlackRedList()
