import pandas as pd
from openpyxl import Workbook

csv_file_path = './CVSS_EPSS_Global_List/Black_Zone.csv'  # Replace with your CSV file path
df = pd.read_csv(csv_file_path)

wb = Workbook()
ws = wb.active
ws.title = "CVE Data"

ws.append(df.columns.tolist())

for row in df.itertuples(index=False):
    ws.append(row)

excel_path = "./CVSS_EPSS_Global_List_Auto_Excel/Black_Zone.xlsx"
wb.save(excel_path)