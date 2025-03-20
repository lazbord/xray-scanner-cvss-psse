import pandas as pd
from openpyxl import Workbook
import datetime

# Load the CSV file
csv_file_path = './CVSS_EPSS_Global_List/Global_List.csv'  # Replace with your CSV file path
df = pd.read_csv(csv_file_path)

# Filter out rows with 'CVSS version' as 'cvssMetricV40'
df = df[df['CVSS version'] != 'cvssMetricV40']

# Filter out rows with CVSS score less than 4
df = df[df['CVSS'] >= 4]

# Create a new workbook and grab the active worksheet
wb = Workbook()
ws = wb.active
ws.title = "CVE Data"

# Write the header row
ws.append(df.columns.tolist())

# Write data rows
for row in df.itertuples(index=False):
    ws.append(row)

# Adjust column widths for readability
for column_cells in ws.columns:
    max_length = max(
        len(str(cell.value)) if cell.value is not None else 0
        for cell in column_cells
    )
    adjusted_width = max_length + 2
    ws.column_dimensions[column_cells[0].column_letter].width = adjusted_width

# Optionally, add a timestamp in the footer or another cell
ws['A1'] = f"CVE"

# Save the workbook
excel_path = "CVE_Report_Filtered.xlsx"
wb.save(excel_path)

print(f"Excel workbook '{excel_path}' created successfully.")
