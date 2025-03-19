import pandas as pd

# Load the CSV file
df = pd.read_csv('./CVSS_EPSS_Global_List/Global_List.csv')

# Define the order of CVSS versions for comparison
metric_order = ['cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31']

# Filter out rows with CVSS < 4 immediately
df_filtered = df[df['CVSS'] >= 4].copy()

# For each CVE, keep only the most recent metric version
df_filtered['metric_rank'] = df_filtered['CVSS version'].apply(lambda x: metric_order.index(x) if x in metric_order else -1)
df_latest_metrics = df_filtered.loc[df_filtered.groupby('CVE')['metric_rank'].idxmax()]

# Define black zone (CVSS >= 9 and EPSS >= 0.7)
blackzone_df = df_latest_metrics[(df_latest_metrics['CVSS'] >= 9) & (df_latest_metrics['EPSS'] >= 0.7)]

# Define red zone (4 <= CVSS < 9 and EPSS >= 0.9)
redzone_df = df_latest_metrics[(df_latest_metrics['CVSS'] < 9) & (df_latest_metrics['CVSS'] >= 4) & (df_latest_metrics['EPSS'] >= 0.9)]

# Drop the 'metric_rank' helper column before saving
blackzone_df = blackzone_df.drop(columns=['metric_rank'])
redzone_df = redzone_df.drop(columns=['metric_rank'])

# Save black zone and red zone CVEs to separate CSV files
blackzone_df.to_csv('blackzone_cves.csv', index=False)
redzone_df.to_csv('redzone_cves.csv', index=False)

# Output the filtered data
print("Black Zone CVEs:")
print(blackzone_df)
print("\nRed Zone CVEs:")
print(redzone_df)
