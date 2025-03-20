import pandas as pd

df = pd.read_csv('./CVSS_EPSS_Global_List/Global_List.csv')

metric_order = ['cvssMetricV2', 'cvssMetricV30', 'cvssMetricV31']

df_filtered = df[df['CVSS'] >= 4].copy()

df_filtered['metric_rank'] = df_filtered['CVSS version'].apply(lambda x: metric_order.index(x) if x in metric_order else -1)
df_latest_metrics = df_filtered.loc[df_filtered.groupby('CVE')['metric_rank'].idxmax()]

blackzone_df = df_latest_metrics[(df_latest_metrics['CVSS'] >= 9) & (df_latest_metrics['EPSS'] >= 0.7)]

redzone_df = df_latest_metrics[(df_latest_metrics['CVSS'] < 9) & (df_latest_metrics['CVSS'] >= 4) & (df_latest_metrics['EPSS'] >= 0.9)]

blackzone_df = blackzone_df.drop(columns=['metric_rank'])
redzone_df = redzone_df.drop(columns=['metric_rank'])

blackzone_df.to_csv('./CVSS_EPSS_Global_List_Auto_Excel/Black_Zone.csv', index=False)
redzone_df.to_csv('./CVSS_EPSS_Global_List_Auto_Excel/Red_Zone.csv', index=False)
