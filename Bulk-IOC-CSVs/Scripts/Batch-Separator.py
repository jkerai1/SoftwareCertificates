## Python Script developed by https://marshsecurity.org/ to allow for the splitting of a bulk CSV into 500-row batches.
## Currently, MDE import only allows a maximum of 500 rows on each import.

import pandas as pd
import os

# Input file path
file_path = '/path/to/your/MDE-IOCs.csv'

# Output directory
output_dir = '/tmp/IOCs/'

# Create the output directory if it doesn't exist
os.makedirs(output_dir, exist_ok=True)

# Load the CSV file
df = pd.read_csv(file_path)

# Define the maximum number of rows per batch (including header row)
max_rows_per_batch = 500

# Re-split the dataframe to ensure each batch has no more than 500 rows including the header
batches = []

# Adjust loop to limit each batch to 499 data rows plus 1 header row
for start_row in range(1, df.shape[0], max_rows_per_batch - 1):  # start from row 1, as row 0 is the header
    batch = df.iloc[start_row:start_row + max_rows_per_batch - 2]  # 499 data rows + 1 header = 500 rows
    batch_with_header = pd.concat([df.iloc[:1], batch], ignore_index=True)  # Include header in each batch
    batches.append(batch_with_header)

# Save each strict batch to a separate CSV file
for i, batch in enumerate(batches, start=1):
    batch_file_path = os.path.join(output_dir, f'MDE-IOCs_batch_{i}.csv')
    batch.to_csv(batch_file_path, index=False)

print(f"Batches have been saved to {output_dir}")
