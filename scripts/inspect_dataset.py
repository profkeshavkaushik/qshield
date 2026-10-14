import sys

import pandas as pd

df = pd.read_csv(sys.argv[1], nrows=int(sys.argv[2]) if len(sys.argv) > 2 else None)
print("shape", df.shape)
print(df.dtypes.to_string())
print(df.head(5).to_string())
for c in df.columns:
    if df[c].nunique() <= 20:
        print("\n", c)
        print(df[c].value_counts(dropna=False).to_string())
