"""
Inspect the exact URL values and lengths stored in the dataset.
"""
import pandas as pd

df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv", nrows=5)
for _, row in df.iterrows():
    url = row["URL"]
    stored_len = row["URLLength"]
    actual_len = len(url)
    stored_letters = row["NoOfLettersInURL"]
    actual_letters = sum(1 for c in url if c.isalpha())
    print(f"URL repr: {repr(url)}")
    print(f"  stored URLLength={stored_len}, actual len={actual_len}")
    print(f"  stored NoOfLettersInURL={stored_letters}, actual letters={actual_letters}")
    print(f"  letters in full URL: {[c for c in url if c.isalpha()]}")
    print()
