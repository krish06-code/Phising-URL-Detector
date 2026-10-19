import sys
import os
import pandas as pd
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml"))
from feature_extractor import extract_features

urls = ["https://www.google.com", "https://paypal.com", "http://www.evil.tracking.xyz"]
for url in urls:
    f = extract_features(url)
    print("URL:", url)
    for k in ["NoOfSubDomain", "DomainLength", "URLLength", "IsHTTPS", "TLDLength"]:
        print("  " + k + ":", f[k])
    print()

df = pd.read_csv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "PhiUSIIL_Phishing_URL_Dataset.csv"), nrows=500)
legit = df[df["label"]==1][["URL","NoOfSubDomain","DomainLength","URLLength"]].head(5)
phish = df[df["label"]==0][["URL","NoOfSubDomain","DomainLength","URLLength"]].head(5)
print("Dataset LEGITIMATE samples:")
print(legit.to_string())
print()
print("Dataset PHISHING samples:")
print(phish.to_string())
