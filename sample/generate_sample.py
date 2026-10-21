"""Generate a fake vulnerability CSV for testing: python sample/generate_sample.py [rows]"""
import csv, random, sys
from datetime import datetime, timedelta
from pathlib import Path

HEADERS = ["CSB ID","Alert ID","Last Scan","Severity","Alert Opened","Days Open","SLO Date","Exception","Exception RITM",
  "Account ID","Account Name","Provider","Enviroment","Asset ID","Asset Type","CVE ID","CVE Description","CVE Link",
  "Cluster","Namespace","Instance","Repository","Registry","Image","Image Tag","Image Created","Package",
  "Current Version","Recommended Version","Package Path","Layer ID","Layer Instruction","OS","OS Version",
  "OS End of Life","Participating Firm","Country","CMS","Function","App ID","App Service","Business Service",
  "Department","Service Line","Data Classification","Data Qualification"]
SLO_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}
APPS = [("APP-1001","Payments API","Payments","Finance Tech"),("APP-1002","Customer Portal","Digital Channels","Digital"),
        ("APP-1003","HR Self Service","People Platform","HR Tech"),("APP-1004","Data Lake Ingest","Analytics","Data Office"),
        ("APP-1005","Audit Workpapers","Assurance","Audit Tech"),("APP-1006","Tax Engine","Tax","Tax Tech"),
        ("APP-1007","Identity Broker","IAM","Security")]
PKGS = [("openssl","3.0.7","3.0.13"),("glibc","2.31","2.31-13+deb11u7"),("log4j-core","2.14.1","2.17.1"),
        ("libcurl","7.74.0","8.4.0"),("zlib","1.2.11","1.2.13"),("jackson-databind","2.12.1","2.15.2"),
        ("requests","2.25.1","2.31.0"),("lodash","4.17.15","4.17.21"),("busybox","1.33.1","1.36.1")]

def main(n=500):
    rnd, now = random.Random(42), datetime(2026, 10, 20, 6, 0)
    out = Path(__file__).with_name("vulnerabilities_sample.csv")
    with out.open("w", newline="") as f:
        w = csv.writer(f); w.writerow(HEADERS)
        for i in range(n):
            app = rnd.choice(APPS); sev = rnd.choices(list(SLO_DAYS), [1, 3, 5, 3])[0]
            pkg = rnd.choice(PKGS); opened = now - timedelta(days=rnd.randint(1, 200))
            cve = f"CVE-202{rnd.randint(1,5)}-{rnd.randint(1000,49999)}"; img = f"{app[1].lower().replace(' ','-')}"
            exc = "Yes" if rnd.random() < .05 else "No"
            w.writerow([f"CSB-{rnd.randint(100,999)}", f"ALRT-{i:06d}", now.isoformat(), sev, opened.isoformat(),
              (now-opened).days, (opened+timedelta(days=SLO_DAYS[sev])).date(), exc, f"RITM{rnd.randint(1000000,9999999)}" if exc=="Yes" else "",
              f"{rnd.randint(10**11,10**12-1)}", f"acct-{app[2].lower().replace(' ','-')}", rnd.choice(["AWS","Azure","GCP"]),
              rnd.choice(["Production","Staging","Development"]), f"i-{rnd.getrandbits(48):012x}", "Container Image", cve,
              f"Vulnerability in {pkg[0]} allowing potential compromise.", f"https://nvd.nist.gov/vuln/detail/{cve}",
              f"aks-{rnd.choice(['east','west'])}-01", img, f"{img}-{rnd.randint(1,5)}", f"org/{img}", "registry.example.com",
              f"registry.example.com/org/{img}", f"1.{rnd.randint(0,9)}.{rnd.randint(0,20)}", (opened-timedelta(days=30)).isoformat(),
              pkg[0], pkg[1], pkg[2], f"/usr/lib/{pkg[0]}", f"sha256:{rnd.getrandbits(64):016x}", "RUN apt-get install -y ...",
              "debian", "11", "2026-06-30", "Example Firm", rnd.choice(["US","UK","SG","MY"]), "CMS-01", "Technology",
              app[0], app[1], app[2], app[3], "Technology", rnd.choice(["Confidential","Internal"]), "Standard"])
    print(f"wrote {n} rows to {out}")

if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 500)
