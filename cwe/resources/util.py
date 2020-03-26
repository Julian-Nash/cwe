import csv
import json
import pickle

with open('software_development.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)

    sdo = {}

    for row in reader:
        sdo[row["CWE-ID"]] = {
            k.replace(" ", "_").replace("-", "_").lower(): v
            for k, v in row.items()
            if k
        }

with open('research_concepts.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)

    rco = {}

    for row in reader:
        rco[row["CWE-ID"]] = {
            k.replace(" ", "_").replace("-", "_").lower(): v
            for k, v in row.items()
            if k
        }

with open('hardware_design.csv', newline='') as csvfile:
    reader = csv.DictReader(csvfile)

    hdo = {}

    for row in reader:
        hdo[row["CWE-ID"]] = {
            k.replace(" ", "_").replace("-", "_").lower(): v
            for k, v in row.items()
            if k
        }

with open("hardware_design.json", "w") as fp:
    json.dump(hdo, fp)
with open("research_concepts.json", "w") as fp:
    json.dump(rco, fp)
with open("software_development.json", "w") as fp:
    json.dump(sdo, fp)

# total = {}
#
# for k, v in sdo.items():
#     if k not in total:
#         total[k] = v
# for k, v in rco.items():
#     if k not in total:
#         total[k] = v
# for k, v in hdo.items():
#     if k not in total:
#         total[k] = v
#
# with open("../cwe.json", "w") as fo:
#     json.dump(total, fo)
#
# with open("../cwe.pickle", "wb") as pf:
#     pickle.dump(total, pf)
