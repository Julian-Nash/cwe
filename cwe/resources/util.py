import json

with open("software_development.json", "r") as fp:
    data = json.load(fp)

# # args
# for k, v in data.items():
#     for key in v.keys():
#         print(f"{key}=None, ", end="")
#     break

# attrs
for k, v in data.items():
    for key in v.keys():
        t = f"""
@property
def {key}(self):
    return self._{key}
        """
        print(t)
    break