import json

with open("config.json", "r", encoding="utf-8") as handle:
    config = json.load(handle)

accountName = config["accountName"]
accountTag = config["accountTag"]
accountId = config["accountId"]
level = config["level"]
sanity = config["sanity"]
lmd = config["lmd"]
primes = config["primes"]
orundums = config["orundums"]