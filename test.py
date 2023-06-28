import json
import utils
handle = open("characters.json", "w")
data = json.load(open("cache\\character_table.json", "r", encoding="utf-8"))
modules = json.load(open("cache\\module_table.json", "r", encoding="utf-8"))

maindata = {}

# intended to be human readable
for i, v in data.items():
    if i.startswith("char_"):
        chardata = {
            "level": [30, 30, 55, 70, 80, 90][v['rarity']],
            "elite": [0, 0, 1, 2, 2, 2][v['rarity']],
            "potential": v["maxPotentialLevel"] + 1,
            "defaultSkill": len(v["skills"]),
            "skilllevel": 7 if v['rarity'] >= 2 else 1,
            "masteries": { 
                f"s{i+1}": (3 if v['rarity'] > 2 else 0) 
                for i in range(len(v["skills"])) 
            },
            "skin": utils.charid_to_skinids[i][-1],
            "module": "Original", # change later
            "trust": 25570,
            "lang": "jp" 
        }

        maindata[v["name"]] = chardata

json.dump(maindata, handle, indent=4)
handle.close()