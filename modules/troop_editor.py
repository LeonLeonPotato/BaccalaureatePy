from commons import Module
from utils import CustomFlow
import utils
import configloader
import mitmproxy.http
import json

class OperatorEditor(Module):
    def __init__(self):
        super().__init__("Operator Editor")
        self.instid_to_charname = {}
        self.charname_to_instid = {}
        self.charname_to_sentdata = {}

    def defaultSkill(self, flow : CustomFlow):
        request = json.loads(flow.flow.request.text)
        instid = request["charInstId"]
        template = {
            "playerDataDelta": {
                "deleted": {},
                "modified": {
                    "troop": {
                        "chars": {
                            str(instid):  {
                                "defaultSkillIndex": request["defaultSkillIndex"]
                            }
                        }
                    }
                }
            }
        }

        charname = self.instid_to_charname[instid]
        utils.character_config[charname]["defaultSkill"] = request["defaultSkillIndex"] + 1
        utils.info("Default skill of {} changed to {}".format(charname, utils.character_config[charname]["defaultSkill"]))

        flow.flow.response = mitmproxy.http.Response.make(
            200, 
            json.dumps(template)
        )

    def setModule(self, flow : CustomFlow):
        request = json.loads(flow.flow.request.text)
        charname = self.instid_to_charname[request["charInstId"]]
        charcfg = utils.character_config[charname]
        template = {
            "playerDataDelta": {
                "deleted": {},
                "modified": {
                    "rlv2": {
                        "current": {
                            "record": {
                                "brief": None
                            }
                        }
                    },
                    "troop": {
                        "chars": {
                            str(request["charInstId"]): self.charname_to_sentdata[charname]
                        }
                    }
                }
            },
            "result": 0
        }


        template["playerDataDelta"]["modified"]["troop"]["chars"][str(request["charInstId"])]["currentEquip"] = request["equipId"]

        charcfg["module"] = utils.module_table["equipDict"][request["equipId"]]["typeName2"]
        if charcfg["module"] == None:
            charcfg["module"] = "Original"

        flow.flow.response = mitmproxy.http.Response.make(
            200, 
            json.dumps(template)
        )

    def setSquad(self, flow : CustomFlow):
        pass

    def syncData(self, flow : CustomFlow):
        to_edit = flow.data["user"]["troop"]

        for i, (k, v) in enumerate(utils.character_config.items()):
            charid = utils.name_to_charid[k]
            self.charname_to_instid[k] = i
            template = {
                "instId": i,
                "charId": charid,
                "favorPoint": v["trust"],
                "potentialRank": v["potential"]-1,
                "mainSkillLvl": v["skilllevel"],
                "skin": v["skin"],
                "level": v["level"],
                "exp": 0,
                "evolvePhase": v["elite"],
                "defaultSkillIndex": v["defaultSkill"]-1,
                "gainTime": 0,
                "skills": [
                ],
                "voiceLan": v["lang"].upper(),
                "currentEquip": None,
                "equip": {}
            }

            for skill, mastery in v["masteries"].items():
                skill_ordinal = int(skill[-1])-1 # skill is in the form of "s#" and we want the number
                skillId = utils.character_table[charid]["skills"][skill_ordinal]['skillId']
                template["skills"].append({
                    "skillId": skillId,
                    "unlock": 1,
                    "state": 0,
                    "specializeLevel": mastery,
                    "completeUpgradeTime": -1
                })

            # code i wrote to find the module lol
            # its kinda shitty ngl
            if charid in utils.module_table["charEquip"]:
                for i2 in utils.module_table["charEquip"][charid]:
                    found_mod = utils.module_table["equipDict"][i2]["typeName2"]
                    if (not found_mod and v["module"].lower() == "original") or (found_mod and found_mod.lower() == v["module"].lower()):
                        template["currentEquip"] = i2
                        break

            if charid in utils.module_table["charEquip"]:
                for equip_add in utils.module_table["charEquip"][charid]:
                    equip = utils.module_table["equipDict"][equip_add]
                    template["equip"][equip_add] = {
                        "hide": 0,
                        "level": len(equip["itemCost"]) if equip["itemCost"] != None else 1,
                        "locked": 0
                    }

            self.instid_to_charname[i] = k
            self.charname_to_sentdata[k] = template
            to_edit["chars"][str(i)] = template

    def request(self, obj : CustomFlow):
        if obj.flow.request.path == "/charBuild/setDefaultSkill":
            self.defaultSkill(obj)
        elif obj.flow.request.path == "/charBuild/setEquipment":
            self.setModule(obj)

    def response(self, obj : CustomFlow):
        if obj.flow.request.path == "/account/syncData":
            self.syncData(obj)



        