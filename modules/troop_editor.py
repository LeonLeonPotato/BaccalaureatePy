from commons import Module
from utils import CustomFlow
import utils
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
        # utils.info("Default skill of {} changed to {}".format(charname, utils.character_config[charname]["defaultSkill"]))

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
        squad_id = flow.data["squadId"]
        squad_cfg = utils.squads[str(int(squad_id) + 1)]
        data = flow.data["slots"]

        template = {
            "playerDataDelta": {
                "deleted": {},
                "modified": {
                    "troop": {
                        "squads": {
                            squad_id: {
                                "slots": data
                            }
                        }
                    }
                }
            }
        }

        squad_cfg.clear()
        for i in data:
            # if not i: continue
            # charname = self.instid_to_charname[i["charInstId"]]
            # charcfg = utils.character_config[charname]
            # charcfg["module"] = i["currentEquip"] if i["currentEquip"] else "Original"
            # charcfg["defaultSkill"] = i["skillIndex"] + 1
            if i:
                charname = self.instid_to_charname[i["charInstId"]]
                cfg_template = {
                    "name": charname,
                    "skill": i["skillIndex"] + 1,
                }
                if i["currentEquip"]:
                    cfg_template["module"] = utils.module_table["equipDict"][i["currentEquip"]]["typeName2"]
                else:
                    cfg_template["module"] = "Original"
                squad_cfg.append(cfg_template)
            else:
                squad_cfg.append(None)

        

        flow.flow.response = mitmproxy.http.Response.make(
            200, 
            json.dumps(template)
        )

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
                "skills": [ ],
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

            print(utils.get_module_id_from_name(v["module"], charid))
            template["currentEquip"] = utils.get_module_id_from_name(v["module"], charid)

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

    def loadSquads(self, flow : CustomFlow):
        flow.data["user"]["troop"]["curCharInstId"] = len(self.charname_to_instid)
        to_edit = flow.data["user"]["troop"]["squads"]

        for v in to_edit.values():
            cfg_id = str(int(v["squadId"]) + 1)
            squad_cfg = utils.squads[cfg_id]
            v["slots"] = []
            for i in squad_cfg:
                if not i:
                    v["slots"].append(None)
                    continue
                char_template = {
                    "charInstId": self.charname_to_instid[i["name"]],
                    "skillIndex": i["skill"]-1,
                    "currentEquip": utils.get_module_id_from_name(i["module"], utils.name_to_charid[i["name"]])
                }
                v["slots"].append(char_template)


    def request(self, obj : CustomFlow):
        if obj.flow.request.path == "/charBuild/setDefaultSkill":
            self.defaultSkill(obj)
        elif obj.flow.request.path == "/charBuild/setEquipment":
            self.setModule(obj)
        elif obj.flow.request.path == "/quest/squadFormation":
            self.setSquad(obj)

    def response(self, obj : CustomFlow):
        if obj.flow.request.path == "/account/syncData":
            self.syncData(obj)
            self.loadSquads(obj)



        