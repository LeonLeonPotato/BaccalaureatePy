from commons import Module
from utils import CustomFlow
import configloader
import json
import utils

def loadCustomData(flow : CustomFlow):
    to_edit = flow.data["user"]["status"]
    to_edit["uid"] = str(configloader.accountId)
    to_edit["nickname"] = configloader.accountName
    to_edit["level"] = configloader.level
    to_edit["exp"] = 0
    to_edit["ap"] = configloader.sanity
    to_edit["maxAp"] = configloader.sanity
    to_edit["gold"] = configloader.lmd
    to_edit["payDiamond"] = configloader.primes
    to_edit["freeDiamond"] = configloader.orundums

class AccountEditor(Module):
    def __init__(self):
        super().__init__("Account Editor")

        self.stage_cache = None
        self.story_cache = None
    
    def request(self, obj : CustomFlow):
        pass

    def response(self, obj : CustomFlow):
        if(obj.flow.request.path != "/account/syncData"): 
            return

        toReplace = {}
        for k, v in utils.stage_table['stages'].items():
            self.stage_cache = {
                "stageId": k,
                "completeTimes": 10,
                "startTimes": 10,
                "practiceTimes": 10,
                "state": 3,
                "hasBattleReplay": 0,
                "noCostCnt": 0
            }
            toReplace[k] = self.stage_cache

        obj.data['user']['dungeon']['stages'] = toReplace

        obj.data["playerDataDelta"]["modified"]["status"]["mainStageProgress"] = "main_04-10" # enough for now
        obj.data["user"]["status"]["mainStageProgress"] = "main_04-10"
        obj.data["user"]["status"]["level"] = 120
        
        to_replace = { "init": 1 }
        for k, v in utils.story_table.items():
            to_replace[k] = 1
        obj.data["user"]["status"]["flags"] = to_replace

