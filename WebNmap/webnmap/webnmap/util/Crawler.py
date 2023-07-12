import asyncio
import os
import json
import git 

from webnmap.webnmap.model.Affected import Affected
from webnmap.webnmap.model.EcoSystem import EcoSystem
from webnmap.webnmap.model.CVE import CVE
from gaimon.util.CommonDBBounded import CommonDBBounded
from typing import List


class Crawler:
    def __init__(self,path):
        self.pathToRawDB = path
        self.cveList = []
        self.changedFiles = []
        self.newFiles = []
        self.nbcve = 0
        self.cursor = {}

    def pullGithub(self):
        repo = git.Repo(self.pathToRawDB)
        # Check the status of the repository
        repo_status = repo.git.status()
        print(repo_status)

        o = repo.remotes.origin
        o.pull()
        print(repo_status)
        # Update the index
        repo.index.update()
        # Update the index

        # Check the status of the repository
        repo_status = repo.git.status()

        print("Git Status:")
        print(repo_status)
        try:
            changed_files = [item.a_path for item in repo.git.diff(None)]
            new_files = [item.a_path for item in repo.git.diff('HEAD')]
            
            print("Changed Files:")
            for file in changed_files:
                print(file)

            print("\nNew Files:")
            for file in new_files:
                print(file)
            
            if len(changed_files) != 0 or len(new_files) != 0:
                print("Changes were made, updating the Database!")
            else:
                print("No changes detected.")
                
        except Exception as e:
            print("Error: Pull request failed")
            print(str(e))


    async def connectDB(self,config):
        self.cursor = CommonDBBounded(config)
        await self.cursor.connectDB()
        

    def updateDB(self):
        pass

    def checkRanges(self,data):
        for affected in data["affected"]:
            ranges = affected.get("ranges", None)
            if ranges is None : continue
            assert len(ranges) == 1 
    def checkVersions(self,data):
        for affected in data["affected"]:
            versions = affected.get("versions", None)
            if versions is None : continue
            assert len(versions) == 1 

    
    def getIntroduced(self,affected):
        ranges = affected.get("ranges", None)
        if ranges is None : return None
        events = ranges[0].get("events",None)
        if events is None : return None
        introduced = events[0].get("introduced",None)
        if introduced is None : return None
        return introduced

    def getFixed(self,affected):
        fixed = affected.get("versions",None)
        if fixed is not None : return fixed[0]
        ranges = affected.get("ranges", None)
        if ranges is None : return None
        events = ranges[0].get("events",None)
        if events is None : return None
        if len(events) == 2 :
            fixed = events[1].get("fixed",None)
            if fixed is None : 
                fixed = events[1].get("last_affected",None)
            if fixed is None : return None
       
        return fixed

    def repairVersion(self,version):
        if version != "" :
            if "-" in version :
                version = version.replace("-",".")
            version =  version.translate({ord(c): None for c in 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN?_-'})
            prev = None
            
            #for c in version:
            #    if prev != c or c != ".":
            #        versionI3 += c
            #        prev = c
            if version[-1] == ".":
                version = version[:-1]
            if ".." in version:
                version = version.replace("..",".") 
        return version                



    def addCVE(self,data):
        if "Duplicate" in data["details"] :
                pass
        else :
            introduced = ""
            versionF = ""
            versionD = ""
            test = 0
            for affected in data["affected"] :
                specific = affected.get("database_specific", None)
                if specific is None : continue
                version = specific.get("last_known_affected_version_range", None)
                if version is None : 
                    versionF = self.getFixed(affected)                
                introduced = self.getIntroduced(affected)

                introduced = self.repairVersion(introduced)
                version = self.repairVersion(version)
                versionF = self.repairVersion(versionF)


                try :
                        affected["ranges"][0]["events"][0]["introduced"] = introduced
                except :
                    try :
                        affected["database_specific"]["last_known_affected_version_range"] = version  
                    except :
                        continue                       
                
                if test==0 and len(affected["ranges"]) > 1:
                    try :
                        affected["ranges"][0]["events"][1]["fixed"] = versionF
                    except :
                        try:
                            affected["ranges"][0]["events"][1]["last_affected"] = versionF
                        except :
                            affected["versions"][0] = versionF
                            print("Error fixed ")
            self.nbcve +=1
            self.cveList.append(data)

    def onlyUpdate(self):
        for i in self.newFiles:
            try:
                    f = open(i,encoding="utf8")
            except Exception:
                    print("An error as occured")
                    return
            data= json.load(f)
            self.addCVE(data)
            f.close()

        for i in self.changedFiles :
            try:
                    f = open(i,encoding="utf8")
            except Exception:
                    print("An error as occured")
                    return
            data= json.load(f)
            self.addCVE(data)
            f.close()
            
            

    def getRawDB(self):
        """ get every cve from the raw cve database
            specified by the pathToRawDB
        :param: pathToRawDB : path to the dir of the raw advisory database
        :return: none
        """
        for i, (root, dirs, filenames) in enumerate(os.walk(self.pathToRawDB+ "/advisories/github-reviewed")):
            for file in filenames:
                try:
                    f = open(root+"/"+file,encoding="utf8")
                except Exception:
                    print("An error as occured")
                    return
                data= json.load(f)
                self.addCVE(data)
                f.close

    async def initialize(self,config) :
        
        await self.connectDB(config)
        self.cursor.session.appendModel(CVE)
        self.cursor.session.appendModel(Affected)
        self.cursor.session.appendModel(EcoSystem)
        self.cursor.session.checkModelLinking()
        await self.cursor.session.createTable()
        
        ecoSystemList:list[EcoSystem] = await self.cursor.session.select(EcoSystem, "")
        
        ecoSystemMap = {i.ecosystem:i for i in ecoSystemList}
        insert = list()
        update = set()
        for cve in self.cveList :
            affected = cve.get("affected", None)
            if affected is None : continue
            eco = affected[0]["package"].get("ecosystem", None)
            if eco is None : continue
            record = ecoSystemMap.get(eco, None)
            
            if record is not None and record not in update:
                continue
            #	#record.fromDict(eco)  We don't want to do anything here
            #	await session.update(record)  
            #	update.add(record)
            else :
                record = EcoSystem(eco)
                ecoSystemMap[record.ecosystem] = record
                insert.append(record)
        await self.cursor.session.insertMultiple(insert, True, True)
        for eco in ecoSystemList :
            print(eco.ecosystem)
        

        cveList:list[CVE] = await self.cursor.session.select(CVE, "")
        listID:list[str] = [cveDB.ADVid for cveDB in cveList]
        insertCVE = list()
        for raw in self.cveList :
            cve1 = CVE(raw)
            if cve1.ADVid in listID :
                continue

            filtered = list()
            for affected in cve1.affected :   
                affected.eco = ecoSystemMap.get(affected.name, None)
                if affected.eco is not None :
                    filtered.append(affected)
            cve1.affected = filtered
            insertCVE.append(cve1)
        
        # NOTE Cannot insert everything at once, it is too big for postgreSQL
        print("Inserting in the database: "+ str(len(insertCVE)) + "cve (s)")
        for chunk in range(0,len(insertCVE),1500) :
            print(chunk,chunk+1500)
            await self.cursor.session.insertMultiple(insertCVE[chunk:chunk+1500], True, True)

        ecoSystemList = await self.cursor.session.select(EcoSystem, "WHERE ecosystem = 'npm' ")
        affectedList = []
        if len(ecoSystemList):
            clause = f"WHERE eco IN ({','.join([str(i.id) for i in  ecoSystemList])})"
            affectedList = await self.cursor.session.select(Affected, clause, isRelated=True)
        cveList = [i.cve for i in affectedList]
        
        return cveList
                    
                
if __name__=="__main__":
    config = {}
    with open("/etc/gaimon/extension/webnmap/WebNmap.json") as fd :  # ../config/global/WebNmap.json
        config["DB"] = json.load(fd)

    crawler = Crawler("./RawDB/advisory-database")
    crawler.pullGithub()
    crawler.getRawDB()
    
    def applyData(fetched:List[CVE]) :
        print(f">>> Total {len(fetched)}")
        """
        for cve in fetched:
            print(dir(cve))
            print(cve.name)
            print(cve.ADVid)
            print(cve.path)
            print(cve.summary)
            print(cve.severity)
            print("end cve \n")
        """
    IS_ASYNC = True

    if IS_ASYNC :
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(crawler.initialize(config))
        applyData(result)

    