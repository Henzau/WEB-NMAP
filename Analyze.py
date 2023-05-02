import json
import os
import shutil # Copy file
from packaging import version # easy way to compare version 
import re
import string

 #use java convention

class Analyze:
    def __init__(self):
        self.listCVE = []
        self.nbCVE = 0

    def compareVersion(self,B,data,way,i):
    versionA = []
    versionB = []
    match way:
        case 1 :
            versionA = data["affected"][i]["database_specific"]["last_known_affected_version_range"]
            if "<=" in versionA :
                if version.parse(B[1]) <= version.parse(versionA.split()[1]):
                #CVE still active
                    self.listCVE.append(data)
            elif "<" in versionA :
                if version.parse(B[1]) < version.parse(versionA.split()[1]):
                    self.listCVE.append(data)
            else :
                if version.parse(B[1]) <= version.parse(versionA):
                    self.listCVE.append(data)

        case 2 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if "pre" in versionA :
                versionA = versionA.replace("pre","")
            if "<=" in versionB :
                if version.parse(B[1]) >= version.parse(versionA.split()[1]) and version.parse(B[1]) <= version.parse(versionB.split()[1]):
                #CVE still active
                    self.listCVE.append(data)
            else :
                if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <= version.parse(versionB):
                    self.listCVE.append(data)

        case 3 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
            if "<=" in versionB :
                if version.parse(B[1]) >= version.parse(versionA.split()[1]) and version.parse(B[1]) <= version.parse(versionB.split()[1]):
                #CVE still active
                    self.listCVE.append(data)
            else :
                if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB):
                    self.listCVE.append(data)

        case 4 :
            self.listCVE.append(data)

        case 5 :
            print("ERROR in CVE")

        case 6 :
            
            if version.parse(B[1]) > version.parse("2.0.2"):
                self.listCVE.append(data)
        
        case _ :
            print("ERROR compare")

    #Check how to get info in the DB
    def selectWay(self,data):
        versionA = []
        try :
        
            versionA = data["affected"][i]["database_specific"]["last_known_affected_version_range"]
        
            return 1                            
        except :
            try :
                if len(data["affected"][0]["ranges"][0]["events"]) >1 :
                    try :
                        versionA=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
                        return 2
                    except :
                        versionA=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
                        return 3
                else :
                    try:
                        #CVEList.append(data)
                        return 4
                    except:
                        return 5
            except :
                return 6
                #if Package[1] > "2.0.2":
                 #   CVEList.append(data)
                  #  print(root+'/'+file)
                   # print(data)
        return 'error'



    #This fonction will test one package and give back the list of cve json or an empty array if no cve was found, this is the bruteforce way, meaning it will check every cve in the dir.
    def testPackage(self,package,pathNewDB):
        #print(Package[0].split("/")[-1])
        if package[0].split("/")[-1] in os.listdir("./NewDB") :
            #Check every CVE on this package
            for i, (root, dirs, filenames) in enumerate(os.walk(pathNewDB+'/'+Package[0].split("/")[-1])):
                for file in filenames :
                    try:
                        f = open(root+'/'+file,encoding="utf8")
                    except Exception:
                        print("An error as occured in the TestPackage")
                        return -2
                    data=json.load(f)
                    way = WhichWay(data)
                
                    for i in range(len(data["affected"])):
                        CompareVersion(Package,data,way,i)
    


#PathDir -> path to the rawDB
#PathNewDB -> path where to save the new DATABASE
def processRawDB(PathDir,PathNewDB):
    count =0
    file = "GHSA-hgpf-97c5-74fc.json"
    for i, (root, dirs, filenames) in enumerate(os.walk(PathDir)):
        
        for file in filenames:
            try:
                f = open(root+"/"+file,encoding="utf8")
            except Exception:
                print("An error as occured")
                return
            data= json.load(f)
            name = data["affected"][0]["package"]["name"]
            versionI = ""
            versionF = ""
            versionD = ""
            test = 0
            # print(len(data["affected"]))
            for p in range(len(data["affected"])) :
                try :
                    versionI = data["affected"][p]["ranges"][0]["events"][0]["introduced"]
                except :
                    try:
                        versionD = data["affected"][p]["database_specific"]["last_known_affected_version_range"]
                        test = 2
                    except :
                        test = 3
                
                try :
                    if len(data["affected"][p]["ranges"][0]["events"]) > 0 :
                        try:
                            versionF = data["affected"][p]["ranges"][0]["events"][1]["fixed"]
                        except :
                            versionF = data["affected"][p]["ranges"][0]["events"][1]["last_affected"]
                    else:
                        versionF = data["affected"][p]["versions"][0]

                except :
                        continue
                           
                "Changing version type"
                if versionI != "" :

                    if "-" in versionI :
                        versionI = versionI.replace("-",".")
                    versionI =  versionI.translate({ord(c): None for c in 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN?_-'})
                    prev = None
                    versionI3 = ""
                    for c in versionI:
                        if prev != c or c != ".":
                            versionI3 += c
                            prev = c
                    if versionI3[-1] == ".":
                        versionI3 = versionI3[:-1]
                 


                # Same thing for the last affected or fixed version
                
                "Changing version type"
                if versionF != "" :

                    
                    if "-" in versionF :
                        versionF = versionF.replace("-",".")
                    versionF =  versionF.translate({ord(k): None for k in 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN?_-'})
                    prev2 = None
                    versionF3 = ""
                    for c in versionF:
                        if prev2 != c or c != ".":
                            versionF3 += c
                            prev2 = c
                    if versionF3[-1] == ".":
                        versionF3 = versionF3[:-1]
                    

                if versionD != "" :

                    if "-" in versionD :
                        versionD = versionD.replace("-",".")
                    versionD =  versionD.translate({ord(c): None for c in 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN?_--'})
                    prev3 = None
                    versionD3 = ""
                    for c in versionD:
                        if prev3 != c or c != ".":
                            versionD3 += c
                            prev3 = c
                    if versionD3[-1] == ".":
                        versionD3 = versionD3[:-1]


                        

                try :
                        data["affected"][p]["ranges"][0]["events"][0]["introduced"] = versionI3
                except :
                    try :
                        data["affected"][p]["database_specific"]["last_known_affected_version_range"] = versionD3  
                    except :
                        continue                       
                        
                
                if test==0 and len(data["affected"][p]["ranges"]) > 0:
                    try :
                        data["affected"][p]["ranges"][0]["events"][1]["fixed"] = versionF3
                    except :
                        try:
                            data["affected"][p]["ranges"][0]["events"][1]["last_affected"] = versionF3
                        except :
                            data["affected"][p]["versions"][0] = versionF3
                            print("Error fixed ")

            f.close()
            if ':' in name :
                name = name.split(":")[0]
            if not os.path.exists(PathNewDB+'/'+name):
                os.makedirs(PathNewDB+'/'+name)
            with open(PathNewDB+'/'+name+ "/"+ file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=4)
              

 




if __name__ == "__main__":
    info = GetPackages('./AppTest/package-lock.json')
    #ProcessRawDB("C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed","./NewDB")
    
    print(len(info))
    nbCVE=0
    nbIn=0
    CVEList = []
    PCVE = []
    PCVEL = []
    # For test purpose
    
    for p in info:
        if p[0] in os.listdir("./NewDB") :
            nbIn+=1
        PCVE = TestPackage(p,"./NewDB")
        if PCVE == -2:
            print("an error occured")
            break
        if len(PCVE) !=0:
            nbCVE+=1
            CVEList.append(PCVE)
            PCVEL.append(p)
    
    PCVE = TestPackage(('babel-core/node_modules/json5', '0.5.1'),"./NewDB")
    if PCVE == -2:
        print("an error occured")
            
    if len(PCVE) !=0:
        nbCVE+=1
        CVEList.append(PCVE)
        PCVEL.append(p)
    
    CVENAME = []
    #for p in info:
    #    print(p)
    for j in CVEList:
        CVENAME.append((j[0]["affected"][0]["package"]["name"],j[0]["id"]))
        
    print(PCVEL)
    print(nbCVE)
   