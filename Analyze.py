import json
import os
import shutil # Copy file
from packaging import version # easy way to compare version 
import re


#camel case
#PathFile to the file "package-lock.json"
def GetPackages(PathFile):
    # Opening JSON file
    f = open(PathFile)
  
    # returns JSON object as 
    # a dictionary
    data = json.load(f)
    packages = []
  
    # Iterating through the json
    # list
    for i in data['packages']:
        version = data['packages'][i]['version']
        name = i[13:]
        packages.append((name,version))

    #we have a tuple with the name of the packages and the version of the packages downloaded  
    # Closing file
    f.close()
    return packages


#PathDir -> path to the rawDB
#PathNewDB -> path where to save the new DATABASE
def ProcessRawDB(PathDir,PathNewDB):
    count =0
    for i, (root, dirs, filenames) in enumerate(os.walk(PathDir)):
        
            for file in filenames:
                try:
                    f = open(root+'/'+file,encoding="utf8")
                except Exception:
                    print("An error as occured")
                    return
                data= json.load(f)
                name = data["affected"][0]["package"]["name"]
                f.close()
                if ':' in name :
                    name = name.split(":")[0]
                if not os.path.exists(PathNewDB+'/'+name):
                    os.makedirs(PathNewDB+'/'+name)
                shutil.copy(root+'/'+file,PathNewDB+'/'+name)
                #print( data["affected"][0]["package"]["name"])

 
def CompareVersion(B,CVEList,data,way,i):
    versionA = []
    versionB = []
    match way:
        case 1 :
            versionA = data["affected"][i]["database_specific"]["last_known_affected_version_range"]
            if re.search('[a-zA-Z]', versionA):
                print("je suis la")
                if version.parse(B[1]) <= version.parse(versionA.split()[1].split(".")[0]):
                #CVE still active
                    CVEList.append(data)
            elif "<=" in versionA :
                print("Test1")
                if version.parse(B[1]) <= version.parse(versionA.split()[1]):
                #CVE still active
                    CVEList.append(data)
            elif "<" in versionA :
                print("test2")
                if version.parse(B[1]) < version.parse(versionA.split()[1]):
                    CVEList.append(data)
            else :
                print("test3")
                if version.parse(B[1]) <= version.parse(versionA):
                    CVEList.append(data)

        case 2 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if "pre" in versionA :
                versionA = versionA.replace("pre","")
            if "<=" in versionB :
                if version.parse(B[1]) >= version.parse(versionA.split()[1]) and version.parse(B[1]) <= version.parse(versionB.split()[1]):
                #CVE still active
                    CVEList.append(data)
            else :
                if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <= version.parse(versionB):
                    CVEList.append(data)

        case 3 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
            if re.search('[a-zA-Z]', versionB):
                if version.parse(B[1]) >= version.parse(versionA.split()[1].split(".")[0]) and version.parse(B[1]) < version.parse(versionB.split()[1].split(".")[0]) :
                #CVE still active
                    CVEList.append(data)
            elif "<=" in versionB :
                if version.parse(B[1]) >= version.parse(versionA.split()[1]) and version.parse(B[1]) <= version.parse(versionB.split()[1]):
                #CVE still active
                    CVEList.append(data)
            else :
                if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB):
                    CVEList.append(data)

        case 4 :
            CVEList.append(data)

        case 5 :
            print("ERROR in CVE")

        case 6 :
            
            if version.parse(B[1]) > version.parse("2.0.2"):
                CVEList.append(data)
        case 7 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-",".")) :
            #CVE still active
                CVEList.append(data)
        case 8 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-",".")) :
            #CVE still active
                CVEList.append(data)
        case 9 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-rc","")) :
            #CVE still active
                CVEList.append(data)
        case 10 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-beta","")) :
            #CVE still active
                CVEList.append(data)

        case 11 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-alpha","")) :
            #CVE still active
                CVEList.append(data)
        case 12 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-dev","")) :
            #CVE still active
                CVEList.append(data)
        case 13 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-beta","")) :
            #CVE still active
                CVEList.append(data)

        case 14 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(str(int(versionB.split("-")[-1],16))) :
            #CVE still active
                CVEList.append(data)

        case 15 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(str(int(versionB.replace("v",""),16))) :
            #CVE still active
                CVEList.append(data)
        case 16 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            versionC = versionB.split(".")
            versionC[1] = str(int(versionC[1].replace("v",""),16))
            versionB = versionC[0] + versionC[1]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB) :
            #CVE still active
                CVEList.append(data)

        case 17 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("vdb_f83a_1c6a_9d",str(int("bf83a1c6a9d",16)))) :
            #CVE still active
                CVEList.append(data)

        case 18 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-2023-03-20T01-49-44-80e3135","0.0.0.2023.03.2001.4944." + str(int("80e3135",16)))) :
            #CVE still active
                CVEList.append(data)

        case 19 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("7.1.10.fp18","7.1.10." + str(int("f18",16)))) :
            #CVE still active
                CVEList.append(data)

        case 20 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-jdk","")) :
            #CVE still active
                CVEList.append(data)
        case 21 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("rc","")) :
            #CVE still active
                CVEList.append(data)

        case 22 :
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) < version.parse(versionB.replace("-release","")) :
            #CVE still active
                CVEList.append(data)

        case 23 : 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20130808000456-233bccbb1abe","0.0.0.20130808000456." + str(int("233bccbb1abe",16)))) :
            #CVE still active
                CVEList.append(data)

        case 24 : 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-2023-03-20T01-49-44-80e3135","0.0.0.2023.03.2001.49.44." + str(int("80e3135",16)))) :
            #CVE still active
                CVEList.append(data)

        case 25 : 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20230313153246-f686da832f85","0.0.0.20230313153246." + str(int("f686da832f85",16)))) :
            #CVE still active
                CVEList.append(data)
        case 26 : 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20200820025921-9323844ea773","0.0.0.20200820025921." + str(int("9323844ea773",16)))) :
            #CVE still active
                CVEList.append(data)
        case 27 : 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20140711154735-199f5f787806","0.0.0.20140711154735." + str(int("199f5f787806",16)))) :
            #CVE still active
                CVEList.append(data)
        case 28:
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20180523222229-09b5706aa936","0.0.0.20180523222229." + str(int("09b5706aa936",16)))) :
            #CVE still active
                CVEList.append(data)
        case 29:
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20220628124252-0981d5add8f3","0.0.0.20220628124252." + str(int("0981d5add8f3",16)))) :
            #CVE still active
                CVEList.append(data)
        case 30:
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20201120070457-d52dcb253c63","0.0.0.20201120070457." + str(int("d52dcb253c63",16)))) :
            #CVE still active
                CVEList.append(data)
        case 31: 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20220916234230-750f26ee23c7","0.0.0.20220916234230." + str(int("750f26ee23c7",16)))) :
            #CVE still active
                CVEList.append(data)

        case 32: 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.31.1-0.20200311080807-483ed864d69f","0.31.1.0.20200311080807." + str(int("483ed864d69f",16)))) :
            #CVE still active
                CVEList.append(data)

        case 33: 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("2.1.1-0.20170519163204-f913f5f9c7c6","2.1.1.0.20170519163204." + str(int("f913f5f9c7c6",16)))) :
            #CVE still active
                CVEList.append(data)

        case 34: 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20180426211050-dadd1711a617","0.0.0.20180426211050." + str(int("dadd1711a617",16)))) :
            #CVE still active
                CVEList.append(data)
        case 35: 
            versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
            versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
            if version.parse(B[1]) >= version.parse(versionA) and version.parse(B[1]) <version.parse(versionB.replace("0.0.0-20210418093520-a5395f728f8d","0.0.0.20210418093520." + str(int("a5395f728f8d",16)))) :
            #CVE still active
                CVEList.append(data)
       


        case _ :
            print("ERROR compare")

#Check how to get info in the DB
def WhichWay(data):
    versionA = []
    try :
        
        versionA = data["affected"][i]["database_specific"]["last_known_affected_version_range"]
        
        return 1                            
    except :
        try :
            if len(data["affected"][0]["ranges"][0]["events"]) >1 :
                try :
                    versionA=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
                    print(versionA)
                    if "release" in versionA :
                        return 22
                    if "b1b5c44e050f" in versionA:
                        return 14
                    if "vdb_f83a_1c6a_9d" in versionA:
                        return 17
                    if "0.0.0-20130808000456-233bccbb1abe" in versionA:
                        return 23
                    if "0.0.0-2023-03-20T01-49-44-80e3135"in versionA:
                        return 24
                    if "0.0.0-2023-03-20T01-49-44-80e3135" in versionA:
                        return 18
                    if "7.1.10.fp18" in versionA:
                        return 19
                    if "0.0.0-20230313153246-f686da832f85" in versionA:
                        return 25
                    if "0.0.0-20200820025921-9323844ea773" in versionA:
                        return 26
                    if "0.0.0-20140711154735-199f5f787806" in versionA:
                        return 27
                    if "0.0.0-20180523222229-09b5706aa936" in versionA:
                        return 28
                    if "0.0.0-20201120070457-d52dcb253c63" in versionA:
                        return 30
                    if "0.0.0-20220916234230-750f26ee23c7" in versionA: 
                        return 31
                    if "0.31.1-0.20200311080807-483ed864d69f" in versionA:
                        return 32
                    if "2.1.1-0.20170519163204-f913f5f9c7c6" in versionA :
                        return 33
                    if "0.0.0-20180426211050-dadd1711a617" in versionA :
                        return 34
                    if "0.0.0-20210418093520-a5395f728f8d" in versionA:
                        return 35
                    
                    if ".v" in versionA:
                        return 16
                    if "jdk" in versionA:
                        return 20
                    if "v" in versionA:
                        return 15
                    if "-rc" in versionA:
                        return 9
                    if "rc" in versionA:
                        return 21

                    
                    if "b" in versionA:
                        return 10
                    if "a" in versionA:
                        return 11
                    
                    if "-" in versionA:
                        return 8
                    return 2
                except :
                    versionA=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
                    if "0.0.0-20220628124252-0981d5add8f3" in versionA:
                        return 29
                    if "d" in versionA:
                        return 12
                    if "b" in versionA:
                        return 13
                    if "-" in versionA:
                        return 7

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



#This fonction will test one package and give back the list of cve json or an empty array if no cve was found, this is the bruteforce way, meaning it will check every cve.
def TestPackage(Package,PathNewDB):
    CVEList= []
   
    #print(Package[0].split("/")[-1])
    #if Package[0] in os.listdir("./NewDB") :
        #Check every CVE on this package
    for i, (root, dirs, filenames) in enumerate(os.walk(PathNewDB)):
        for file in filenames :
            try:
                f = open(root+'/'+file,encoding="utf8")
            except Exception:
                print("An error as occured in the TestPackage")
                return -2
            data=json.load(f)
            print(root+'/'+file)
            way = WhichWay(data)
                
            print(len(data["affected"]))
            for i in range(len(data["affected"])):
                CompareVersion(Package,CVEList,data,way,i)
    return CVEList



            
    




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
    """
    PCVE = TestPackage(('babel-core/node_modules/json5', '0.5.1'),"./NewDB")
    if PCVE == -2:
        print("an error occured")
            
    if len(PCVE) !=0:
        nbCVE+=1
        CVEList.append(PCVE)
        PCVEL.append(p)
    """
    CVENAME = []
    #for p in info:
    #    print(p)
    for j in CVEList:
        CVENAME.append((j[0]["affected"][0]["package"]["name"],j[0]["id"]))
        
    print(PCVEL)
    print(nbCVE)
   