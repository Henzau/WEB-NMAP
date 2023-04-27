import json
import os
import shutil # Copy file
from packaging import version # easy way to compare version 
import re


#camel case

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

 
#This fonction will test one package and give back the list of cve json or an empty array if no cve was found, this is the bruteforce way, meaning it will check every cve.
def TestPackage(Package,PathNewDB):
    CVEList= []
    if Package[0] in os.listdir("./NewDB") :
        
        for i, (root, dirs, filenames) in enumerate(os.walk(PathNewDB+'/'+Package[0])):
            for file in filenames :
                try:
                    f = open(root+'/'+file,encoding="utf8")
                except Exception:
                    print("An error as occured in the TestPackage")
                    return -2
                data=json.load(f)
                versionA = []
                try :
                    versionA = data["affected"][0]["database_specific"]["last_known_affected_version_range"]
                except :
                    try :
                        if len(data["affected"][0]["ranges"][0]["events"]) >1 :
                            try :
                                versionA=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
                            except :
                                versionA=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
                        else :
                            try:
                                CVEList.append(data)
                            except:
                                print("error")
                    except : 
                        print("error New Format")
                
                if versionA ==[]:
                    continue
                else :
                    if re.search('[a-zA-Z]', versionA):
                        print("here")
                        if version.parse(Package[1]) < version.parse(versionA.split()[1].split(".")[0]):
                        #CVE still active
                            CVEList.append(data)
                    elif "<" in versionA :
                        print("no Here")
                        if version.parse(Package[1]) < version.parse(versionA.split()[1]):
                        #CVE still active
                            CVEList.append(data)
                    else :
                        if version.parse(Package[1]) < version.parse(versionA):
                            CVEList.append(data)
    return CVEList
    



if __name__ == "__main__":
    info = GetPackages('./AppTest/package-lock.json')
    #ProcessRawDB("C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed","./NewDB")
    print(len(info))
    nbCVE=0
    nbIn=0
    CVEList = []
    PCVE = []
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
    
    """
    PCVE = TestPackage(('acorn', '8.8.1'),"./NewDB")
    if PCVE == -2:
        print("an error occured")
    if len(PCVE) !=0:
        nbCVE+=1
        CVEList.append(PCVE)

    print("Nb Package in ")
    print(nbIn)
    print(nbCVE)
    

    """
    for p in info:
        print(p)
    print(CVEList)
    print(nbCVE)
   