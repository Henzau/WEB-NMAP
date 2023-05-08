import json
import os
import shutil # Copy file
from packaging import version # easy way to compare version 
from CVE import CVE
import re
import string
from CreateDB import CreateDB
 #use java convention
PATH_TO_DB = "../SQLITEDB/CVEDB.db"

class Analyze:
    def __init__(self):
        self.listCVESite = []
        self.db = CreateDB(PATH_TO_DB)
        self.nbCVE = 0
       
    def createCVE(self,package,name,version,CVEid,severity,ADVID):
        cve = CVE(name,version,CVEid,severity,package,ADVID)
        self.listCVESite.append(cve)
        self.nbCVE += 1
        
        
    def compareVersion(self,B,data,way,i):
        """
        Compare the version between two string version base on a way 
        specified by the pathToRawDB if the version correspond add the package as a vulnerable package
        :param: B : siteweb package  
                data : json data extract from the package CVE
                way : which way should we read the data
                i : which affected package is it and which version
        :return: none
        """
        versionA = []
        versionB = []

        match way:
            case 1 :
                versionA = data["affected"][i]["database_specific"]["last_known_affected_version_range"]
                if "<=" in versionA :
                    if version.parse(B.versionSP) <= version.parse(versionA.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["severity"],data["id"])
                        
                elif "<" in versionA :
                    if version.parse(B.versionSP) < version.parse(versionA.split()[1]):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["severity"],data["id"])
                else :
                    if version.parse(B.versionSP) <= version.parse(versionA):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["severity"],data["id"])

            case 2 :
                versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
                versionB=data["affected"][0]["ranges"][0]["events"][1]["fixed"]
                if "pre" in versionA :
                    versionA = versionA.replace("pre","")
                if "<=" in versionB :
                    if version.parse(B.versionSP) >= version.parse(versionA.split()[1]) and version.parse(B.versionSP) <= version.parse(versionB.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["severity"],data["id"])
                else :
                    if version.parse(B.versionSP) >= version.parse(versionA) and version.parse(B.versionSP) <= version.parse(versionB):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["severity"],data["id"])

            case 3 :
                versionA=data["affected"][0]["ranges"][0]["events"][0]["introduced"]
                versionB=data["affected"][0]["ranges"][0]["events"][1]["last_affected"]
                if "<=" in versionB :
                    if version.parse(B.versionSP) >= version.parse(versionA.split()[1]) and version.parse(B.versionSP) <= version.parse(versionB.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["severity"],data["id"])
                else :
                    if version.parse(B.versionSP) >= version.parse(versionA) and version.parse(B.versionSP) < version.parse(versionB):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["severity"],data["id"])

            case 4 :
                self.createCVE(B,data["affected"][i]["package"]["name"],"0",data["aliases"],data["severity"],data["id"])

            case 5 :
                print("ERROR in CVE")

            case 6 :
            
                if version.parse(B.versionSP) > version.parse("2.0.2"):
                    self.createCVE(B,data["affected"][i]["package"]["name"],"<= 2.0.2",data["aliases"],data["severity"],data["id"])
        
            case _ :
                print("ERROR compare")

    #Check how to get info in the DB
    def selectWay(self,data):
        """ Select which way to read the data from the cve data
            :param: data : json data extract from the package CVE
            :return: the way of reading the package
        """
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
    def testPackage(self,package):
        """ Test one package with all the cve available
            :param: package : package from the siteweb   
            :return: none
        """
        #print(self.listCVEDB)
        #Check every CVE on this package
        
            
        cvel = self.db.getInfo(package.nameSP)
        if len(cvel) > 0 :
            for cve in cvel:
                data = cve[3]
                jsondata = json.loads(data)
                way = self.selectWay(jsondata)
                for i in range(len(jsondata["affected"])):
                    self.compareVersion(package,jsondata,way,i)

    def checkPackages(self,packages):
        """ Test every packages 
            :param: packages : list of packages from the siteweb   
            :return: none
        """
        for package in packages:
            self.testPackage(package)

        for cve in self.listCVESite:
            print((cve.WebPackage.pathSP,cve.WebPackage.versionSP,cve.name,cve.version,cve.ADVID))
              


