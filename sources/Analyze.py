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
       
    def createCVE(self,package,name,version,CVEid,severity,ADVID,summary):
        cve = CVE(name,version,CVEid,severity,package,ADVID,summary)
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
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],str(data["severity"]),data["id"],data["summary"])
                        
                elif "<" in versionA :
                    if version.parse(B.versionSP) < version.parse(versionA.split()[1]):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],str(data["severity"]),data["id"],data["summary"])
                else :
                    if version.parse(B.versionSP) <= version.parse(versionA):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],json.dumps(str(data["severity"])),data["id"],data["summary"])

            case 2 :
                versionA=data["affected"][i]["ranges"][0]["events"][0]["introduced"]
                versionB=data["affected"][i]["ranges"][0]["events"][1]["fixed"]
                
                if "pre" in versionA :
                    versionA = versionA.replace("pre","")
                if "<=" in versionB :
                    if version.parse(B.versionSP) >= version.parse(versionA.split()[1]) and version.parse(B.versionSP) <= version.parse(versionB.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],str(data["severity"]),data["id"],data["summary"])
                else :
                    if version.parse(B.versionSP) >= version.parse(versionA) and version.parse(B.versionSP) < version.parse(versionB):
                       
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],str(data["severity"]),data["id"],data["summary"])

            case 3 :
                versionA=data["affected"][i]["ranges"][0]["events"][0]["introduced"]
                versionB=data["affected"][i]["ranges"][0]["events"][1]["last_affected"]
                if "<=" in versionB :
                    if version.parse(B.versionSP) >= version.parse(versionA.split()[1]) and version.parse(B.versionSP) <= version.parse(versionB.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],str(data["severity"]),data["id"],data["summary"])
                else :
                    if version.parse(B.versionSP) >= version.parse(versionA) and version.parse(B.versionSP) <= version.parse(versionB):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],str(data["severity"]),data["id"],data["summary"])

            case 4 :
                self.createCVE(B,data["affected"][i]["package"]["name"],"0",data["aliases"],str(data["severity"]),data["id"],data["summary"])

            case 5 :
                print("ERROR in CVE")

            case 6 :
            
                if version.parse(B.versionSP) > version.parse("2.0.2"):
                    self.createCVE(B,data["affected"][i]["package"]["name"],"<= 2.0.2",data["aliases"],str(data["severity"]),data["id"])
        
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


    def reportPrint(self):
        print("WebNmap report on your website ")
        print("By Enzo\n \n")
        for cve in self.listCVESite:
            print("Common Vulnerability Exposure found in the package : "+ cve.webPackage.nameSP)
            print("Problem : "+cve.summary)
            print("this package can be found here : "+cve.webPackage.pathSP)
            print("the severity of the Vulnerability is :"+cve.severity.split("CVSS:")[-1].split("/")[0])
            print("It can be fixed by updating this package to the version " + cve.version)
            print("------------------------------------------------------------------------------------------")
        print("there is "+str(self.nbCVE) + " Vulnerabilities on your website")


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
                if cve[0] == "core":
                    if cve[1] == package.pathSP.split("node_modules")[-1]:
                        data = cve[3]
                        jsondata = json.loads(data)
                        way = self.selectWay(jsondata)
                        for i in range(len(jsondata["affected"])):
                            self.compareVersion(package,jsondata,way,i)
                else :
                    data = cve[3]
                    jsondata = json.loads(data)
                    way = self.selectWay(jsondata)
                    for i in range(len(jsondata["affected"])):
                        if jsondata["affected"][i]["package"]["name"] == package.nameSP:
                            self.compareVersion(package,jsondata,way,i)

    def checkPackages(self,packages):
        """ Test every packages 
            :param: packages : list of packages from the siteweb   
            :return: none
        """
        for package in packages:
            self.testPackage(package)

        self.reportPrint()
              


