from functools import lru_cache
import json
import os
import shutil # Copy file
from packaging import version # easy way to compare version 
import re
import string
from cvss import CVSS2, CVSS3
from webnmap.webnmap.model.CVE import CVE
from webnmap.webnmap.model.EcoSystem import EcoSystem
from webnmap.webnmap.model.Affected import Affected
from webnmap.webnmap.model.WebNmapCVE import WebNmapCVE


 #use java convention

config = {}
with open("/home/henzhau/WebNmap/webnmap/webnmap/config/global/WebNmap.json") as fd :  # ../config/global/WebNmap.json
    config["DB"] = json.load(fd)





class Analyze:
    def __init__(self,session,eco,cveByName):
        self.listCVESite = []
        self.nbCVE = 0
        self.session = session
        self.eco = eco
        self.cveByName = cveByName   
    
    def createCVE(self,package,name,version,CVEid,severity,ADVID,summary,fixed):
        cve = WebNmapCVE(name,version,CVEid,severity,package,ADVID,summary,fixed)
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
                #print(data['id'])
                versionA = data["affected"][i]["database_specific"]["last_known_affected_version_range"]
                if "<=" in versionA :
                    if version.parse(B.versionSP) <= version.parse(versionA.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"last_affected")
                        
                elif "<" in versionA :
                    if version.parse(B.versionSP) < version.parse(versionA.split()[1]):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"last_affected")
                else :
                    if version.parse(B.versionSP) <= version.parse(versionA):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"last_affected")

            case 2 :
                versionA=data["affected"][i]["ranges"][0]["events"][0]["introduced"]
                versionB=data["affected"][i]["ranges"][0]["events"][1]["fixed"]
                
                if "pre" in versionA :
                    versionA = versionA.replace("pre","")
                if "<=" in versionB :
                    if version.parse(B.versionSP) >= version.parse(versionA.split()[1]) and version.parse(B.versionSP) <= version.parse(versionB.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"fixed")
                else :
                    if version.parse(B.versionSP) >= version.parse(versionA) and version.parse(B.versionSP) < version.parse(versionB):
                        
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"fixed")

            case 3 :
                versionA=data["affected"][i]["ranges"][0]["events"][0]["introduced"]
                versionB=data["affected"][i]["ranges"][0]["events"][1]["last_affected"]
                if "<=" in versionB :
                    if version.parse(B.versionSP) >= version.parse(versionA.split()[1]) and version.parse(B.versionSP) <= version.parse(versionB.split()[1]):
                    #CVE still active
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"last_affected")
                else :
                    if version.parse(B.versionSP) >= version.parse(versionA) and version.parse(B.versionSP) <= version.parse(versionB):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionB,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"last_affected")

            case 4 :
                versionA=data["affected"][i]["versions"][0]
                if data["id"] == "GHSA-73qr-pfmq-6rp8":
                    if version.parse(B.versionSP) >= version.parse("2.0.3"):
                        self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"last_affected")
                elif version.parse(B.versionSP) <= version.parse(versionA):
                    self.createCVE(B,data["affected"][i]["package"]["name"],versionA,data["aliases"],data["database_specific"]["severity"],data["id"],data["summary"],"last_affected")


        
            case _ :
                print("ERROR compare")

    #Check how to get info in the DB
    def selectWay(self,affected):
        """ Select which way to read the data from the cve data
            :param: data : json data extract from the package CVE
            :return: the way of reading the package
        """
        versionA = []
        
        ranges = affected.get("ranges", None)
        if ranges is not None :
            events = ranges[0].get("events",None)
            if events is not None :
                if len(events) == 2 :
                    fixed = events[1].get("fixed",None)
                    if fixed is not None : 
                        return 2
                    
                    fixed = events[1].get("last_affected",None)
                    if fixed is not None : return 3
                    else : 
                        print("Error here")
                
        fixed =  affected.get("versions",None)
        if fixed is not None : return 4
        specific = affected.get("database_specific", None)
        if specific is not None : 
            version = specific.get("last_known_affected_version_range", None)
            if version is not None : return 1
        
        return -1


    def reportPrint(self):
        print("\n\nWebNmap report on your website ")
        print("By Enzo\n")
        print("There are "+str(self.nbCVE) + " vulnerabilities on your website")
        print("Here is a list of vulnerability and how to fix them\n")
        print("------------------------------------------------------------------------------------------")
        for cve in self.listCVESite:
            print("Common Vulnerability Exposure found in the package : "+ cve.webPackage.nameSP)
            print("Problem : "+cve.summary)
            print("ID : "+cve.ADVID)
            print("this package can be found here : "+cve.webPackage.pathSP)
            if(cve.severity == None):
                print("error")
            else:
                print("It is a "+cve.severity+" vulnerability")
                #c = CVSS3(cve.severity[0]['score'])
                #print("The CVSS is "+str(c.scores()[0]))
                #print("It is a "+c.severities()[0]+" Vulnerability")
            print("This package is currently installed in version : "+cve.webPackage.versionSP)

            if cve.fixed == "fixed":
                print("The package is fixed in his version : " + cve.version)
            else : 
                print("The last known affected package is "+cve.version)

            print("------------------------------------------------------------------------------------------")
        print("There are "+str(self.nbCVE) + " vulnerabilities on your website")

        

    #This fonction will test one package and give back the list of cve json or an empty array if no cve was found, this is the bruteforce way, meaning it will check every cve in the dir.
    async def testPackage(self,package,cveList):
        """ Test one package with all the cve available
            :param: package : package from the siteweb   
            :return: none
        """
        #print(self.listCVEDB)
        #Check every CVE on this package
        
        
        

        cvel = []

        for cve in cveList :
            if package.nameSP == cve.name:
                cvel.append(cve)
            else: 
                print("WTF")

        if len(cvel) > 0 :
            for cve in cvel:
                if cve.name == "core":
                    if cve.path == package.pathSP.split("node_modules")[-1]:
                        data = cve.data
                        jsondata = json.loads(data)
                        way = self.selectWay(jsondata)
                        for affected in jsondata["affected"]:
                            self.compareVersion(package,affected,way,i)
                else :
                    data = cve.data
                    jsondata = json.loads(data)
                    
                    for i in range(len(jsondata["affected"])):
                        way = self.selectWay(jsondata["affected"][i])
                        if jsondata["affected"][i]["package"]["name"] == package.nameSP:
                            self.compareVersion(package,jsondata,way,i)

    @lru_cache(maxsize = 100)
    async def checkPackages(self,sessionName,packages):
        """ Test every packages 
            :param: packages : list of packages from the siteweb   
            :return: none
        """
        print(sessionName+ " is analyzing ")
        
        for package in packages:
            if package.nameSP in self.cveByName:
                await self.testPackage(package,self.cveByName[package.nameSP])

        return self.listCVESite
            


              

