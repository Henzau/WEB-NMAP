import sqlite3
import json
import os

class CreateDB:
    def __init__(self,path):
        self.cveList = []
        self.nbcve = 0
        self.pathToMyDB = path

    def createConnection(self):
        """ create a database connection to the SQLite database
            specified by the self.pathToMyDB
        :param: none
        :return: Connection object or None
        """
        conn = None
        try:
            conn = sqlite3.connect(self.pathToMyDB)
        except Error as e:
            print(e)

        return conn

    def addTabDB(self):
        """ add a table to the DB and add the data in the "self.cveList" new table to the SQLite database
            specified by the self.pathToMyDB
        :param: none
        :return: none
        """
        conn = self.createConnection()
        if conn == None :
            print("an error as occured in the connection to the DB")
            return
        cursor = conn.cursor()
        
        #Uncomment if db is dead
        cursor.execute("""CREATE TABLE CVEs(
                   name TEXT,
                   path TEXT,
                   id TEXT,
                   JSON TEXT
            )""")
        all_cve = []
        for cve in self.cveList:
            path= cve["affected"][0]["package"]["name"]
            packageName = path.split("/")[-1]
            cveid = cve["id"]
            all_cve.append((packageName,path,cveid,json.dumps(cve)))
            
        cursor.executemany("INSERT INTO CVEs VALUES (?,?,?,?)",all_cve)
        conn.commit()

        cursor.execute("CREATE INDEX name_idx ON CVEs (name)")
        conn.commit()
        cursor.close()
        conn.close()

    def getInfo(self,name):
        """
        Query all rows in the packages table
        :param: none
        :return: none
        """
        conn = self.createConnection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM CVEs WHERE name = ?", (name,))
        cvel= cursor.fetchall()
        cursor.close()
        conn.close()
        
        
        return cvel
        

            


    def getRawDB(self,pathToRawDB):
        """ get every cve from the raw cve database
            specified by the pathToRawDB
        :param: pathToRawDB : path to the dir of the raw advisory database
        :return: none
        """
        for i, (root, dirs, filenames) in enumerate(os.walk(pathToRawDB)):
            for file in filenames:
                try:
                    f = open(root+"/"+file,encoding="utf8")
                except Exception:
                    print("An error as occured")
                    return
                data= json.load(f)
                if data["affected"][0]["package"]["ecosystem"] == "npm":
                    name = data["affected"][0]["package"]["name"]
                    versionI = ""
                    versionF = ""
                    versionD = ""
                    test = 0
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
                    self.nbcve +=1
                    self.cveList.append(data)
                
