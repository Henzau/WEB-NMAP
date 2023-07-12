from Analyze import Analyze  
from CreateDB import CreateDB 
from Extract import Extract
from Interface import Interface
import sys
import os
import git 
            

PATH_TO_DB = "../SQLITEDB/CVEDB.db"
PATH_TO_RAW_DB = "../../RawDB/advisories/github-reviewed"

if __name__=="__main__":
    """Analyze a website packages with the advisory database.
    """

    if(len(sys.argv)<2):
        print("\nusage : WebNmap.py [fonction]")
        print("-CreateDB     Create a SQLite Database and process the raw database \n| WebNmap.py CreateDB \n")
        print("-Extract      Extract every packages from a website \n| WebNmap.py Extract [path]  \n")
        print("-Analyze      Analyze the website packages and give a report \n| WebNmap.py Analyze [pathToJsonPackageLock]  \n")
    else: 
        if(sys.argv[1]=="Interface" and len(sys.argv)!=2 ):
            print("\nusage : WebNmap.py Interface")
        
        if(sys.argv[1]=="CreateDB" and len(sys.argv)!=2 ):
            print("\nusage : WebNmap.py CreateDB ")

    
        if(sys.argv[1]=="Extract" and len(sys.argv)!=3):
            print("\nusage : WebNmap.py Extract [path]")
            print("error expected:")
            print("-path                Path to the json-lock.json file of your website")
        
        if(sys.argv[1]=="Analyze" and len(sys.argv)!=3 ):
            print("\nusage : WebNmap.py Analyze [pathToJsonPackageLock]  ")
            print("error expected:")
            print("-pathToJsonPackageLock        Path to the json-lock.json file of your website")

        if(sys.argv[1]=="CreateDB" and len(sys.argv)==2 ):
            if os.path.exists(PATH_TO_DB):
                os.remove(PATH_TO_DB)
                print("The previous db was removed")
            db = CreateDB(PATH_TO_DB) #r"../SQLITEDB/CVEDB.db"
            db.getRawDB(PATH_TO_RAW_DB) # C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed
            db.addTabDB()
          
        if(sys.argv[1]=="Extract" and len(sys.argv)==3 ):
            site = Extract(sys.argv[2])
            site.getPackages()
            print("Number of packages extracted from your website : "+ str(site.nbPackage))

        if(sys.argv[1]=="Analyze" and len(sys.argv)==3 ):
            analyze = Analyze()
            site = Extract(sys.argv[2])
            site.getPackages()
            analyze.checkPackages(site.webPackagesList)
        
        if(sys.argv[1]=="UpdateDB" ):
            repo = git.Repo("../../RawDB/")
            o = repo.remotes.origin
            o.pull()

            if os.path.exists(PATH_TO_DB):
                os.remove(PATH_TO_DB)
                print("The previous db was removed")
            db = CreateDB(PATH_TO_DB) #r"../SQLITEDB/CVEDB.db"
            db.getRawDB(PATH_TO_RAW_DB) # C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed
            db.addTabDB()

        if(sys.argv[1]=="Interface" and len(sys.argv)==2 ):
            interface = Interface()
            interface.app()
            
