from Analyze import Analyze  
from CreateDB import CreateDB 
from Extract import Extract


if __name__ == '__main__':
    db = CreateDB(r"../SQLITEDB/test.db")
    site = Extract('../AppTest/package-lock.json')
    site.getPackages()
    print("Number of packages extracted from the website : "+ str(site.nbPackage))
    #db.getRawDB("C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed")
    #db.addTabDB()
    
    analyze = Analyze(db)
    analyze.checkPackages(site.webPackagesList)
    #print(analyze.listCVESite)
    print("Number of CVE found in the website :" + str(analyze.nbCVE))


