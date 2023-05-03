from Analyze import Analyze  
from CreateDB import CreateDB 
from Extract import Extract


if __name__ == '__main__':
    db = CreateDB(r"../SQLITEDB/test.db")
    site = Extract('../AppTest/package-lock.json')
    #db.getRawDB("C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed")
    #db.addTabDB()
    db.getInfo()
    site.getPackages()
    analyze = Analyze(db.cveFromDB)
    analyze.checkPackages(site.webPackagesList)
    #print(analyze.listCVESite)
    print(analyze.nbCVE)
