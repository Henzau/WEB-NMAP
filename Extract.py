import json
from packaging import version

class Extract:
    def __init__(self,path):
        self.webPackagesList =[]  
        self.nbPackage = 0
        self.pathFile = path

    #camel case
    #PathFile to the file "package-lock.json"
    def getPackages(self):
        # Opening JSON file
        f = open(self.pathFile)
        data = json.load(f)
        
        # For each packages in the json file we add the package name and version in a list of tuple
        for i in data['packages']:
            self.nbPackage += 1
            version1 = data['packages'][i]['version']
            version1 =  version1.translate({ord(k): None for k in 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN?_-'})
            name = i[13:]
            self.webPackagesList.append((name,version1))
        # Closing file
        f.close()
         
"""
if __name__ == "__main__":
    info = Extract('./AppTest/package-lock.json')
    info.getPackages()

    print(info.webPackagesList)
    #ProcessRawDB("C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed","./NewDB")
"""