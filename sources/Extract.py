import json
from packaging import version

class Extract:
    def __init__(self,path):
        self.webPackagesList =[]  
        self.nbPackage = 0
        self.pathFile = path

    def getPackages(self):
        """ get every packages from a website
            :param: none 
            :return: none
        """
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
         
