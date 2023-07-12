import json
from webnmap.webnmap.model.Package import Package
from xerial.AsyncDBSessionBase import AsyncDBSessionBase


class Extract:     

    async def getPackages(self,file,eco,session,sessionName):
        """ get every packages from a website
            :param: none 
            :return: none
        """
        # Opening JSON file
        self.webPackagesList =[] 
        self.nbPackage = 0

        if eco == "npm":

            f = open(file)
            data = json.load(f)
            
            # For each packages in the json file we add the package name and version in a list of tuple
            for i in data['packages']:
                self.nbPackage += 1
                version1 = data['packages'][i]['version']
                version1 =  version1.translate({ord(k): None for k in 'azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN?_-'})
                name = i.split("/")[-1]
                packageWeb = Package().setPackage(name,i,version1,sessionName)
                
                #print(packageWeb.toDict())

                self.webPackagesList.append(packageWeb)
            # Closing file
            
            self.webPackagesList = self.webPackagesList[1:]
            f.close()
            await self.insertPackages(session)
    
    async def insertPackages(self,session:AsyncDBSessionBase):
       await session.insertMultiple(self.webPackagesList,True,False)

    