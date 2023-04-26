import json
import os
import shutil # Copy file


#camel case

def GetPackages(PathFile):
    # Opening JSON file
    f = open(PathFile)
  
    # returns JSON object as 
    # a dictionary
    data = json.load(f)
    packages = []
  
    # Iterating through the json
    # list
    for i in data['packages']:
        version = data['packages'][i]['version']
        name = i[13:]
        packages.append((name,version))

    #we have a tuple with the name of the packages and the version of the packages downloaded  
    # Closing file
    f.close()
    return packages


#PathDir -> path to the rawDB
#PathNewDB -> path where to save the new DATABASE
def ProcessRawDB(PathDir,PathNewDB):
    count =0
    for i, (root, dirs, filenames) in enumerate(os.walk(PathDir)):
        
            for file in filenames:
                try:
                    f = open(root+'/'+file,encoding="utf8")
                except Exception:
                    print("An error as occured")
                data= json.load(f)
                name = data["affected"][0]["package"]["name"]
                f.close()
                if ':' in name :
                    name = name.split(":")[0]
                if not os.path.exists(PathNewDB+'/'+name):
                    os.makedirs(PathNewDB+'/'+name)
                shutil.copy(root+'/'+file,PathNewDB+'/'+name)
                #print( data["affected"][0]["package"]["name"])

    


if __name__ == "__main__":
    info = GetPackages('./AppTest/package-lock.json')
    print(info[5])
    #ProcessRawDB("C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed","./NewDB")
    nbCVE=0
    for p in info:
        
        if p[0] in os.listdir("./NewDB") :
            nbCVE+=1
            print("oui")

    print(nbCVE)