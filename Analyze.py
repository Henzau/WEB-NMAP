import json
  
# Opening JSON file
f = open('./AppTest/package-lock.json')
  
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
print(packages)
  
# Closing file
f.close()