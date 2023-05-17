class Package :

	def __init__(self,name,path,version):
		self.nameSP = name
		self.pathSP = path
		self.versionSP = version

	def printInfoPackage(self):
		print("---------------------------------------------------------")
		print("Package : "+ self.nameSP )
		print("This package come from : "+ self.pathSP)
		print("This package is currently install in his version : "+ self.versionSP)
		print("---------------------------------------------------------")
