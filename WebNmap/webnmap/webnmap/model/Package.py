from xerial.Record import Record
from xerial.StringColumn import StringColumn
from xerial.IntegerColumn import IntegerColumn

class Package(Record) :
	nameSP = StringColumn(length=254)
	pathSP = StringColumn(length=254)
	versionSP = StringColumn(length=254)
	sessionName = StringColumn(length=254,isIndex=True)

	def setPackage(self,name,path,version,sessionName):
		self.nameSP = name
		self.pathSP = path
		self.versionSP = version
		self.sessionName = sessionName
		return self

	def printInfoPackage(self):
		print("---------------------------------------------------------")
		print("Package : "+ self.nameSP )
		print("This package come from : "+ self.pathSP)
		print("This package is currently install in his version : "+ self.versionSP)
		print("---------------------------------------------------------")