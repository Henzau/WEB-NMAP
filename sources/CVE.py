class CVE :
	def __init__(self,name,version,CVEID,severity,WebPackage,ADVID):
		self.name = name
		self.version = version
		self.CVEID = CVEID
		self.ADVID = ADVID
		self.severity = severity
		self.WebPackage = WebPackage

	def printCVE(self):
		print("ouais")
		print((self.WebPackage,self.name,self.version,self.severity))