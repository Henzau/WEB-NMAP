class CVE :
	def __init__(self,name,version,CVEID,severity,webPackage,ADVID,summary):
		self.name = name
		self.version = version
		self.CVEID = CVEID
		self.ADVID = ADVID
		self.severity = severity
		self.webPackage = webPackage
		self.summary = summary 

	def printCVE(self):
		print("ouais")
		print((self.webPackage,self.name,self.version,self.severity))