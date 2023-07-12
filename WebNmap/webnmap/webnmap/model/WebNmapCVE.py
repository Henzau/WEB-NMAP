class WebNmapCVE :
	def __init__(self,name,version,CVEID,severity,webPackage,ADVID,summary,fixed):
		self.name = name
		self.version = version
		self.CVEID = CVEID
		self.ADVID = ADVID
		self.severity = severity
		self.webPackage = webPackage
		self.summary = summary 
		self.fixed= fixed

	def printCVE(self):
		print((self.webPackage,self.name,self.version,self.severity))