from xerial.Record import Record
from xerial.StringColumn import StringColumn
from xerial.IntegerColumn import IntegerColumn



class Affected (Record) :
	__is_mapper__ = True
	cve = IntegerColumn(foreignKey="CVE.id")
	eco = IntegerColumn(foreignKey="EcoSystem.id")
	name = StringColumn(length=254)
	versionIntroduced= StringColumn(length=254)
	versionFixed =  StringColumn(length=254)
	versionLastAffected = StringColumn(length=254)
	def __init__(self, affected) :
		self.name = affected["package"]["ecosystem"]
		#It depends on the cve : need to make try with for each version : last_affected see test in Analyze "selectWay"
		try :
			self.versionFixed = affected["database_specific"]["last_known_affected_version_range"][0]
		except :
			try :
				self.versionIntroduced = affected["ranges"][0]["events"][0]["introduced"]
				if len(affected["ranges"][0]["events"]) > 1 : 
					try : 
						self.versionFixed = affected["ranges"][0]["events"][1]["fixed"]
					except:
						self.versionLastAffected = affected["ranges"][0]["events"][1]["last_affected"][0]
			except :
				self.versionFixed = affected["versions"][0]