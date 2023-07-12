from xerial.Record import Record
from xerial.StringColumn import StringColumn
from xerial.JSONColumn import JSONColumn
from xerial.Children import Children
from webnmap.webnmap.model.Affected import Affected
import json

class CVE(Record):
	name=StringColumn(length=254, isIndex=True)
	CVEid=StringColumn(length=254)
	ADVid = StringColumn(length=254)
	path = StringColumn(length=254)
	summary = StringColumn(length=254)
	#details = StringColumn(length=254)
	data = JSONColumn()
	affected = Children("Affected.id")
	# affected = IntegerColumn(foreignKey="Affected.id")
	severity = StringColumn(length=20)

	def __init__(self, raw) :
		self.name = raw["affected"][0]["package"]["name"].split("/")[-1]
		self.path = raw["affected"][0]["package"]["name"]
		self.CVEid = raw.get("aliases"[0],"None")
		try :
			self.CVEid = raw["aliases"][0]
		except:
			try : 
				self.CVEid = raw["database_specific"]["cwe_ids"][0]
			except :
				self.CVEid = "No aliases given"

		self.ADVid = raw["id"]
		self.data = json.dumps(raw)
		try :
			self.summary = raw["summary"]
		except:
			self.summary = "No summary given"
		self.severity = raw["database_specific"]["severity"]
		#self.details = raw["details"]
		self.affected = []
		for i in raw["affected"] :
			self.affected.append(Affected(i))