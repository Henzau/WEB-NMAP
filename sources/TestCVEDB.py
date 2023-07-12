from xerial.PostgresDBSession import PostgresDBSession
from xerial.AsyncPostgresDBSession import AsyncPostgresDBSession
from xerial.Vendor import Vendor
from xerial.Record import Record
from xerial.StringColumn import StringColumn
from xerial.IntegerColumn import IntegerColumn
from xerial.JSONColumn import JSONColumn
from xerial.Children import Children
from CreateDB import CreateDB
from typing import List

import json, asyncio

with open('config.json') as fd :
	config = json.load(fd)

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

			

class EcoSystem (Record) :
	ecosystem = StringColumn(length=255, isIndex=True)
	def __init__(self, eco) :
		self.ecosystem = eco

RawDB = CreateDB("../PostgreSQL/CVE.db")
RawDB.getRawDB("../../RawDB/advisory-database/advisories/github-reviewed")
print(RawDB.nbcve)


IS_ASYNC = True

async def initialize(config) -> List[CVE]:
	session = AsyncPostgresDBSession(config)
	await session.connect()
	session.appendModel(CVE)
	session.appendModel(Affected)
	session.appendModel(EcoSystem)
	session.checkModelLinking()
	await session.createTable()

	ecoSystemList:List[EcoSystem] = await session.select(EcoSystem, "")
	ecoSystemMap = {i.ecosystem:i for i in ecoSystemList}
	insert = list()
	update = set()
	for cve in RawDB.cveList :
		affected = cve.get("affected", None)
		if affected is None : continue
		eco = affected[0]["package"].get("ecosystem", None)
		if eco is None : continue
		record = ecoSystemMap.get(eco, None)
		
		if record is not None and record not in update:
			continue
		#	#record.fromDict(eco)  We don't want to do anything here
		#	await session.update(record)  
		#	update.add(record)
		else :
			record = EcoSystem(eco)
			ecoSystemMap[record.ecosystem] = record
			insert.append(record)
	await session.insertMultiple(insert, True, True)
	for eco in ecoSystemList :
		print(eco.ecosystem)
	

	cveList:List[CVE] = await session.select(CVE, "")
	listID:List[str] = [cveDB.ADVid for cveDB in cveList]
	insertCVE = list()
	for raw in RawDB.cveList :
		cve1 = CVE(raw)
		if cve1.ADVid in listID :
			continue

		filtered = list()
		for affected in cve1.affected :   
			affected.eco = ecoSystemMap.get(affected.name, None)
			if affected.eco is not None :
				filtered.append(affected)
		cve1.affected = filtered
		insertCVE.append(cve1)
	
	# Cannot insert everything at once, it is too big for postgreSQL
	await session.insertMultiple(insertCVE[:2000], True, True)
	#await session.insertMultiple(insertCVE[3000:6000], True, True)
	#await session.insertMultiple(insertCVE[6000:9000], True, True)
	#await session.insertMultiple(insertCVE[9000:], True, True)

	# await session.insertMultiple([CVE(i) for i in RawDB.cveList], True, True)
	ecoSystemList = await session.select(EcoSystem, "WHERE ecosystem = 'PyPI' ")
	# print(ecoSystemList)
	# print(f"({','.join([str(i.id) for i in  ecoSystemList])})")
	clause = f"WHERE eco IN ({','.join([str(i.id) for i in  ecoSystemList])})"
	affectedList = await session.select(Affected, clause, isRelated=True)
	cveList = [i.cve for i in affectedList]
	
	return cveList


def applyData(fetched:List[CVE]) :
	print(f">>> Total {len(fetched)}")
	for cve in fetched:
		print(dir(cve))
		print(cve.name)*ù
		print(cve.ADVid)
		print(cve.path)
		print(cve.summary)
		print(cve.severity)
		print("end cve \n")

if IS_ASYNC :
	loop = asyncio.get_event_loop()
	result = loop.run_until_complete(initialize(config))
	applyData(result)

else :
	session = PostgresDBSession(config)
	session.connect()
	session.appendModel(CVE)
	session.createTable()	
	session.insertMultiple([CVE(i) for i in RawDB.cveList])
	test:List[CVE] = session.selectRaw(CVE,"WHERE name = 'json5'")
	applyData(test)
