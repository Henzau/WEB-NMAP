from xerial.PostgresDBSession import PostgresDBSession
from xerial.AsyncPostgresDBSession import AsyncPostgresDBSession
from xerial.Vendor import Vendor
from xerial.Record import Record
from xerial.StringColumn import StringColumn
from xerial.JSONColumn import JSONColumn
from CreateDB import CreateDB
from typing import List

import json, asyncio

with open('config.json') as fd :
	config = json.load(fd)

class CVE(Record):
	name=StringColumn(length=254)
	CVEid=StringColumn(length=254)
	path = StringColumn(length=254)
	data = JSONColumn()

	def __init__(self, raw) :
		self.name = raw["affected"][0]["package"]["name"]
		self.path = raw["affected"][0]["package"]["name"].split("/")[-1]
		self.CVEid = raw["id"]
		self.data = raw


RawDB = CreateDB("../PostgreSQL/CVE.db")
RawDB.getRawDB("../../RawDB/advisory-database/advisories/github-reviewed")
all_cve = []

IS_ASYNC = True

async def initialize(config) -> List[CVE]:
	session = AsyncPostgresDBSession(config)
	await session.connect()
	session.appendModel(CVE)
	await session.createTable()
	await session.insertMultiple([CVE(i) for i in RawDB.cveList])
	return await session.selectRaw(CVE,"WHERE name = 'json5'")

def applyData(fetched:List[CVE]) :
	print(f">>> Total {len(fetched)}")
	for cve in fetched:
		print(cve.name)
		print(cve.path)

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
