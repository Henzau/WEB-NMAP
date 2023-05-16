from xerial.PostgresDBSession import PostgresDBSession
from xerial.Vendor import Vendor
from xerial.Record import Record
from xerial.StringColumn import StringColumn
from xerial.JSONColumn import JSONColumn
from CreateDB import CreateDB


class CVE(Record):
	name=StringColumn(length=254)
	CVEid=StringColumn(length=254)
	path = StringColumn(length=254)
	data = JSONColumn()

config = {
	"user": "admin",
	"password" : "admin",
	"host" : "localhost",
	"port" : 5432,
	"database" : "cve",
 	"vendor" : Vendor.POSTGRESQL,
}
RawDB = CreateDB("../PostgreSQL/CVE.db")
RawDB.getRawDB("../../RawDB/advisory-database/advisories/github-reviewed")
all_cve = []
session = PostgresDBSession(config)
session.connect()
session.appendModel(CVE)
session.createTable()


for d in RawDB.cveList :
	
	cve = CVE().fromDict({
	"name" : d["affected"][0]["package"]["name"],
	"path" : d["affected"][0]["package"]["name"].split("/")[-1],
	"CVEid" : d["id"],
	"data" : d
	})
	all_cve.append(cve)
	session.insert(cve)
	break


# session.insertMultiple(all_cve)

test:List[CVE] = session.selectRaw(CVE,"WHERE name = 'json5'")
for cve in test:
	print(cve.name)
	print(cve.path)

