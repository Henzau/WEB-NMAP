from CVE import CVE
class ProccessCVE :

	def __init__(self,listCVE,nb):
        self.listCVESite = listCVE
        self.infosCVElist = []
        self.nbCVE = nb

    def ExtractCVEInfo(self):
        for cve in listCVESite:
            name = cve["affected"][0]["package"]["name"]
            version = cve["affected"][0]["package"]["name"]
            cveID = cve["aliases"][0]
