from xerial.StringColumn import StringColumn
from xerial.Record import Record

class EcoSystem (Record) :
	ecosystem = StringColumn(length=255, isIndex=True)
	def __init__(self, eco) :
		self.ecosystem = eco