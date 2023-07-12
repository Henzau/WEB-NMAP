from gaimon.core.AsyncService import AsyncService
from gaimon.core.WebSocketManagement import WebSocketManagement
import gaimon.model as MainModel
import webnmap.webnmap.model as WebNModel

from webnmap.webnmap.service.WebNmapService.WebNmapHandler import WebNmapHandler
from webnmap.webnmap.service.WebNmapService.WebNmapManagement import WebNmapManagement


from typing import Dict, List
from asyncio import Task

import os, logging,json
from gaimon.util.CommonDBBounded import CommonDBBounded

from xerial.Vendor import Vendor
from xerial.AsyncDBSessionPool import AsyncDBSessionPool



class WebNmapService(AsyncService):
	def __init__(self, config: dict, namespace: str = ''):
		super().__init__(config, namespace)
	
		self.config = config
	#async def connect(self):
	#	self.cursor = CommonDBBounded(config)
	#	await self.cursor.connectDB()

		
	async def connect(self):
		self.isConnected = True
		self.config["DB"]["connectionNumber"]= self.config.get("DBConnectionNumber",2)
		self.pool = AsyncDBSessionPool(self.config["DB"])
		await self.pool.createConnection()
		print(f">>> Service.connect n={len(self.pool.pool)}")
		self.session = await self.pool.getSession()
		await AsyncDBSessionPool.browseModel(self.session, WebNModel)
		await AsyncDBSessionPool.browseModel(self.session, MainModel)
		await self.session.createTable()
		self.session.checkModelLinking()
		await self.sessionPool.release(self.session)
		print(f">>> Service.connected n={len(self.pool.pool)}")

		
	def setHandler(self):
		self.appendHandler(WebNmapHandler)
		self.resourcePath = self.config['resourcePath']
		self.managementMap: Dict[str, WebNmapManagement] = {}  # NOTE Not needed ?
		self.sendTask: List[Task] = []
		self.loadManagement()

	def initLoop(self, loop):
		self.loop = loop
		for management in self.managementMap.values():
			self.sendTask.append(loop.create_task(management.send()))


	async def prepareHandler(self, handler, request, parameter):
		print(f">>> Service.prepareHandler n={len(self.pool.pool)}")
		entity: str = None if parameter is None else parameter.get('entity', None)
		handler.session = await self.pool.getSession()
		if entity is not None and handler.session.vendor == Vendor.POSTGRESQL:
			handler.session.setSchema(entity)
		handler.management = await self.getManagement(parameter)

	async def getManagement(self, parameter: dict) -> WebNmapManagement:
		entity: str = None if parameter is None else parameter.get('entity', None)
		resourcePath = f"{self.resourcePath}/webnmap"
		if not os.path.isdir(resourcePath): os.makedirs(resourcePath)
		management = WebNmapManagement( self.resourcePath, entity)
		management.entity = entity
		management.checkPath()
		session = await self.pool.getSession()
		await management.prepare(session)
		await management.prepareAnalyze(session)
		#session = await self.pool.getSession()
		#if entity is not None and session.vendor == Vendor.POSTGRESQL:
		#	session.setSchema(entity)
		return management

	async def releaseHandler(self, handler : WebNmapHandler):
		#print(handler)
		#print(handler.management)
		await self.pool.release(handler.session)
		print(f">>> Service.releaseHandler n={len(self.pool.pool)}")
		#await self.releaseManagement(handler.management)

	async def releaseManagement(self, management: WebNmapManagement):
		#print(management)
		entity = management.entity
		#print(entity)
		self.managementMap[entity].append(management)
		

	async def prepare(self):
		pass

	async def load(self):
		await self.connect()
		

	async def close(self): # NOTE Not needed ?
		pass
#		for task in self.sendTask:
#			if not task.done():
#				task.cancel()

	def loadManagement(self):  # NOTE Not needed ?
		resourcePath = f"{self.resourcePath}/WebNmap"
		if not os.path.isdir(resourcePath): os.makedirs(resourcePath)
		for i in os.listdir(resourcePath):
			path = f"{resourcePath}/{i}"
			if i[:7] == 'Entity-' and os.path.isdir(path):
				entity = i[7:]
				logging.info(f">>> Loading management {entity}")
				management = WebNmapManagement(self.resourcePath, entity)
				management.checkPath()
				self.managementMap[entity] = management
