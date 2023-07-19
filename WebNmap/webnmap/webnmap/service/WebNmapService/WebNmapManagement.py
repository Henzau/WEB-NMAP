from gaimon.core.WebSocketManagement import WebSocketManagement
from gaimon.core.WebSocketMode import WebSocketMode
from gaimon.service.notification.NotificationStorage import NotificationStorage
from gaimon.service.notification.NotificationItem import NotificationItem
from gaimon.service.notification.NotificationType import NotificationType
from webnmap.webnmap.model.Extract import Extract
from webnmap.webnmap.service.WebNmapService.Analyze import Analyze
from webnmap.webnmap.model.Package import Package
from webnmap.webnmap.model.Affected import Affected
from webnmap.webnmap.model.EcoSystem import EcoSystem

from xerial.AsyncDBSessionBase import AsyncDBSessionBase


from typing import List, Dict
from sanic import Websocket
import asyncio, logging, traceback, json, os


from gaimon.util.CommonDBBounded import CommonDBBounded




class WebNmapManagement:
	def __init__(self, resourcePath: str, entity: str, sleepTime: int = 300):
		self.eco = None
		self.packagesListFile = None
		self.webObject = {}
		self.entity = entity  # NOTE Not needed ?
		self.resourcePath = f'{resourcePath}/notification/Entity-{entity}/' # NOTE Not needed ?
		self.sleepTime = sleepTime  # NOTE Not needed ?
		self.socketMap: Dict[int, List[Websocket]] = {} # NOTE Not needed ?
		self.socketIDMap: Dict[int, Websocket] = {} # NOTE Not needed ?
		self.socketID = 1 # NOTE Not needed ?
		self.webObject = Extract()


	async def prepare(self):
		#self.webPackageList:List[Package] = await session.select(Package,"")
		self.webPackageList:List[Package] = []

		self.webPackageID = {webPackage.id for webPackage in self.webPackageList}

		self.webPackageSessionNameDict = {}
		for webPackage in self.webPackageList:
			if webPackage.sessionName not in self.webPackageSessionNameDict:
				self.webPackageSessionNameDict[webPackage.sessionName] = []
			self.webPackageSessionNameDict[webPackage.sessionName].append(webPackage)
	
	async def prepareAnalyze(self, session: AsyncDBSessionBase):
		
		ecoSystemList:List[EcoSystem] = await session.select(EcoSystem, "WHERE ecosystem = 'npm' ")
		affectedList:List[Affected] = []
		if len(ecoSystemList):
			clause = f"WHERE eco IN ({','.join([str(i.id) for i in  ecoSystemList])})"
			affectedList = await session.select(Affected, clause, isRelated=True)
		self.cveList = [i.cve for i in affectedList]

		self.CveId = {}
		self.cveByName = {}
		for cve in self.cveList:
			if cve.ADVid not in self.CveId :
				self.CveId[cve.ADVid] = cve.ADVid
				if cve.name not in self.cveByName:
					self.cveByName[cve.name] = []
				self.cveByName[cve.name].append(cve)
		self.analyzer = Analyze(self.cveByName)
		self.analyzeAnswer= {}


	async def getEco(self,eco):
		self.eco = eco
		#print("Eco selected : "+self.eco)

	async def getPackage(self,file,eco,sessionName):
		self.packagesListFile = file
		#print("File system acquired ")
		await self.createPackagesList(eco,sessionName)
	
	async def createPackagesList(self,eco,sessionName):
		if self.packagesListFile is None : return
		if eco is None : return
		if sessionName not in self.webPackageSessionNameDict:
			self.webPackageSessionNameDict[sessionName] = await self.webObject.getPackages(self.packagesListFile,eco,sessionName)
		#print("Object created")
	
	async def analyze(self,session,sessionName):

		if self.analyzer.eco is None : self.analyzer.eco = self.eco
		
		webPackagesList =[]
		if sessionName in self.webPackageSessionNameDict:
			webPackagesList = self.webPackageSessionNameDict[sessionName]
		else: 
			await self.prepare(session)
			if sessionName in self.webPackageSessionNameDict:
				webPackagesList = self.webPackageSessionNameDict[sessionName]

		if len(webPackagesList) == 0 : return		
		#print("Analyzing packages")
		#print("nb webpackage : " + str(len(webPackagesList)))
	
		if sessionName not in self.analyzeAnswer :
				self.analyzeAnswer[sessionName] = await self.analyzer.checkPackages(webPackagesList)
				#print("create new analyzing for client : "+str(sessionName))
		else :
				#print("result already known in map for client : "+str(sessionName))
				pass

		#print(len(self.analyzeAnswer[sessionName]))
		#self.analyzer.reportPrint()
	
	async def trigger(self,session):
		await self.prepare(session)
		await self.prepareAnalyze(session)
		



	
	def setSocket(self, uid: int, socket: Websocket):
		socketList = self.socketMap.get(uid, [])
		if len(socketList) == 0: self.socketMap[uid] = socketList
		if hasattr(socket, 'uidList'):
			socket.uidList.append(uid)
		else:
			socket.uidList = [uid]
		socketList.append(socket)

	def removeSocket(self, uid: int, socket: Websocket):
		socketList = self.socketMap.get(uid, None)
		if socketList is None: return
		if hasattr(socket, 'uidList'):
			if uid in socket.uidList:
				socket.uidList.remove(uid)
		if socket in socketList:
			socketList.remove(socket)

	def appendSocket(self, socket: Websocket) -> int:
		socketID = self.socketID
		self.socketID += 1
		self.socketIDMap[socketID] = socket
		return socketID

	def setSocketUID(self, socketID: int, uid: int):
		socket = self.socketIDMap.get(socketID, None)
		if socket is None: return False
		self.setSocket(uid, socket)
		return True

	def removeSocketUID(self, socketID: int, uid: int):
		socket = self.socketIDMap.get(socketID, None)
		if socket is None: return False
		self.removeSocket(uid, socket)
		del self.socketIDMap[socketID]
		return True

	async def createReceiveTask(self, socket: Websocket):
		while True:
			if WebSocketManagement.isClose(socket):
				self.removeSocket(socket)
			received = await socket.recv()
			data = json.loads(received)
			uid = data['uid']
			socketList = self.socketMap.get(uid, [])
			if len(socketList) == 0: self.socketMap[uid] = socketList
			socketList.append(socket)

	def removeSocket(self, uid: int, socket: Websocket):
		if hasattr(socket, 'uidList'):
			uidList = socket.uidList
			for uid in uidList:
				if uid not in self.socketMap:
					if socket in self.socketMap[uid]:
						self.socketMap[uid].remove(socket)

		if uid not in self.socketMap:
			if socket in self.socketMap[uid]:
				self.socketMap[uid].remove(socket)

	def checkPath(self):
		if not os.path.isdir(self.resourcePath):
			os.makedirs(self.resourcePath)
		for i in NotificationType:
			path = f'{self.resourcePath}/{i.value}'
			if not os.path.isdir(path):
				os.makedirs(path)

	def loadUnsent(self):
		self.unsent = []
		for storage in self.storageMap.values():
			self.unsent.extend(storage.getUnsent())

	async def append(self, type: NotificationType, item: NotificationItem):
		await self.sendToPush(type, item)
		self.storageMap[type].append([item])
		self.unsent.append(item)
		if item.uid not in self.unread[type]:
			unread = []
			self.unread[type][item.uid] = unread
		else:
			unread = self.unread[type][item.uid]

		if item.uid not in self.unreadMap:
			unreadMap = {}
			self.unreadMap[type][item.uid] = unreadMap
		else:
			unreadMap = self.unreadMap[type][item.uid]
		unreadMap[item.ID] = item
		unread.append(item)

	async def sendToPush(self, type: NotificationType, item: NotificationItem):
		if type != NotificationType.INTERNAL: return False
		socketList = self.socketMap.get(item.uid, None)
		if socketList is None: return False
		alive = []
		result = {
			'mode': WebSocketMode.PUSH.value,
			'route': '/notification',
			'isSuccess': True,
		}
		for socket in socketList:
			if not WebSocketManagement.isClose(socket):
				result['result'] = item.toDict()
				await socket.send(json.dumps(result))
				alive.append(socket)
			else:
				self.removeSocket(item.uid, socket)
				print(">>> Socket is closed")
		self.socketMap[item.uid] = alive
		return True

	def getUnread(self,
					type: NotificationType,
					uid: int,
					startTime: float) -> List[NotificationItem]:
		if uid not in self.unread[type]:
			unread = self.storageMap[type].getUnread(uid)
			self.unread[type][uid] = unread
			self.unreadMap[type][uid] = {i.ID: i for i in unread}
		else:
			unread = self.unread[type][uid]
		if startTime < 0 or len(unread) == 0:
			return unread
		else:
			return WebNmapManagement.getByStartTime(unread, startTime)

	@staticmethod
	def getByStartTime(notificationList: List[NotificationItem],
						startTime: float) -> List[NotificationItem]:
		n = len(notificationList)
		if n == 0: return []
		last = notificationList[-1]
		if last.notifyTime < startTime: return []
		low = 0
		high = n - 1
		i = 0
		while low <= high:
			i = (high + low) // 2
			notification: NotificationItem = notificationList[i]
			if notification.notifyTime < startTime:
				low = i + 1
			elif notification.notifyTime > startTime:
				high = i - 1
			else:
				break
		return notificationList[i:]

	def setAsRead(self, type: NotificationType, uid: int, notificationIDList: List[int]):
		unreadMap = self.unreadMap[type].get(uid, {})
		readList = []
		unreadList = self.unread[type].get(uid, [])
		for notificationID in notificationIDList:
			if notificationID in unreadMap:
				readList.append(unreadMap[notificationID])
				del unreadMap[notificationID]
		self.unread[type][uid] = sorted(
			list(unreadMap.values()),
			key=lambda x: x.notifyTime
		)
		self.storageMap[type].setAsRead(uid, readList, unreadList)

	async def send(self):
		while True:
			current = self.unsent[:]
			self.unsent = []
			unsent = []
			sent = {i.value: [] for i in NotificationType}
			for item in current:
				try:
					await item.send()
					sent[item.type].append(item)
				except:
					logging.error(traceback.format_exc())
					unsent.append(item)
			for type, notificationList in sent.items():
				self.storageMap[type].setAsSent(notificationList)
			self.unsent.extend(unsent)
			await asyncio.sleep(self.sleepTime)
