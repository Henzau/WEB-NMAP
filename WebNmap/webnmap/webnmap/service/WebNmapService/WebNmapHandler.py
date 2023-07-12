from gaimon.core.Route import POST, SOCKET
from gaimon.service.notification.NotificationItem import NotificationItem
from gaimon.service.notification.NotificationType import NotificationType

from typing import List

import asyncio, traceback, json
from xerial.AsyncDBSessionBase import AsyncDBSessionBase



class WebNmapHandler:
    def __init__(self, service):
        from webnmap.webnmap.service.WebNmapService.WebNmapService import WebNmapService  # NOTE Why import are here ? idea : to not charged Service and Management before it is called 
        from webnmap.webnmap.service.WebNmapService.WebNmapManagement import WebNmapManagement
        self.service: WebNmapService = service
        self.management: WebNmapManagement = None
        self.session: AsyncDBSessionBase = None

    @POST('/benchmark')
    async def benchmark(self, request, parameter):
        return {'isSuccess': True}
    

    @POST('/eco')
    async def getEco(self, request, parameter):
        econame = parameter['eco']
        if econame is not None :
            await self.management.getEco(econame)
        return {'isSuccess': True}
    
  
    
    @POST('/extract')
    async def postFile(self, request, parameter):
        sessionName = parameter['sessionName']

        file = parameter['file']
        eco = parameter['eco']
        if file is not None and eco is not None :
            await self.management.getPackage(file,eco,self.session,sessionName)      

        return {'isSuccess': True}
    
    @POST('/report')
    async def getReport(self, request, parameter):
        sessionName = parameter['sessionName']

        await self.management.Analyze(self.session,sessionName)
        return {'isSuccess':True}
    
    @POST('/trigger')
    async def trigger(self,request,parameter):
        await self.management.trigger(self.session)
        #self.service.releaseHandler(self.management)  # Note sur if it works this way

        return {'isSuccess':True}
    
        
    



    ## NOTE NOTIFICATION ROUTES
    

    @POST('/register/uid')
    async def registerUID(self, request, parameter):
        registerUID = parameter['uid']
        socketID = parameter['socketID']
        for uid in registerUID:
            self.management.setSocketUID(socketID, uid)
        return {'isSuccess': True}

    @POST('/deregister/uid')
    async def deregisterUID(self, request, parameter):
        deregisterUID = parameter['uid']
        socketID = parameter['socketID']
        for uid in deregisterUID:
            self.management.removeSocketUID(socketID, uid)
        return {'isSuccess': True}

    @POST('/count')
    async def count(self, request, parameter):
        uid = parameter['uid']
        count = self.management.storage.count(uid)
        return {'isSuccess': True, 'count': count}

    @POST('/set')
    async def set(self, request, parameter):
        uid = parameter['uid']
        level = parameter['level']
        type = parameter['type']
        info = parameter['info']
        item = NotificationItem(uid, level, type, info)
        await self.management.append(NotificationType.INTERNAL, item)
        return {'isSuccess': True}

    @POST('/set/list')
    async def setList(self, request, parameter):
        for i in parameter['notificationList']:
            uid = i['uid']
            level = i['level']
            type = i['type']
            info = i['info']
            item = NotificationItem(uid, level, type, info)
            await self.management.append(NotificationType.INTERNAL, item)
        return {'isSuccess': True}

    @POST('/set/asRead')
    async def setAsRead(self, request, parameter):
        uid = parameter['uid']
        notificationIDList: List[int] = parameter['notificationIDList']
        self.management.setAsRead(NotificationType.INTERNAL, uid, notificationIDList)
        return {'isSuccess': True}

    @POST('/get/unread')
    async def getUnread(self, request, parameter):
        uid = parameter['uid']
        startTime = parameter['startTime']
        unread = self.management.getUnread(NotificationType.INTERNAL, uid, startTime)
        return {'isSuccess': True, 'notification': [i.toDict() for i in unread]}

    @POST('/get/page')
    async def getPage(self, request, parameter):
        uid = parameter['uid']
        page = parameter['page']
        perPage = parameter['perPage']
        storage = self.management.storageMap[NotificationType.INTERNAL]
        notificationList = storage.getPage(uid, page, perPage)
        return {'isSuccess': True, 'notification': [i.toDict() for i in notificationList]}

    @POST('/search')
    async def search(self, request, parameter):
        uid = parameter['uid']
        level = int(parameter['level'])
        date = parameter['notifyTime']
        info = parameter['info']
        storage = self.management.storageMap[NotificationType.INTERNAL]
        notificationList = storage.search(uid, level, date, info)
        return {'isSuccess': True, 'notification': [i.toDict() for i in notificationList]}

    @POST('/get/current')
    async def getCurrent(self, request, parameter):
        uid = parameter['uid']
        number = parameter['number']
        storage = self.management.storageMap[NotificationType.INTERNAL]
        notificationList = storage.getCurrent(uid, number)
        return {'isSuccess': True, 'notification': [i.toDict() for i in notificationList]}
