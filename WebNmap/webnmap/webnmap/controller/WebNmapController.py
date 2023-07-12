from gaimon.core.Route import GET, POST, ROLE
from gaimon.model.User import User
from gaimon.model.UserGroup import UserGroup
from gaimon.model.UserGroupPermission import UserGroupPermission, __GAIMON_ROLE__
from gaimon.model.PermissionType import PermissionType as PT

from sanic import response

import math, os, string, random, json, mimetypes


class WebNmapController:
	def __init__(self, application):
		from gaimon.core.AsyncApplication import AsyncApplication
		self.application: AsyncApplication = application
		self.resourcePath = self.application.resourcePath
		self.avatar = {}
		self.path = "/user/avatar/"
		self.client = None
	

	async def checkService(self):
		if self.client is None: 
			self.client = await self.application.getServiceClient("webnmap.webnmap.WebNmapService")

	@GET("/webnmap/test", role=["user"])
	async def test(self, request):
		await self.checkService()
		resulteco = await self.client.call('/eco', {'eco' : 'npm'})
		result = await self.client.call('/extract', {'file' : '/home/henzhau/WebNmap/webnmap/webnmap/service/WebNmapService/test/package-lock.json'})
		resultAnalyze = await self.client.call('/report', {})
		print("Specify Eco : " + str(resulteco))
		print("Extract packages : " + str(result))
		print("Analyze packages : "+ str(resultAnalyze))
		return response.json({'isSuccess': True, 'result': "test"}, ensure_ascii=False)


