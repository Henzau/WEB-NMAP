from gaimon.core.AsyncServiceClient import AsyncServiceClient
from gaimon.service.notification.NotificationLevel import NotificationLevel
from gaimon.service.notification.NotificationType import NotificationType

from datetime import datetime


class WebNmapCreator:
	def __init__(self, config):
		self.config = config
		self.client = AsyncServiceClient(config)

	async def createWebNmap(
		self,
		level: NotificationLevel,
		uid: int,
		n: int,
		type: NotificationType,
		message: str
	):
		for i in range(n):
			data = {
				'level': level,
				'uid': uid,
				'type': type,
				'info': {
					'message': message
				}
			}
			result = await self.client.call('/set', data)
			print(f"Send notification {i}", result)


if __name__ == '__main__':
	import json, asyncio
	with open('/etc/gaimon/WebNmapService.json', encoding="utf-8") as fd:
		config = json.load(fd)

	creator = WebNmapCreator(config)
	asyncio.run(
		creator.createWebNmap(
			NotificationLevel.INFO,
			1,
			1,
			NotificationType.INTERNAL,
			f"This is a fake notification for test @{datetime.now()}."
		)
	)
