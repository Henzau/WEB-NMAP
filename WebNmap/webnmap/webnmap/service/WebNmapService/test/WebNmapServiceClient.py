from gaimon.core.AsyncServiceClient import AsyncServiceClient

import json, asyncio,time

class WebNmapServiceClient:
    def __init__(self, config) :
        self.config = config
        self.client = AsyncServiceClient(config)
        self.error = 0
    
    async def call(self,n,error) :
        #resulteco = await self.client.call('/eco', {'eco' : 'npm'})
        sessionName = str(n)
        
        try:
            result = await self.client.call('/extract', {'file' : '/home/henzhau/WebNmap/webnmap/webnmap/service/WebNmapService/test/package-lock.json','eco':'npm','sessionName':sessionName})
            resultReport = await self.client.call('/report',{'sessionName': sessionName})
        except:
            error += 1
        return error
        
        #resultAnalyze = await self.client.call('/report', {})
        #print("Specify Eco : " + str(resulteco))
        #print("Extract packages : " + str(result))
        #print("Analyze packages : "+ str(resultAnalyze))


async def get_benchmark_results(client: WebNmapServiceClient,M,n):
    error = 0
    call = [client.call(n,error) for i in range(0,M)]
    results = await asyncio.gather(*call)
    print("numbers of error on client "+str(n) + " : " +str(sum(results)))
    
    
    return results

def aggregate_results(clients: list,M,n):
    results= []
    req=0
    n = n-(n-1)
    for client in clients :
        results.append( asyncio.run(get_benchmark_results(client,M,n)))
        req+=M
        n+=1
    return req

if __name__ == '__main__' :
    with open('/etc/gaimon/extension/webnmap/WebNmapService.json') as fd :
        config = json.load(fd)
    
    N = 1
    M = 200
    clientList = [WebNmapServiceClient(config) for i in range(N)]
    begin = time.time()
    req = aggregate_results(clientList,M, N)
    end = time.time()
    timeend= end - begin
    print("We have done "+str(req)+" req in "+str(timeend))


