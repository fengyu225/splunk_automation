import splunklib.client as client
import splunklib.results as results
import os
import sys
import time
import getpass
import pycurl
import StringIO
import feedparser
from multiprocessing import Lock, Process, Queue


password = getpass.getpass("Splunk Admin Password: ")


indexes_config = {}

search1_conn = client.connect(
        host = "sch3.splunk.ash0.coresys.tmcs",
#        host = "idx1.splunk.stg1.websys.tmcs",
        #host = "sch1.splunk.toolscap2.cloudsys.tmcs",
        port = 8089,
        username = "admin",
        password = password
    )


def run_query(conn, query, field_names, chk_time=0.2):
    """
    return a list of tuples, each tuple element is a value for a field name
    """
    job = conn.jobs.create(query)
    while not job.is_done():
        time.sleep(chk_time)
    rr = results.ResultsReader(job.results())
    v = []
    for result in rr:
        if isinstance(result,dict):
            v.append(tuple(result[field_name] for field_name in field_names))
    job.cancel()
    return v


def get_indexers(index):
    query = "| eventcount summarize=false index={0} | fields server | dedup server".format(index)
    r = run_query(search1_conn, query, ["server"])
    return [v[0] for v in r]


def get_index_usage(index, indexer, indexer_conn, result_q):
    query = """| dbinspect index={0} timeformat="%s" | fields state,id,rawSize, sizeOnDiskMB,earliestTime,latestTime | stats sum(rawSize) AS rawTotal, sum(sizeOnDiskMB) AS diskTotalinMB, min(earliestTime) as earliestTime, max(latestTime) as latestTime by state | convert ctime(earliestTime) as earliestTime | convert ctime(latestTime) as latestTime | eval rawTotalinMB=(rawTotal / 1024 / 1024) | fields - rawTotal | sort state""".format(index)
    r = run_query(
            indexer_conn, query,
            ['state','diskTotalinMB', 'earliestTime', 'latestTime', 'rawTotalinMB'],
            0.5
        )
    if len(r) == 0:
        result_q.put("On indexer {0}, nothing returned from dbinspect".format(indexer))
        return
    index_limits = get_config_value(indexer,index)
    if index_limits == None:
        result_q.put("index {0} is not setup on indexer {1}".format(index, indexer))
        return
    hot_warm_use = reduce(lambda x,y:x+y, [float(i[1]) for i in filter(lambda x:(x[0]=="hot" or x[0]=="warm"), r)], 0.0)
    hot_warm_usage = "{:2.3f} %".format(100*(float(hot_warm_use)/float(index_limits["homePath.maxDataSizeMB"])))
    cold_use = reduce(lambda x,y:x+y, [float(i[1]) for i in filter(lambda x:x[0]=="cold", r)], 0.0)
    cold_usage = "{:2.3f} %".format(100*(float(cold_use)/float(index_limits["coldPath.maxDataSizeMB"])))
    total_usage = "{:2.3f} %".format(100*((float(cold_use)+float(hot_warm_use))/(float(index_limits["homePath.maxDataSizeMB"])+float(index_limits["coldPath.maxDataSizeMB"]))))
    free = float(index_limits["homePath.maxDataSizeMB"])+float(index_limits["coldPath.maxDataSizeMB"])-float(cold_use)-float(hot_warm_use)
    free_hot_warm = float(index_limits["homePath.maxDataSizeMB"])-float(hot_warm_use)
    free_cold = float(index_limits["coldPath.maxDataSizeMB"])-float(cold_use)
    #total = float(index_limits["homePath.maxDataSizeMB"])+float(index_limits["coldPath.maxDataSizeMB"])
    #use = float(cold_use)+float(hot_warm_use)
    hot_r = filter(lambda x:x[0]=="hot", r)
    hot_time_range = "no hot bucket" if hot_r==[] else "{0} to {1}".format(hot_r[0][2],hot_r[0][3])
    warm_r = filter(lambda x:x[0]=="warm", r)
    warm_time_range = "no warm bucket" if warm_r==[] else "{0} to {1}".format(warm_r[0][2],warm_r[0][3])
    cold_r = filter(lambda x:x[0]=="cold", r)
    cold_time_range = "no cold bucket" if cold_r==[] else "{0} to {1}".format(cold_r[0][2],cold_r[0][3])
    earliest_time = cold_r[0][2] if len(cold_r)>0 else warm_r[0][2] if len(warm_r)>0 else hot_r[0][2] if len(hot_r)>0 else "-INF"
    s = """
On Indexer {0}:
Hot:                {1}
Warm:               {2}
Cold:               {3}
Hot+Warm Use:       {4} ({10} MB)
Free Hot+Warm (MB): {8}
Hot+Warm Alloc(MB): {12}
Cold Use:           {5} ({11} MB)
Free Cold (MB):     {9}
Total Use:          {6}
Free Total (MB):    {7}
""".format(indexer,hot_time_range,warm_time_range,cold_time_range,hot_warm_usage,cold_usage,total_usage,free,free_hot_warm,free_cold,float(hot_warm_use),float(cold_use),index_limits["homePath.maxDataSizeMB"])
    result_q.put(s)


def get_indexes_config(indexer,index):
    curl = pycurl.Curl()
    b = StringIO.StringIO()
    curl.setopt(
            pycurl.URL,
            """https://{0}:8089/servicesNS/nobody/system/properties/indexes/{1}""".format(indexer,index)
    )
    curl.setopt(pycurl.HTTPHEADER, ['Content-Type: application/json'])
    curl.setopt(pycurl.SSL_VERIFYPEER, False)
    curl.setopt(pycurl.SSL_VERIFYHOST, False)
    curl.setopt(pycurl.WRITEFUNCTION, b.write)
    curl.setopt(pycurl.USERPWD, "admin:{0}".format(password))
    r = curl.perform()
    return b.getvalue()


def get_config_value(indexer,index):
    field_names = [
            "homePath.maxDataSizeMB",
            "coldPath.maxDataSizeMB",
            "maxHotBuckets",
            "maxWarmDBCount",
            "maxTotalDataSizeMB",
            "maxHotIdleSecs",
            "maxDataSize"
    ]
    if indexer not in indexes_config:
        indexes_config[indexer] = {}
    if index not in indexes_config[indexer]:
        indexes_config[indexer][index] = get_indexes_config(indexer,index)
    d=feedparser.parse(indexes_config[indexer][index])
    r = {}
    for field_name in field_names:
        try:
            value = filter(lambda x:x['title']==field_name, d['entries'])[0]['content'][0]['value']
        except IndexError,e:
            print "index {0} is not set up on indexer {1}".format(index, indexer)
            return None
        r[field_name] = value
    r['maxDataSize'] = 10240 if r['maxDataSize']=="auto_high_volume" else r['maxDataSize']
    return r


if __name__ == "__main__":
    if len(sys.argv)>1:
        index = sys.argv[1]
        indexers = get_indexers(index)
        indexers_conn = map(
                lambda x:client.connect(
                    host=x,
                    port = 8089,
                    username = "admin",
                    password = password
                ),
                indexers
        )
        index_usage = []
        processes = []
        result_q = Queue()
        for indexer,indexer_conn in zip(indexers,indexers_conn):
            p = Process(target=get_index_usage, args=(index,indexer,indexer_conn,result_q))
            p.start()
            processes.append(p)
        for p in processes:
            p.join()
        while not result_q.empty():
            print result_q.get()
        sys.exit(0)
