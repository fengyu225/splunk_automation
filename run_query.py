#!/usr/bin/python

import argparse
import getpass
import splunklib.client as client
import splunklib.results as results
import re
import time


options = argparse.ArgumentParser(description = "Script to Run Splunk Query")
options.add_argument("-s","--splunk-server", action="store",dest="host",required=True,help="Set Hostname of Splunk")
options.add_argument("-l","--port", action="store",dest="port",default=8089,help="Set Splunk Port",type=int)
options.add_argument("-u","--username", action="store",dest="username",default="admin",help="Set Login username")
options.add_argument("-q","--query", action="store",dest="query_f",required=True,help="Path to Splunk Query File")


args = options.parse_args()


passwd = getpass.getpass("Password for Splunk User {0} on {1}: ".format(args.username,args.host))


def run_query(conn, query, chk_time=0.2):
    """
    return a list of tuples, each tuple element is a value for a field name
    """
    job = conn.jobs.create(query)
    while not job.is_done():
        time.sleep(chk_time)
    rr = results.ResultsReader(job.results())
    v = []
    field_names = None
    for result in rr:
        if isinstance(result,dict):
            if field_names is None:
                field_names = result.keys()
            try:
                v.append(tuple(str(result[field_name]) for field_name in field_names))
            except:
                job.cancel()
                raise
    job.cancel()
    return v,field_names


if __name__ == "__main__":
    conn = client.connect(host=args.host,port=args.port,username=args.username,password=passwd)
    with open(args.query_f, "r") as query_f:
        for each_line in query_f:
            m = re.search("^\ *query\ *:\ *(?P<query>.*)", each_line)
            if m is None:
                continue
            query = m.group("query").strip()
            print query+"\n"
            r,field_names = run_query(conn,query)
            if r == []:
                continue
            print ",".join(field_names)
            for each_r in r:
                print ",".join(each_r)
            print "\n"
