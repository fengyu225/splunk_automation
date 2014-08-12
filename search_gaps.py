import splunklib.client as client
import splunklib.results as results
import time
import os
import sys
from get_ssh_conn import get_ssh_conn
import argparse
import getpass
from multiprocessing import Lock, Process, Queue, current_process


WORKER_NUM = 20 

env_q = Queue()
output_q = Queue()


def get_splunk_conn(host="sch3.splunk.ash0.coresys.tmcs",username="admin"):
    password = getpass.getpass("Splunk Admin Password: ")
    splunk_conn = client.connect(
            host = host,
    #        host = "idx1.splunk.stg1.websys.tmcs",
            #host = "sch1.splunk.toolscap2.cloudsys.tmcs",
            port = 8089,
            username = username,
            password = password
        )
    return splunk_conn


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


def set_env(f):
    def new_f(*f_args):
        while True:
            try:
                host = env_q.get(False)
            except:
                break
            try:
                res = f(host,*f_args)
            except Exception,e:
                output_q.put("Host {0} (pid: {2}):\n{1}\n".format(host,str(e),current_process().pid))
            else:
                output_q.put("Host {0} (pid: {2}):\n{1}\n".format(host,res,current_process().pid))
    return new_f


def send_file_to_host(host,files,dest_dir="/tmp"):
    with get_ssh_conn(host,"splunk") as ssh:
        sftp = ssh.open_sftp()
        for each_file in files:
            try:
                sftp.put(each_file,os.path.join(dest_dir,each_file))
            except:
                print "error sending file {0} to host {1}".format(each_file,host)
                continue
        sftp.close()


@set_env
def search_gaps(host,splunk_conn,timerange,gap_length):
    gap_length = str(gap_length)
    query = "| metasearch index=* host={0} {1} | top limit=0 index,source | dedup index,source | fields index,source".format(host,timerange)
    r = run_query(splunk_conn, query, ["index","source"])
    files = []
    for each_source in r:
        query = "| metasearch index={0} host={1} source={2} {3} | delta _time as t_diff p=1 | search t_diff<-{4} | top limit=0 _time,t_diff | fields _time,t_diff".format(each_source[0],host,each_source[1],timerange,gap_length)
        #print query
        res = run_query(splunk_conn,query,["_time","t_diff"])
        if not res:
            continue
        file_path = "splunk_log_gaps_{0}_{1}".format(host.replace(".","-"),each_source[1].replace("/","-"))
        with open(file_path,"w") as f:
            s = "\n".join([",".join(x) for x in res])
            f.write(s)
        files.append(file_path)
    send_file_to_host(host,files)
    return "success"


if __name__ == "__main__":
    options = argparse.ArgumentParser()
    options.add_argument("-f","--hosts",action="store",dest="hosts_f",required=True)
    options.add_argument("-t","--time_range",action="store",dest="tm_range",required=True)
    options.add_argument("-l","--gap_length",action="store",dest="gap_length",default="600",help="Default: 600 seconds")
    args = options.parse_args()
    splunk_conn = get_splunk_conn()
    process = []
    with open(args.hosts_f,"r") as hosts_f:
        for host in hosts_f:
            env_q.put(host.strip())
    for i in range(int(WORKER_NUM)):
        #res = search_gaps("apq1.tmol.stg1.websys.tmcs","earliest=07/01/2014:05:00:00 latest=07/07/2014:06:30:00")
        p = Process(target=search_gaps,args=(splunk_conn,args.tm_range.strip(),args.gap_length.strip()))
        p.start()
        process.append(p)
    for p in process:
        p.join()
    while not output_q.empty():
        print output_q.get()
    sys.exit(0)
