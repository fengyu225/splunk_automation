#!/usr/bin/python

import sys
import getpass
import argparse
import pycurl
import urllib
import StringIO
import feedparser
import re
from lxml import etree
import splunklib.client as client
from multiprocessing import Process,Queue,current_process


options = argparse.ArgumentParser(description = "Script to Add/Delete/Update Configuration Files Stanza on Remote Host")
options.add_argument("-f","--hosts", action="store",dest="hosts_f",required=True,help="Path to File of List of Hosts to be Configured")
options.add_argument("-u","--admin_username", action="store",dest="admin_username",default="admin",help="Set Admin Login username")
options.add_argument("-c","--conf",action="store",dest="conf_f",default=None,help="Path to File of Configuration Modification Details")
options.add_argument("-t","--conf_name",action="store",dest="conf_name",required=True,help="Configuration File Name on Remote Hosts: inputs/outputs/server/props/transforms/indexes")
options.add_argument("-s","--stanza_name",action="store",dest="stanza_name",default=None,help="Stanza Name for Inq/delete")
options.add_argument("-m","--mode",action="store",dest="mode",required=True,help="""Action on Configuration Files: add/delete/update/inq""")
options.add_argument("-r","--restart",action="store",dest="restart",default="0",help="Restart Splunk")
options.add_argument("-w","--worker_num",action="store",dest="worker_num",default="20",help="Number Of Process Running in Parallel")
options.add_argument("-i","--is_re",action="store",dest="is_re",default="0",help="Use Regex set in stanza_name to Search for Stanzas")


args = options.parse_args()


password = getpass.getpass("Splunk Admin Password: ")


xml_ns = {
        'default': 'http://www.w3.org/2005/Atom',
        's': 'http://dev.splunk.com/ns/rest',
        'opensearch': 'http://a9.com/-/spec/opensearch/1.1/'
        }


STATUS_CODES = {
            "200":"Operation successful.",
            "201":"Object created successfully.",
            "204":"Successful, but no content was returned.",
            "401":"Authentication failure: must pass valid credentials with request. Session may have timed out.",
            "402":"The Splunk license in use has disabled this feature.",
            "403":"Insufficient permissions to view/edit/create/disable/delete.",
            "404":"Object does not exist.",
            "405":"Method Not Allowed (e.g. supports GET but not POST)",
            "409":"Request error: this operation is invalid for this item. See response body for explanation.",
            "500":"Internal server error. See response body for explanation.",
            "503":"This feature has been disabled in Splunk configuration files."
        }


input_q = Queue()
output_q = Queue()
WORKER_NUM = args.worker_num


def reload_indexes(forwarder):
    url = """https://{0}:8089/services/data/indexes/_reload""".format(forwarder)
    return perform_curl(url)


def reload_monitoring(forwarder):
    url = """https://{0}:8089/services/data/inputs/monitor/_reload""".format(forwarder)
    return perform_curl(url)


def restart_splunk(forwarder):
    if args.conf_name == "inputs":
        r = reload_monitoring(forwarder)
        if not (r[0] == "200" or r[0] == "201" or r[0] == "204"):
            raise Exception("Reload Monitoring Error: {0}".format(STATUS_CODES[r[0]]))
    elif args.conf_name == "indexes":
        r = reload_indexes(forwarder)
        if not (r[0] == "200" or r[0] == "201" or r[0] == "204"):
            raise Exception("Reload Indexes Error: {0}".format(STATUS_CODES[r[0]]))
    else:
        conn = client.connect(host=forwarder,port=8089,username=args.admin_username,password=password)
        r = conn.restart(timeout=180)
        if r["status"] != 200:
            raise Exception("Restart Failed")


def set_forwarder(f):
    def new_f(*f_args):
        while True:
            try:
                forwarder = input_q.get(False)
            except:
                break
            try:
                print "PID: {0}".format(current_process().pid)
                res = f(forwarder,*f_args)
                if args.restart == "1":
                    restart_splunk(forwarder)
            except Exception,e:
                output_q.put("On Host {0}:\n{1}\n".format(forwarder,str(e)))
            else:
                output_q.put("On Host {0}:\n{1}\n".format(forwarder,res))
    return new_f


def perform_curl(url,request_cmd=None,data=None):
    curl = pycurl.Curl()
    b = StringIO.StringIO()
    curl.setopt(pycurl.URL,url)
    curl.setopt(pycurl.CONNECTTIMEOUT, 15)
    curl.setopt(pycurl.TIMEOUT, 15)
    curl.setopt(pycurl.SSL_VERIFYPEER, False)
    curl.setopt(pycurl.SSL_VERIFYHOST, False)
    curl.setopt(pycurl.USERPWD, "{0}:{1}".format(args.admin_username,password))
    if request_cmd is not None:
        curl.setopt(pycurl.CUSTOMREQUEST, request_cmd)
    if data is not None:
        data = urllib.urlencode(data)
        curl.setopt(pycurl.POSTFIELDS, data)
    curl.setopt(pycurl.WRITEFUNCTION, b.write)
    try:
        r = curl.perform()
    except:
        raise Exception("status: {0}".format(STATUS_CODES[str(curl.getinfo(pycurl.HTTP_CODE))]))
    else:
        if str(curl.getinfo(pycurl.HTTP_CODE)) == "200" or str(curl.getinfo(pycurl.HTTP_CODE)) == "201" or str(curl.getinfo(pycurl.HTTP_CODE)) == "204":
            return str(curl.getinfo(pycurl.HTTP_CODE)),b.getvalue()
        raise Exception(url+"\n"+STATUS_CODES[str(curl.getinfo(pycurl.HTTP_CODE))]+"\n"+b.getvalue())
    finally:
        if curl is not None:
            curl.close()


def reload_conf(forwarder,config_type):
    url = "https://{0}:8089/servicesNS/nobody/system/configs/conf-{1}/_reload".format(forwarder,urllib.quote(config_type,""))
    try:
        perform_curl(url)
    except:
        raise


@set_forwarder
def add_stanza(forwarder,config_type):
    content_dict = read_conf_change()
    res = ""
    for each_stanza in content_dict:
        d = content_dict[each_stanza]
        d["name"] = each_stanza
        r = add_single_stanza(forwarder,config_type,d)
        res += "{0}\n".format(STATUS_CODES[r[0]])
    return res


def add_single_stanza(forwarder,config_type,content_dict):
    reload_conf(forwarder,config_type)
    url = """https://{0}:8089/servicesNS/nobody/system/configs/conf-{1}""".format(forwarder,urllib.quote(config_type,""))
    return perform_curl(url,data=content_dict)


@set_forwarder
def update_stanza(forwarder,config_type):
    content_dict = read_conf_change()
    res = ""
    for each_stanza in content_dict:
        c = update_single_stanza(forwarder,config_type,each_stanza,content_dict[each_stanza])[0]
        res += "{0}\n".format(STATUS_CODES[c])
    return res


def update_single_stanza(forwarder,config_type,stanza_name,content_dict):
    reload_conf(forwarder,config_type)
    url = """https://{0}:8089/servicesNS/nobody/system/configs/conf-{1}/{2}""".format(forwarder,urllib.quote(config_type,""),urllib.quote(stanza_name,""))
    return perform_curl(url,data=content_dict)


@set_forwarder
def delete_stanza_by_name(forwarder,config_type,stanza_name):
    reload_conf(forwarder,config_type)
    url = """https://{0}:8089/servicesNS/nobody/system/configs/conf-{1}/{2}""".format(forwarder,urllib.quote(config_type,""),urllib.quote(stanza_name,""))
    r = perform_curl(url,request_cmd="DELETE")
    return "{0}\n".format(STATUS_CODES[r[0]])


def get_config_xml(forwarder,config_type,stanza_name=None):
    reload_conf(forwarder,config_type)
    #url = """https://{0}:8089/servicesNS/nobody/system/configs/conf-{1}""".format(forwarder,urllib.quote(config_type,""))
    if stanza_name is None:
        url = """https://{0}:8089/servicesNS/nobody/search/properties/{1}""".format(forwarder,urllib.quote(config_type,""))
    else:
        url = """https://{0}:8089/servicesNS/nobody/search/properties/{1}/{2}""".format(forwarder,urllib.quote(config_type,""),urllib.quote(stanza_name,""))
    return perform_curl(url)


def get_stanza_content_by_name(xml_str,stanza_name):
    try:
        tree = etree.fromstring(xml_str)
    except:
        #print xml_str
        raise
    stanza_root = None
    try:
        stanza_root = tree.xpath("//default:title[text()='{0}']".format(stanza_name), namespaces=xml_ns)[0].getparent()
    except IndexError, e:
        raise Exception("No stanza with name {0} in config file {1}.conf".format(stanza_name,config_type))
    entries = stanza_root.xpath(".//default:entry", namespaces=xml_ns)
    titles = [entry.xpath(".//default:title", namespaces=xml_ns)[0].text for entry in entries]
    contents = [entry.xpath(".//default:content", namespaces=xml_ns)[0].text for entry in entries]
    return {key:("" if val is None else val) for (key,val) in zip(titles,contents) if not key.startswith("_")}


def get_all_stanza_names(xml_str):
    try:
        tree = etree.fromstring(xml_str)
    except:
        #print xml_str
        raise
    stanza_nodes = None
    try:
        stanza_nodes = tree.xpath("//default:entry/default:title", namespaces=xml_ns)
    except IndexError, e:
        raise Exception("XML format error: {0}.conf".format(config_type))
    return [s.text for s in stanza_nodes]


@set_forwarder
def display_conf(forwarder,stanza_name=None,is_re="0"):
    t = get_config_xml(forwarder, args.conf_name)
    if not (t[0] == "200" or t[0] == "201" or t[0] == "204"):
        return "Configuration File {1}.conf doesn't exists:\n".format(forwarder,args.conf_name)
    xml_str = t[1]
    l = get_all_stanza_names(xml_str)
    if stanza_name is None:
        return "Configuration File {1}.conf Contains Stanzas:\n".format(forwarder,args.conf_name)+"\n".join(l)
    else:
        if is_re=="1":
            filter_r = filter(lambda x:re.search("(?P<stanza_name>{0})".format(stanza_name),x) is not None,l)
        else:
            filter_r = filter(lambda x:x==stanza_name,l)
        if filter_r == []:
            return "Configuration File {1} doesn't Contain Stanza {2}".format(forwarder,args.conf_name,stanza_name)
        else:
            s = ""
            for stanza_name in filter_r:
                t = get_config_xml(forwarder, args.conf_name, stanza_name)
                if not (t[0] == "200" or t[0] == "201" or t[0] == "204"):
                    return "Configuration File {1}.conf doesn't contains stanza with name{2} :\n".format(forwarder,args.conf_name,stanza_name)
                xml_str = t[1]
                dic = get_stanza_content_by_name(xml_str,stanza_name)
                s += "Configuration File {1}.conf Stanza {2} Contains Details:\n".format(
                    forwarder,args.conf_name,stanza_name)
                for key in dic:
                    s += "{0}:{1}".format(key,dic[key])
                    s += "\n"
            return s


def read_conf_change():
    conf_change = {}
    stanza_name = None
    stanza_content = {}
    with open(args.conf_f, "r") as conf_f:
        for each_line in conf_f:
            each_line = each_line.strip()
            if each_line.startswith("#") or len(each_line) == 0:
                continue
            m = re.search("^\ *name\ *=\ (?P<stanza_name>.*)", each_line)
            if m is not None:
                stanza_name = m.group("stanza_name")
                conf_change[stanza_name] = {}
            elif stanza_name is not None:
                l_lst = each_line.split("=")
                key = l_lst[0].strip()
                val = None if len(l_lst) == 1 else "=".join(l_lst[1:]).strip()
                if key not in conf_change[stanza_name]:
                    conf_change[stanza_name][key] = val
                else:
                    raise Exception("Incorrect Conf Change Format")
            else:
                raise Exception("Incorrect Conf Change Format")
    return conf_change


worker_func_d = {
        "add":add_stanza,
        "delete":delete_stanza_by_name,
        "update":update_stanza,
        "inq":display_conf
        }


args_d = {
            "add":(args.conf_name,),
            "delete":(args.conf_name,args.stanza_name),
            "update":(args.conf_name,),
            "inq":(args.stanza_name,args.is_re)
        }


if __name__ == "__main__":
    with open(args.hosts_f, "r") as forwarders_f:
        for forwarder in forwarders_f:
            forwarder = forwarder.strip()
            input_q.put(forwarder)
    process = []
    for i in range(int(WORKER_NUM)):
        p = Process(target=worker_func_d[args.mode],args=args_d[args.mode])
        p.start()
        process.append(p)
    for p in process:
        p.join()
    while not output_q.empty():
        print output_q.get()
    sys.exit(0)
