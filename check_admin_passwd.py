import sys
import getpass
import argparse
import pycurl
import urllib
import StringIO
import feedparser
import re
from multiprocessing import Process,Queue


options = argparse.ArgumentParser(description = "Script to Check Login On Remote Hosts")
options.add_argument("-f","--hosts", action="store",dest="hosts_f",required=True,help="Path to File of List of Hosts to be Checked")
options.add_argument("-u","--admin_username", action="store",dest="admin_username",default="admin",help="Set Admin Login username")
options.add_argument("-m","--mode", action="store",dest="mode",required=True,help="check/reset")


args = options.parse_args()


status_codes = {
            "200":"Operation successful.",
            "201":"Object created successfully.",
            "204":"Successful, but no content was returned.",
            "400":"Request error. See response body for explanation.",
            "401":"Authentication failure: must pass valid credentials with request. Session may have timed out.",
            "402":"The Splunk license in use has disabled this feature.",
            "403":"Insufficient permissions to view/edit/create/disable/delete.",
            "404":"Object does not exist.",
            "405":"Method Not Allowed (e.g. supports GET but not POST)",
            "409":"Request error: this operation is invalid for this item. See response body for explanation.",
            "500":"Internal server error. See response body for explanation.",
            "503":"This feature has been disabled in Splunk configuration files."
        }



def check_login(input_q,output_q,password):
    while True:
        try:
            forwarder = input_q.get(False)
        except:
            break
        curl = pycurl.Curl()
        b = StringIO.StringIO()
        curl.setopt(
                pycurl.URL,
                """https://{0}:8089/services/auth/login""".format(forwarder)
        )
        login_detail = {"username":args.admin_username,"password":password}
        data = urllib.urlencode(login_detail)
        curl.setopt(pycurl.CONNECTTIMEOUT, 30)
        curl.setopt(pycurl.TIMEOUT, 30)
        curl.setopt(pycurl.SSL_VERIFYPEER, False)
        curl.setopt(pycurl.SSL_VERIFYHOST, False)
        curl.setopt(pycurl.USERPWD, "{0}:{1}".format(args.admin_username,password))
        curl.setopt(pycurl.WRITEFUNCTION, b.write)
        curl.setopt(pycurl.POSTFIELDS,data)
        try:
            r = curl.perform()
        except Exception,e:
            output_q.put("Error Performing Curl on Host: \n\t{0}\n\t{1}".format(forwarder,str(e)))
        else:
            status_code = str(curl.getinfo(pycurl.HTTP_CODE))
            if status_code == "200":
                continue
            if status_code == "401":
                output_q.put(forwarder)
                continue
            output_q.put(
                    "---------------- {0} ----------------\n{1}".format(forwarder,status_codes[status_code]))


def change_admin_password(input_q,output_q,password,new_password):
    while True:
        try:
            forwarder = input_q.get(False)
        except:
            break
        curl = pycurl.Curl()
        b = StringIO.StringIO()
        curl.setopt(
                pycurl.URL,
                """https://{0}:8089/services/authentication/users/{1}""".format(forwarder,args.admin_username)
        )
        login_detail = {"password":new_password}
        data = urllib.urlencode(login_detail)
        curl.setopt(pycurl.CONNECTTIMEOUT, 3)
        curl.setopt(pycurl.TIMEOUT, 3)
        curl.setopt(pycurl.SSL_VERIFYPEER, False)
        curl.setopt(pycurl.SSL_VERIFYHOST, False)
        curl.setopt(pycurl.USERPWD, "{0}:{1}".format(args.admin_username,password))
        curl.setopt(pycurl.WRITEFUNCTION, b.write)
        curl.setopt(pycurl.POSTFIELDS,data)
        try:
            r = curl.perform()
        except Exception,e:
            output_q.put("Error Performing Curl on Host: \n\t{0}\n\t{1}".format(forwarder,str(e)))
        else:
            status_code = str(curl.getinfo(pycurl.HTTP_CODE))
            if status_code == "200":
                continue
            else:
                output_q.put(
                        "---------------- {0} ----------------\n{1}:{2}".format(forwarder,status_code,status_codes[status_code])
                )


if __name__ == "__main__":
    input_q = Queue()
    output_q = Queue()
    worker_num = 20
    process = []
    password = getpass.getpass("Splunk Admin Password: ")
    if args.mode=="check":
        worker_func = check_login
        worker_args = (input_q,output_q,password)
    elif args.mode=="reset":
        new_password = getpass.getpass("Splunk Admin New Password: ")
        worker_func = change_admin_password
        worker_args = (input_q,output_q,password,new_password)
    else:
        raise Exception("Unknown Mode: {0}".format(args.mode))
    with open(args.hosts_f, "r") as forwarders_f:
        for forwarder in forwarders_f:
            forwarder = forwarder.strip()
            input_q.put(forwarder)
    for i in range(worker_num):
        p = Process(target=worker_func, args=worker_args)
        p.start()
        process.append(p)
    for p in process:
        p.join()
    while not output_q.empty():
        print output_q.get()
    sys.exit(0)
