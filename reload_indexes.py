#!/usr/bin/python

import sys
import getpass
import pycurl
import urllib
import StringIO
import re

password = getpass.getpass("Splunk Admin Password: ")


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


def perform_curl(url,request_cmd=None,data=None):
    curl = pycurl.Curl()
    b = StringIO.StringIO()
    curl.setopt(pycurl.URL,url)
    curl.setopt(pycurl.CONNECTTIMEOUT, 3)
    curl.setopt(pycurl.TIMEOUT, 3)
    curl.setopt(pycurl.SSL_VERIFYPEER, False)
    curl.setopt(pycurl.SSL_VERIFYHOST, False)
    curl.setopt(pycurl.USERPWD, "{0}:{1}".format("admin",password))
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


def reload_indexes(indexer):
    url_1 = "https://{0}:8089/servicesNS/nobody/system/configs/conf-indexes/_reload".format(indexer)
    url_2 = """https://{0}:8089/services/data/indexes/_reload""".format(indexer)
    s = ""
    try:
        t = perform_curl(url_1)
        s += url_1+"\n"
        s += STATUS_CODES[t[0]]+"\n"
    except:
        raise
    try:
        t = perform_curl(url_2)
        s += url_2+"\n"
        s += STATUS_CODES[t[0]]+"\n"
    except:
        raise
    print s


if __name__ == "__main__":
    if len(sys.argv)<=1:
        print "Need Indexer Hostname as First Parameter"
    reload_indexes(sys.argv[1])
