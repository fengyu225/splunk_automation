import urllib
import urllib2
import re
import sys


cloud_sys_field_names = ["Name", "Status", "Ping"]
res_re_s = "\ *,\ *".join("\"?(?P<{0}>[^,\[\]\"]+)\"?".format(n) for n in cloud_sys_field_names)
res_re_p = re.compile(res_re_s)

def get_cloudsys_portal_stauts(host,field_names=cloud_sys_field_names):
    url = "http://search.inventory.cloudsys.tmcs/v1/search/"
    url += "/".join(str(field_name) for field_name in field_names)
    url += "?q={0}".format(host)
    try:
        response = urllib2.urlopen(url)
    except urllib2.HTTPError as e:
        print "cloudsys portal not reachable, error code:{0}".format(e.code)
    except urllib2.URLError as e:
        print "Error with request: host: {0}, error code: {1}".format(host,e.code)
    else:
        m = res_re_p.search(response.read())
        print {n:str(m.group(n)) for n in cloud_sys_field_names} if m is not None else "{0} not found from CloudSys Portal".format(host) 
        if m is not None and m.group("Ping")=="Up":
            return m.group("Name")

if __name__ == "__main__":
    if len(sys.argv)<2:
        print "pass hosts file path as first parameter"
        sys.exit(1)
    h = ""
    for host in sys.stdin:
        host = host.strip().split(" ")[0]
        t = get_cloudsys_portal_stauts(host)
        if t is not None:
            h += t+"\n"
    with open(sys.argv[1].strip(), "w") as f:
        f.write(h)
