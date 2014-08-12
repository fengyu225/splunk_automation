import splunklib.client as client
from contextlib import contextmanager
import paramiko
import select
import time
import ConfigParser
from collections import defaultdict
from collections import namedtuple
from itertools import product
import getpass
import re
import socket
import sys
import fnmatch


DEFAULT_TRANSFORMS_STANZAS = ['access-extractions', 'access-request', 'ad-kv', 'all', 'all_lazy', 'alnums', 'alphas', 'bc_domain', 'bc_uri', 'bracket-space', 'browser', 'cisco-codes', 'colon-kv', 'colon-line', 'db2', 'digits', 'dnslookup', 'email', 'exceptionclass', 'filetype', 'float', 'guid-to-translate', 'guid_lookup', 'int', 'ip', 'ipv4', 'language', 'log4-severity', 'loglevel', 'loglevel-weblogic', 'novell-groupwise-arrival', 'novell-groupwise-queue', 'novell-groupwise-transfer', 'nspaces', 'num-kv', 'octet', 'os', 'perfmon-kv', 'qstring', 'registry', 'reqstr', 'sbstring', 'send_to_nullqueue', 'sendmail-extractions', 'sendmail-pid', 'sendmail-qid', 'sendToTCP', 'set_sourcetype_to_stash', 'sid_lookup', 'simple_uri', 'simple_url', 'splunk-access-extractions', 'splunk-service-extractions', 'splunk_help', 'splunk_index_history', 'splunkd-disassembler', 'stash_extract', 'strip-winevt-linebreaker', 'syslog-extractions', 'syslog-header-stripper-ts', 'syslog-header-stripper-ts-host', 'syslog-header-stripper-ts-host-proc', 'syslog-host', 'syslog-host-full', 'syslog-process', 'tcpdump-endpoints', 'uri', 'uri_root', 'uri_seg', 'url', 'was-trlog-code', 'weblogic-code', 'wel-col-kv', 'wel-eq-kv', 'wel-message', 'wmi-host', 'wmi-override-host']

DEFAULT_INPUTS_STANZAS = ['batch://$SPLUNK_HOME/var/spool/splunk', 'batch://$SPLUNK_HOME/var/spool/splunk/...stash_new', 'fschange:$SPLUNK_HOME/etc', 'monitor://$SPLUNK_HOME/etc/splunk.version', 'monitor://$SPLUNK_HOME/var/log/splunk', 'script', 'splunktcp', 'SSL']


def read_config(path):
    """
    read configuration file.
    config file should contains general stanza and log.* stanza
    general stanza required fields: 
        forwarder,forwarder_port,logfile_host,logfile_ssh_user
    log stanza required fields:
        path_pattern,source_pattern,app,h_num,cls,cluster,host_suffix,index, and any fields appear in them 
    return value: a dict maps from "general" and "log" to a list of dict
    """
    res = defaultdict(list)
    configs = ConfigParser.SafeConfigParser()
    configs.optionxform = str
    configs.read(path)
    sections = filter(lambda x:x=="general" or x.startswith("log"), configs.sections())
    if "general" not in sections:
        raise Exception("read_config: general section not found in config file")
    res["general"].append({option:configs.get("general",option) for option in configs.options("general")})
    for each_log in filter(lambda x:x.startswith("log"),configs.sections()):
        res["log"].append({option:configs.get(each_log,option) for option in configs.options(each_log)})
    if "log" not in res:
        raise Exception("read_config: no log stanza found in config file")
    return res


def get_splunk_conf(host):
    """
    this function get inputs.conf/props.conf/transforms.conf on host
    return a dict that maps from conf_name (inputs/props/transforms) to a dict that maps from stanza names to dict
    """
    confs_name = ["inputs", "props", "transforms"]
    stanza_ignore = {"inputs":DEFAULT_INPUTS_STANZAS, "transforms":DEFAULT_TRANSFORMS_STANZAS, "props":"^source::/.*$"}
    conn = client.connect(host=host,port=8089,username=admin_uname,password=admin_passwd,app="system",onwer="nobody")
    all_confs = conn.confs.list()
    res = {}
    for conf_name in confs_name:
        conf = filter(lambda x:x.name==conf_name,all_confs)[0] #conf is a generator
        # find all stanza names for inputs/transforms/props
        # for inputs/transforms, filter out default stanza names
        # for props, filter out stanza names that don't match regex 
        stanza_names = [x.name for x in conf.list() if isinstance(stanza_ignore[conf_name],list) and not x.name in stanza_ignore[conf_name] or isinstance(stanza_ignore[conf_name],str) and re.match(stanza_ignore[conf_name],x.name) is not None]
        res[conf_name] = {}
        for n in stanza_names:
            c = filter(lambda x:x.name==n,conf.list())[0].content
            c = {x:c[x] if c[x] is not None else "" for x in c}
            res[conf_name][n] = c
    return res


def get_available_port(host,base=9999,limit=100):
    """
    find port on host that is not used
    """
    for i in range(0,limit,1):
        s = socket.socket()
        try:
            s.connect((host,base+i))
            return base+i
        except socket.error,e:
            continue
    return -1


def set_tcp_input_stanza(conn, port_num, params):
    """
    set up tcp stanza in inputs.conf
    params should be a dict which contains keys: host,index,source,sourcetype
    values of host/index/source/sourcetype in params are associated with each reloaded logs
    this doesn't require a Splunkd restart
    """
    if not isinstance(params, dict):
        raise Exception("get_tcp_input_stanza: {0} is not a dict".format(params))
    s = filter(lambda x:x.name==str(port_num), conn.inputs)
    if len(s) != 0:
        s[0].update(**params).refresh() #if intpus.conf has a stanza for this port_num, update it
    else:
        conn.inputs.create(str(port_num),"tcp",**params)


def apply_splunk_conf(host,conf_dict):
    """
    this function updates props.conf and transforms.conf on host with values in conf_dict
    conf_dict should be a dict from props/transforms to dicts from stanza names to dicts  
    this update requires Splunkd restart
    """
    confs_name = ["props", "transforms"]
    stanza_ignore = {"inputs":DEFAULT_INPUTS_STANZAS, "transforms":DEFAULT_TRANSFORMS_STANZAS, "props":"^source::/.*$"}
    conn = client.connect(host=host,port=8089,username=admin_uname,password=admin_passwd,app="system",onwer="nobody")
    confs_list = conn.confs.list()
#    for conf_name in conf_dict:
    for conf_name in confs_name:
        if len(conf_dict[conf_name]) == 0:
            continue
        curr_conf = filter(lambda x:x.name==conf_name,confs_list)[0]
        # delete stanzas in inputs.conf and transforms.conf that is not default, and stanzas in props.conf that matches regex
        map(lambda x:x.delete(),[s for s in curr_conf.list() if isinstance(stanza_ignore[conf_name],list) and not s.name in stanza_ignore[conf_name] or isinstance(stanza_ignore[conf_name],str) and re.match(stanza_ignore[conf_name],s.name) is not None])
        for each_stanza in conf_dict[conf_name]:
            s = curr_conf.create(each_stanza)
            s.post(**conf_dict[conf_name][each_stanza])
            s.update()
    conn.restart(timeout=180)


def rm_tcp_input_stanza(conn, port_num):
    conn.inputs.delete(str(port_num))


@contextmanager
def get_ssh_conn(host, user):
    """
    Function for getting SSH connection to host with hostname 'host' and
    username 'user'
    Returning a SSH connection that can be used with 'with' statement
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, username=user)
        yield ssh
    except paramiko.BadHostKeyException, e:
        print "Server's host key could not be verified: {}".format(host)
        raise
    except paramiko.AuthenticationException, e:
        print "Authentication failed: {}".format(host)
        raise
    except paramiko.PasswordRequiredException, e:
        print "Public Key not Pushed on host {0} with user {1}".format(host,user)
        raise
    except Exception:
        raise
    finally:
        if ssh:
            ssh.close()


def replace_path_pattern(conf):
    """
    replace fields in path_pattern with values
    conf should be a namedtuple
    return log file path on aso box
    """
    p = re.compile("{(?P<name>[^{}]+)}")
    field_names = p.findall(conf.path_pattern);
    result = conf.path_pattern
    for each_field in field_names:
        result = result.replace("{"+each_field+"}",eval("conf."+each_field))
    return result


def replace_source_pattern(conf):
    """
    replace fields in source_pattern with values
    conf should be a namedtuple
    return log file path that appears in inputs.conf
    """
    p = re.compile("{(?P<name>[^{}]+)}")
    field_names = p.findall(conf.source_pattern);
    result = conf.source_pattern
    for each_field in field_names:
        result = result.replace("{"+each_field+"}",eval("conf."+each_field))
    return result


def get_cmd(conf,res):
    conf_path = replace_path_pattern(conf)
    if "sed_cmd" in conf._fields:
        cmd = r"{3} {0} | {4}  | nc {1} {2}".format(conf_path,res["general"][0]["forwarder"],res["general"][0]["forwarder_port"],conf.uncompress_cmd,conf.sed_cmd)
    else:
        cmd = r"{3} {0} | nc {1} {2}".format(conf_path,res["general"][0]["forwarder"],res["general"][0]["forwarder_port"],conf.uncompress_cmd)
    return cmd


def 


def send_logs(path):
    """
    1. read configs 
    2. loop through each log.* stanza
    3. for each log stanza in config file, get a product of all fields
    4. construct a dict host_conf that maps host to a list of namedtuples constructed from config product 
       the reason for using host_conf is because changes of inputs.conf doesn't require splunkd restart and categorizing configs by host can minimize number of splunkd restart (only need to restart splunkd for each host)
    5. for each host in host_conf, read props.conf/transforms.conf on it and set up props.conf and transforms.conf on forwarder
    6. loop through each config product and setup inputs.conf on forwarder.
    7. after inputs.conf is setup on forwarder, open a ssh channel to {logfile_host} (aso box) and execute gzip and netcat command to send logs to forwarder
    8. after logs have been sent, delete tcp stanza and close port on forwarder
    """
    global admin_uname 
    global admin_passwd 
    admin_uname = raw_input("Splunk Admin Username: ") 
    admin_passwd = getpass.getpass("Splunk Admin Password: ") 
    res = read_config(path)
    confs = []
    for each_r in res["log"]:
        conf_tuple = namedtuple("conf_tuple", " ".join(each_r.keys()))
        t = [each_r[x].split(",") for x in each_r]
        p = product(*t)
    ### conf_tuple(h_num='1', app='pxy', host_suffix='websys.tmcs', month='02', cluster='ash1', year='2014', log_name_prefix='us_access_log', path_pattern='/nls2/vol3/current/htdocs/logs/{year}/{month}/{day}/tm/{cluster}/{class}/{app}/{h_num}/apache/{log_name_prefix}_{year}{month}{day}', day='10', cls='tmol') 
        confs = [conf_tuple(**(dict(zip(each_r.keys(),x)))) for x in p]
        host_conf = defaultdict(list)
        for each_conf in confs:
            host_conf[".".join([each_conf.app+each_conf.h_num,each_conf.cls,each_conf.cluster,each_conf.host_suffix])].append(each_conf)
        for host in host_conf:
            orig_conf = get_splunk_conf(host)
            #orig_conf["props"]["source::/atl/local/log/atlas.log"]["TIME_FORMAT"]="%b %d %Y %H:%M:%S"
            apply_splunk_conf(res["general"][0]["forwarder"],orig_conf)
            for conf in host_conf[host]:
                conn = client.connect(host=res["general"][0]["forwarder"],port=8089,username=admin_uname,password=admin_passwd,app="system",owner="nobody")
                conf_source = replace_source_pattern(conf)
                sourcetypes = [orig_conf["props"][x]["sourcetype"] for x in orig_conf["props"] if fnmatch.fnmatch("source::"+conf_source,x)]
                if len(sourcetypes) == 0:
                    print "ERROR: send_logs: props.conf on host {0} contains no stanza for file {1}".format(host,conf_source)
                    continue
                set_tcp_input_stanza(conn,res["general"][0]["forwarder_port"],{"host":host,"index":conf.index,"sourcetype":sourcetypes[0],"source":conf_source}) 
                with get_ssh_conn(res["general"][0]["logfile_host"],res["general"][0]["logfile_ssh_user"]) as ssh:
                    transport = ssh.get_transport()
                    transport.set_keepalive(1)
                    channel = transport.open_session()
                    cmd = get_cmd(conf,res)
#                    channel.exec_command(cmd)
                    print cmd
#                    while True:
#                        time.sleep(3)
#                        if channel.exit_status_ready():
#                            print "done"
#                            break
                rm_tcp_input_stanza(conn, res["general"][0]["forwarder_port"])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "pass config file path as the first parameter"
    else:
        send_logs(sys.argv[1].strip())
