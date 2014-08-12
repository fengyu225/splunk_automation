from datetime import *
import os
import ConfigParser
from collections import namedtuple
import re
import fnmatch
import argparse
from collections import defaultdict
from tm_format_to_re import tm_format_to_re

PROPS_CONF_PATH = "/opt/splunk/etc/system/local/props.conf"
INPUTS_CONF_PATH = "/opt/splunk/etc/system/local/inputs.conf"
TRANSFORMS_CONF_PATH = "/opt/splunk/etc/system/local/transforms.conf"

def read_timestamp_break(source):
    configs = ConfigParser.RawConfigParser()
    configs.optionxform = str
    configs.read(PROPS_CONF_PATH)
    stanzas = filter(lambda x:fnmatch.fnmatch("source::{0}".format(source),x),configs.sections())
    if not stanzas:
        print "no stanza found in {1} match {0}".format(source,PROPS_CONF_PATH)
        return None
    options = configs.options(stanzas[0])
    if not "TIME_PREFIX" in options or not "TIME_FORMAT" in options:
        print "TIME_PREFIX or TIME_FORMAT not configured in stanza ".format(stanzas[0])
        return None
    timestamp_break = namedtuple("tm_break","prefix time_format")
    tm_format=re.sub("%\d+N", "%f", configs.get(stanzas[0],"TIME_FORMAT"))
    return timestamp_break(prefix=configs.get(stanzas[0],"TIME_PREFIX"),time_format=tm_format)


def get_time_regex(time_prefix,time_format):
    t_regex = tm_format_to_re(time_prefix,time_format)
    try:
        p = re.compile(t_regex)
    except:
        print "regex error: \n\tt_regex"
        return None
    else:
        return p

# was trying to use binary search to search for gaps in raw log files. 
# some raw log files are not well sorted on timestamp. so using binary search cannot get accurate results
#def read_curr_line(seek_ptr,f):
#    if seek_ptr == 0:
#        return 0,f.readline()
#    f.seek(seek_ptr)
#    c = f.read(1)
#    while c!="\n":
#        curr = f.tell()
#        if curr<2:
#            f.seek(0)
#            break
#        f.seek(curr-2)
#        c = f.read(1)
#    return f.tell(),f.readline()
#
#
#def search_earliest(l,r,dt,f,p,time_format):
#    m = (l+r)/2
#    ln,line = read_curr_line(m,f)
#    if ln<=l:
#        # f.tell() is beginning of next line
#        return f,line 
#    else:
#        m_obj = p.search(line)
#        if not m_obj:
#            raise Exception("error in search_earliest: cannot parse datetime from log \n{0}".format(l))
#        d = datetime.strptime(m_obj.group("time_str"),time_format)
#        if d<dt:
#            return search_earliest(m+1,r,dt,f,p,time_format)
#        else:
#            return search_earliest(l,m-1,dt,f,p,time_format)
#
#
#def get_latest_time_earlier_than(dt_str,f_path):
#    """
#    if dt_str is earlier than or equal to the first log, return the first log
#    if dt_str is later than the last log, return the last log
#    else return latest log that is earlier than dt_str
#
#    performance: for 1GB log file, this function takes less than 0.1s 
#    """
#    tm_brk = read_timestamp_break(f_path)
#    p = get_time_regex(tm_brk.prefix,tm_brk.time_format)
##    p = get_time_regex("^\d+\.\d+\.\d+\.\d+\t\S+\t\S+\t", "%d/%b/%Y:%H:%M:%S")
##    time_format = "%d/%b/%Y:%H:%M:%S"
#    dt = datetime.strptime(dt_str,"%m/%d/%y %I:%M:%S.%f %p")
#    f = open(f_path,"r")
#    f,res = search_earliest(0,os.stat(f_path)[6],dt,f,p,tm_brk.time_format)
#    return res


def filter_logs(f,gaps,to_dir="/tmp"):
    tm_brk = read_timestamp_break(f)
    if tm_brk is None:
        print "reading timestamp break failed for file {0}".format(f)
        return False
    p = get_time_regex(tm_brk.prefix,tm_brk.time_format)
    gaps_dt = []
    for gap in gaps:
        start_dt = datetime.strptime(re.sub("(.*)-\d{2}:\d{2}$", r"\g<1>", gap[0]), "%Y-%m-%dT%H:%M:%S.%f")
        end_dt = start_dt+timedelta(seconds=abs(int(gap[1])))
        gaps_dt.append((start_dt,end_dt))
    dest_f = os.path.join(to_dir,f.split("/")[-1])
    os.remove(dest_f) if os.path.exists(dest_f) else None
    try:
        f_path = "/".join(f.split("/")[:-1])
        f_dir = [os.path.join(f_path,x) for x in os.listdir(f_path)]
        for each_f in filter(lambda x:re.match("^{0}(\.\d+)?$".format(f), x), f_dir):
            with open(each_f, "r") as in_f:
                with open(dest_f,"a") as out_f:
                    for each_log in in_f:
                        m = p.search(each_log)
                        if m is not None:
                            dt = datetime.strptime(m.group("time_str"), tm_brk.time_format)
                            dt = dt.replace(year=datetime.now().year)
                            if len(filter(lambda d:dt>d[0] and dt<d[1], gaps_dt)) > 0:
                                out_f.write(each_log)
    except IOError:
        print "file {0} not exists".format(f)
        return False 
    else:
        if not os.path.exists(dest_f):
            return False
        elif os.stat(dest_f).st_size==0:
            os.remove(dest_f)
            return False
        return True


def fill_logs(log_gap_files_dir="/tmp"):
    log_gaps_files = filter(lambda f:f.startswith("splunk_log_gaps_"),os.listdir(log_gap_files_dir))
    logfiles = map(
        lambda x:x.replace("-", "/"),
        map(
            lambda x:re.sub("splunk_log_gaps_([^_]+_)(.+)", r"\g<2>", x),
            log_gaps_files
            )
        )
    log_gaps = defaultdict(list) 
    for i,log_gaps_file in enumerate(log_gaps_files):
        with open(os.path.join(log_gap_files_dir, log_gaps_file), "r") as f:
            for line in f:
                log_gaps[logfiles[i]].append((line.split(",")[0].strip(),line.split(",")[1].strip()))
    #log_gaps:
    #defaultdict(<type 'list'>, {'/pxy/local/logs/us_access_log': [('2014-07-09T01:01:39.000-07:00', '-540'), ('2014-07-08T01:03:13.000-07:00', '-446')], '/pxy/local/logs/lu_access_log': [('2014-07-09T00:55:43.000-07:00', '-898'), ('2014-07-08T01:01:42.000-07:00', '-537')]})
    files = []
    for each_f in log_gaps:
        res = filter_logs(each_f, log_gaps[each_f])
        if res:
            files.append(each_f)
    # return list of paths of log files that have gap in Splunk
    return files


def set_inputs_conf(f,to_dir="/tmp"):
    configs = ConfigParser.RawConfigParser()
    configs.optionxform = str
    configs.read(INPUTS_CONF_PATH)
    f_path = "/".join(f.split("/")[:-1])
    f_name = f.split("/")[-1]
    stanzas = filter(lambda x:x=="monitor://{0}".format(f) or x=="monitor://{0}".format(f_path) or x=="monitor://{0}/".format(f_path),configs.sections())
    for stanza in stanzas:
        d = {o:configs.get(stanza,o) for o in configs.options(stanza)}
        if stanza == "monitor://{0}".format(f):
            new_stanza_name = "monitor://{0}".format(os.path.join(to_dir, f.split("/")[-1]))
        else:
            new_stanza_name = "monitor://{0}".format(to_dir)
        if not new_stanza_name in configs.sections():
            configs.add_section(new_stanza_name)
        for option in d:
            configs.set(new_stanza_name,option,d[option])
        configs.set(new_stanza_name,"crcSalt", "<SOURCE>")
    with open(INPUTS_CONF_PATH, "w") as f:
        configs.write(f)


def set_props_conf(f,to_dir="/tmp"):
    configs = ConfigParser.RawConfigParser()
    configs.optionxform = str
    configs.read(PROPS_CONF_PATH)
    stanzas = filter(lambda x:fnmatch.fnmatch("source::{0}".format(f),x),configs.sections())
    to_dir = to_dir[:-1] if to_dir[-1] == "/" else to_dir
    if len(stanzas) == 0:
        print "No stanza in {1} match file: {0}".format(f,PROPS_CONF_PATH)
        return
    #there should not be more than one stanza in props.conf that match a file
    stanza = stanzas[0]
    d = {o:configs.get(stanza,o) for o in configs.options(stanza)}
    new_stanza_name = "source::{0}".format(os.path.join(to_dir,f.split("/")[-1]))
    if not new_stanza_name in configs.sections():
        configs.add_section(new_stanza_name)
    temp_str = "_".join(os.path.join(to_dir,f.split("/")[-1]).split("/"))
    temp_str = re.sub("\W", "_", temp_str)
    d["TRANSFORMS-{0}".format(temp_str)] = temp_str
    # setting up sourcetype transforms
    configs_t = ConfigParser.RawConfigParser()
    configs_t.optionxform = str
    configs_t.read(TRANSFORMS_CONF_PATH)
    if not temp_str in configs_t.sections():
        configs_t.add_section(temp_str)
        configs_t.set(temp_str,"SOURCE_KEY","MetaData:Source")
        configs_t.set(temp_str,"REGEX",".*")
        configs_t.set(temp_str,"DEST_KEY","MetaData:Source")
        configs_t.set(temp_str,"FORMAT","source::{0}".format(f))
    with open(TRANSFORMS_CONF_PATH, "w") as f:
        configs_t.write(f)
    for option in d:
        configs.set(new_stanza_name,option,d[option])
    with open(PROPS_CONF_PATH, "w") as f:
        configs.write(f)


if __name__ == "__main__":
    options = argparse.ArgumentParser()
    options.add_argument("-g","--gap_file_dir",action="store",dest="gap_file_dir",required=True)
    options.add_argument("-l","--missing_logs_dir",action="store",dest="missing_logs_dir",default="/tmp",help="Default: /tmp")
    args = options.parse_args()
    files = fill_logs(args.gap_file_dir)
    for each_f in files:
        set_props_conf(each_f,args.missing_logs_dir)
        set_inputs_conf(each_f,args.missing_logs_dir)
