#!/opt/splunk/bin/python
import sys
import os
import ConfigParser
import argparse


def change_server_conf(path):
    path = os.path.join(path, "server.conf")
    configs = ConfigParser.SafeConfigParser()
    configs.optionxform = str
    configs.read(path)
    if not "sslConfig" in configs.sections():
        configs.add_section("sslConfig")
    configs.set("sslConfig", "sslKeysfilePassword", "password")
    configs.set("sslConfig", "supportSSLV3Only", "true")
    if not "license" in configs.sections():
        configs.add_section("license")
    configs.set("license", "active_group", "Forwarder")
    with open(path, "w") as f:
        configs.write(f)


def change_outputs_conf(path):
    path = os.path.join(path, "outputs.conf")
    configs = ConfigParser.SafeConfigParser()
    configs.optionxform = str
    configs.read(path)
    if not "tcpout" in configs.sections() or not "defaultGroup" in configs.options("tcpout"):
        print "no tcpout stanza in outputs.conf, or no defaultGroup in tcpout stanza"
        return
    default_group_name = "tcpout:{0}".format(configs.get("tcpout", "defaultGroup"))
    if not default_group_name in configs.sections() or not "server" in configs.options(default_group_name):
        print "no {0} stanza in outputs.conf or no server stanza in {0} stanza".format(default_group_name)
        return
    out_server_stanza_name = "tcpout-server://{0}".format(configs.get(default_group_name,"server"))
    if not out_server_stanza_name in configs.sections():
        print "no {0} stanza in outputs.conf".format(out_server_stanza_name)
        return 
    configs.set(out_server_stanza_name, "sslPassword", "password")
    with open(path, "w") as f:
        configs.write(f)


def set_followtail(path):
    path = os.path.join(path,"inputs.conf")
    configs = ConfigParser.SafeConfigParser()
    configs.optionxform = str
    configs.read(path)
    for stanza in configs.sections():
        if stanza.startswith("monitor://"):
            configs.set(stanza, "followTail", "1")
    with open(path, "w") as f:
        configs.write(f)


def remove_followtail(path):
    path = os.path.join(path,"inputs.conf")
    configs = ConfigParser.SafeConfigParser()
    configs.optionxform = str
    configs.read(path)
    for stanza in configs.sections():
        if stanza.startswith("monitor://") and "followTail" in configs.options(stanza) and configs.get(stanza, "followTail") == "1":
            configs.remove_option(stanza,"followTail")
    with open(path, "w") as f:
        configs.write(f)


if __name__ == "__main__":
    options = argparse.ArgumentParser()
    options.add_argument("-p","--path", action="store",dest="path",default="/opt/splunk/etc/system/local")
    options.add_argument("-f","--follow_tail", action="store",dest="follow_tail",default="0",help="Set followTail for each inputs.conf stanzas")
    options.add_argument("-i","--initial", action="store",dest="initial",default="0")
    args = options.parse_args()

    if args.initial=="1":
        change_server_conf(args.path)
        change_outputs_conf(args.path)

    if args.follow_tail=="1":
        set_followtail(args.path)
    else:
        remove_followtail(args.path)
