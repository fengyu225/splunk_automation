import sys
import os
import ConfigParser


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


if __name__ == "__main__":
    if len(sys.argv)<=1:
        path = "/opt/splunk/etc/system/local"
    else:
        path = sys.argv[1].strip()
    change_server_conf(path)
    change_outputs_conf(path)
