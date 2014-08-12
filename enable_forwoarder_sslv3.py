import argparse
import os
import sys
import time
import datetime
import re
import paramiko
import sqlite3
import splunklib.client as client
import ConfigParser
import socket
import ssl
import errno
from contextlib import contextmanager


def parse_args():
    """
    db: path to sqlite3 database file.
        name of table: forwarders
        schema: CREATE TABLE forwarders(host text,user text,status text);
                host:   Splunk forwarder host name
                user:   SSH username
                status: processing status
    """
    options = argparse.ArgumentParser("Script for Adding SSLv3Only on Forwarders")
    options.add_argument("-d", "--db", action="store", dest="db",
                         required=True, help="Set Path to Sqlite Database")
    options.add_argument("-l", "--limit", action="store", dest="limit",
                         required=True, help="Set Limit on # of Hosts")
    return options.parse_args()


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


def is_splunk_running(host, user):
    """
    Function for checking whether Splunk is running on remote host using ps
    If return value contains regex pattern splunkd\s*\-p\s*\d+, then Splunk
    is running.
    """
    with get_ssh_conn(host, user) as ssh:
        ssh_stdout_str = ""
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('ps -ef \
                | grep splunkd | grep -v grep')
        ssh_stdout_str = ssh_stdout.read()
        return re.search("splunkd\s*\-p\s*\d+", ssh_stdout_str) is not None


def stop_splunk(host, user):
    """
    Function for stopping Splunk on remote host
    Each exec_command call happens in a new shell. This function checks
    Splunk is stopped by checking every 6 seconds for at most 10 times.
    If Splunk is not stopped after 60s, it raises an exception
    """
    with get_ssh_conn(host, user) as ssh:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sudo -l")
        if "/etc/init.d/splunk stop" in ssh_stdout.read():
            ssh.exec_command("sudo /etc/init.d/splunk stop")
            for i in range(10):
                if is_splunk_running(host, user):
                    time.sleep(6)
                else:
                    return
            raise Exception("Stop Splunk Failed on host {0}".format(host))
        else:
            raise Exception("No Permission to Stop Splunk \
                    on host {0}".format(host))


def start_splunk(host, user):
    """
    Function for starting Splunk on remote host
    The way used by this function for checking if Splunk is started is
    same as function stop_splunk
    """
    with get_ssh_conn(host, user) as ssh:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("sudo -l")
        if "/etc/init.d/splunk start" in ssh_stdout.read():
            ssh.exec_command("sudo /etc/init.d/splunk start")
            for i in range(10):
                if not is_splunk_running(host, user):
                    time.sleep(6)
                else:
                    return
            raise Exception("Start Splunk Failed on host {0}".format(host))
        else:
            raise Exception("No Permission to Start Splunk on \
                    host {0}".format(host))


def remote_mv(host, user, orig, new):
    """
    Function to perform 'mv orig new' on remote host
    """
    with get_ssh_conn(host, user) as ssh:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("mv {0} {1}".format(orig, new))



def remote_mkdir(host, user):
    """
    Function to create backup dir on remote host
    """
    with get_ssh_conn(host, user) as ssh:
        ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("mkdir -p /opt/splunk/etc/system/local/Backup")


def apply_conf_change(host, user):
    """
    Function for adding supportSSLV3Only=true for sslConfig stanza
    Returns 1 if server.conf contains sslConfig stanza and supportSSLV3Only is
        already set to true, otherwise return nothing
    It first downloads server.conf file from remote host to local directory
    If server.conf doesn't contain sslConfig stanza, it adds one
    It changes server.conf locally then puts local server.conf to remote host
    Before it puts server.conf on remote host, it backups remote server.conf.
    """
    with get_ssh_conn(host, user) as ssh:
        sftp = ssh.open_sftp()
        sftp.get("/opt/splunk/etc/system/local/server.conf",
                 os.path.join(os.getcwd(), "server.conf"))
        config = ConfigParser.RawConfigParser()
        config.optionxform = str
        config.read(os.path.join(os.getcwd(), "server.conf"))
        if not config.has_section("sslConfig"):
            config.add_section("sslConfig")
        if config.has_option("sslConfig", "supportSSLV3Only") and \
                config.get("sslConfig", "supportSSLV3Only") == "true":
            return 0
        config.set("sslConfig", "#By default, allow both v2 and v3 connections to the HTTP server\nsupportSSLV3Only", "true")
        with open(os.path.join(os.getcwd(), "server.conf"), "wb") \
                as configfile:
            config.write(configfile)
        remote_mkdir(host,user)
        remote_mv(host, user, "/opt/splunk/etc/system/local/server.conf",
                  "/opt/splunk/etc/system/local/Backup/server.conf_backup_before_sslv3only_{0}".format(datetime.datetime.today().strftime("%Y%m%d")))
        try:
            sftp.put(os.path.join(os.getcwd(), "server.conf"),
                     "/opt/splunk/etc/system/local/server.conf")
        except:
            remote_mv(host, user,
                      "/opt/splunk/etc/system/local/Backup/server.conf_backup_before_sslv3only_{0}".format(datetime.datetime.today().strftime("%Y%m%d")),
                      "/opt/splunk/etc/system/local/server.conf")
            raise
        finally:
            os.remove(os.path.join(os.getcwd(), "server.conf"))


def get_host_from_db(db_conn):
    """
    It returns a dict mapping from host to user
    """
    c = db_conn.cursor()
    return {row[0]: row[1] for row in
            c.execute("select host, user from forwarders where status<>'successful' and status <> 'Public Key Not Pushed' and status<>'host not exists' and status<>'Stop Splunk Failed' order by host asc limit {0}".format(args.limit))}


def update_status(db_conn, host, status):
    """
    Function for updating processing status in database table 'forwarders'
    """
    c = db_conn.cursor()
    q = "update forwarders set status='{0}',date='{1}' where host='{2}'".format(
            status,
            datetime.datetime.today().strftime("%Y-%m-%d"),
            host
            )
    c.execute(q)
    print q
    db_conn.commit()


def test_ssl_v3_connection(host):
    """
    Testing remote host accepts sslv3 connection
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ssl_sock = ssl.wrap_socket(s,ssl_version=ssl.PROTOCOL_SSLv3)
        ssl_sock.connect((host,8089))
    except:
        raise
    finally:
        if ssl_sock:
            ssl_sock.close()
        if s:
            s.close()


def test_ssl_v2_connection(host):
    """
    Testing remote host doesn't accept sslv2 connection
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ssl_sock = ssl.wrap_socket(s,ssl_version=ssl.PROTOCOL_SSLv2)
        ssl_sock.connect((host,8089))
    except ssl.SSLError, e:
        pass
    else:
        raise
    finally:
        if ssl_sock:
            ssl_sock.close()
        if s:
            s.close()


if __name__ == "__main__":
    args = parse_args()
    with sqlite3.connect(args.db) as db_conn:
        host_user = get_host_from_db(db_conn)
        for (host, user) in host_user.iteritems():
            update_status(db_conn, host, "started")
            try:
                r = apply_conf_change(host, user)
            except paramiko.PasswordRequiredException, e:
                print "Public Key not Pushed on host {0} with user {1}".format(host,user)
                update_status(db_conn, host, "Public Key Not Pushed")
                continue
            except socket.gaierror, e:
                print "Unknown Host {0}".format(host)
                update_status(db_conn, host, "host not exists")
                continue
            except IOError, e:
                if e.errno == errno.ENOENT:
                    continue
                else:
                    raise
            update_status(db_conn, host, "change applied")
            if r is None:
                if is_splunk_running(host, user):
                    try:
                        stop_splunk(host, user)
                    except:
                        update_status(db_conn, host, "Stop Splunk Failed")
                        continue
                try:
                    start_splunk(host, user)
                except:
                    remote_mv(host, user,
                            "/opt/splunk/etc/system/local/Backup/server.conf_backup_before_sslv3only_{0}".format(datetime.datetime.today().strftime("%Y%m%d")),
                            "/opt/splunk/etc/system/local/server.conf")
                    start_splunk(host, user)
                    update_status(db_conn, host, "Start Splunk Failed")
                    continue
                #test_ssl_v3_connection(host)
                #test_ssl_v2_connection(host)
            update_status(db_conn, host, "successful")
