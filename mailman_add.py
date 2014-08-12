import ldap
import sys
import socket
import argparse
import getpass
import urllib
import urllib2
import cookielib
import re
import splunklib.client as client


def parse_args():
    options = argparse.ArgumentParser("Script for Adding Users to Splunk Users Email Group")
    options.add_argument("-s","--hosts", action="store", dest="splunk_hosts",default="sch1.splunk.ash0.coresys.tmcs,sch2.splunk.ash0.coresys.tmcs", help="Set Splunk Search Head, default to search1 and search2")
    options.add_argument("-u","--splunk_username", action="store", dest="splunk_username",required=True, help="Set Splunk Username with User Admin Auth")
    args = options.parse_args()
    return args


def mailinglist_admin_login():
    cookie_jar = cookielib.CookieJar()
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie_jar))
    urllib2.install_opener(opener)
    url = "http://lists.tm.tmcs/mailman/admin/splunk-users/members/add"
    result = None
    while result == None or re.search("Authorization\s*failed",result) is not None:
        mailinglist_pw = getpass.getpass("Splunk Users Mailing List Admin Password: ")
        data = urllib.urlencode({'adminpw': mailinglist_pw})
        result = opener.open(url,data).read()
    return opener


def get_splunk_users(splunk_hosts, splunk_username, splunk_passwd):
    splunk_user_emails = []
    for host in splunk_hosts.split(","):
        try:
            splunk_service = client.connect(
                host = host,port=8089,
                username=splunk_username,
                password = splunk_passwd
                )
            users = splunk_service.users.list(count=-1)
            for user in users:
                if user.email is None or user.email.find("@") == -1:
                    print "User {0} on host {1} doesn't have correct email".format(user.name,host)
                    continue
                splunk_user_emails.append(user.email.lower())
        except socket.error as e:
            print "Connection to Splunk host {0} at port 8089 Failed".format(host)
    return set(splunk_user_emails)


def add_mailinglist_user(opener,email):
    url = "http://lists.tm.tmcs/mailman/admin/splunk-users/members/add"
    data = urllib.urlencode({
        'subscribees': email,
        'send_welcome_msg_to_this_batch': '0',
        'subscribe_or_invite': '0',
        'send_notifications_to_list_owner': '0'
        })
    result = opener.open(url,data).read()
    if re.search("Already\s*a\s*member",result) is not None:
        print "{0} is already a member".format(email)
    if re.search("Successfully\s*subscribed", result) is not None:
        print "Successfully subscribed: {0}".format(email)


if __name__ == "__main__":
    args = parse_args()
    opener = mailinglist_admin_login()
    while True:
        args.splunk_password = getpass.getpass("Password for Splunk User {0}: ".format(args.splunk_username))
        try:
            splunk_users_emails = get_splunk_users(args.splunk_hosts, args.splunk_username, args.splunk_password)
        except splunklib.binding.AuthenticationError, e:
            print "Incorrect Password for Account: {0}".format(args.splunk_username)
            continue
        except:
            raise
        else:
            break
    for each_email in splunk_users_emails:
        add_mailinglist_user(opener,each_email)
