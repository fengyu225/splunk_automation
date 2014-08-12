import argparse
import splunklib.client as client
import splunklib.binding
from itertools import product
import getpass


def parse_args():
    options = argparse.ArgumentParser("Script for adding/removing user roles")
    options.add_argument("-s","--splunk-server", action="store", dest="host", required=True,help="Set Hostname of Splunk     Search Head")
    options.add_argument("-l","--port", action="store",dest="port",default=8089,help="Set Rest API port on   Splunk Search Head - Default Set to 8089",type=int)
    options.add_argument("-u","--username", action="store", dest="username",required=True, help="Set Login  username")
    options.add_argument("-v","--users", action="store", dest="users", default="all", help="Set Users whose Roles You're going to work with, separate by a space('all' for All Users).")
    options.add_argument("-a","--action", action="store", dest="action", required=True, choices=['+', '-'], help="Set Action to be Taken on Users' Roles, + for add roles and - for remove roles")
    options.add_argument("-r","--roles", action="store", dest="roles", required=True, help="Set Roles You're going to Add to or Remove from Users, separate by a space.")

    args = options.parse_args()

    return args


def change_role(user_role_action):
    user,role,action = user_role_action
    if action=="+":
        user.roles.append(role.name)
    else:
        try:
            user.roles.remove(role.name)
        except ValueError:
            print "User %s doesn't have role %s" % (user.name, role.name)
            return
    if user.roles == []:
        print "User %s only has 1 role %s, the role cannot be removed" % (user.name, role.name)
    else:
        user.update(roles=user.roles).refresh()


if __name__ == "__main__":
    args = parse_args()
    while True:
        args.password = getpass.getpass("Password for Splunk User {0}: ".format(args.username))
        try:
            service = client.connect(
                    host=args.host,
                    port=args.port,
                    username=args.username,
                    password=args.password)
        except splunklib.binding.AuthenticationError, e:
            print "Incorrect Password for Splunk username: {0}".format(args.username)
            continue
        except:
            raise
        else:
            break
    #get correct users(exist in Splunk) from input user names
    all_users = service.users.list(count=-1)
    if args.users.lower().strip() == "all":
        users = all_users
    else:
        input_users = [name.lower() for name in args.users.split(" ")]
        users = [user for user in all_users if user.name in input_users]
        if len(args.users.split(" ")) != len(users):
            print "Following users are not found in Splunk:\n\t%s" % "\n\t".join(set([name.lower() for name in args.users.split(" ")])-set([u.name for u in users]))

    #get correct roles(exist in Splunk) from input roles
    all_roles = service.roles.list(count=-1)
    input_roles = [role.lower() for role in args.roles.split(" ")]
    roles = [role for role in all_roles if role.name in input_roles]
    if len(args.roles.split(" ")) != len(roles):
        print "Following roles are not found in Splunk:\n\t%s" % "\n\t".join(set([role.lower() for role in args.roles.split(" ")])-set([r.name for r in roles]))

    map(change_role, product(users,roles,args.action))
