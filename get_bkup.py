import os
import sys
import tarfile


if __name__ == "__main__":
    if len(sys.argv)<3:
        print "Pass two parameters:\n\t1). backup for exact hostname match\n\t2). Git backup repo path"
        sys.exit(1)
    backup_path = sys.argv[2].strip()
    l = os.listdir(backup_path)
    for h in sys.stdin:
        h = ".".join(h.strip().split(".")[:2]) if sys.argv[1]!='backup' else h.strip()
        r = filter(lambda x:x.startswith(h.strip()), l)
        if len(r)>0:
            with tarfile.open("{0}.tar.gz".format(h.strip()), "w:gz") as tar:
                tar.add(os.path.join(backup_path,r[0]), arcname="splunk_backups/"+r[0])
        else:
            print "Not Found in Backup Repo: {0}".format(h)
