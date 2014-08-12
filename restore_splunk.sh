ORIG_HOSTS=hosts
HOSTS=hosts_up
HOSTS_WIPE_OUT=hosts_wipe_out
BACKUP_DIR_PATH=/home/yu/splunk/splunk_backups
ONALL=/home/yu/splunk/splunk_scripts/onall

if [ ! -f $ORIG_HOSTS ]; then
    echo "no hosts file found"
    exit 1
fi

if [ ! -f get_bkup.py ]; then
    # get_bkup.py reads a list of hosts from stdin
    # then compress and save etc/ directory for each host
    echo "get_bkup.py not found"
    exit 1
fi

if [ ! -f change_config.py ]; then
    # change_config.py runs on each forwarder host
    # it changes ssl password of server.conf and outputs.conf 
    # and it adds [license] stanza and adds active_group=Forwarder
    echo "change_config.py not found"
    exit 1
fi

if [ ! -f get_cloudsys_portal_info.py ]; then
    # get_cloudsys_portal_info.py reads hosts from input file
    # and for each host it sends request to CloudSys portal asking
    # for ping status of the host. If ping status is "Up", then it writes
    # the hosts in the input file, otherwise it prints out hostname and 
    # ping status
    echo "get_cloudsys_portal_info.py not found"
    exit 1
fi

cat $ORIG_HOSTS | python get_cloudsys_portal_info.py $HOSTS

if [ ! -s $HOSTS ]; then
        echo "File hosts is empty. Do nothing."
        exit 1
else
    echo "###############################################"
    echo "copying backups to remote hosts"
    cat $HOSTS | $ONALL -t 10 -u splunk -q 'ls -1 /opt/splunk/etc/system/local/outputs.conf' | grep "No such file or directory" | grep -o "^\([^.]\+\.\)\{4\}[^:.]\+" > $HOSTS_WIPE_OUT
    cat $HOSTS_WIPE_OUT | /usr/bin/python get_bkup.py backup $BACKUP_DIR_PATH
    > hosts_temp
    for h in `cat $HOSTS_WIPE_OUT`
    do
        if [ -f "$h.tar.gz" ]
        then
            echo ${h} >> hosts_temp
        else
            echo "skip ${h}: backup not found"
        fi
    done
    mv hosts_temp $HOSTS_WIPE_OUT
    if [ ! -s $HOSTS_WIPE_OUT ]; then
        echo "No hosts wiped out or backup not found"
    else
        # if parallel-scp is installed, then use it
        if which parallel-scp > /dev/null; then
            parallel-scp -h $HOSTS_WIPE_OUT -p 3000 $h.tar.gz /tmp
        else
            for h in `cat $HOSTS_WIPE_OUT`;do echo $h;scp $h.tar.gz $h:/tmp;done;
        fi
        for h in `cat $HOSTS_WIPE_OUT`;do echo $h;scp $h.tar.gz $h:/tmp;done;
        echo "###############################################"
        echo ""
        echo "###############################################"
        echo "uncompressing backups on hosts:"
        cat $HOSTS_WIPE_OUT
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'tar xzvf /tmp/`hostname`.tar.gz -C /tmp 1>/dev/null'
        echo "###############################################"
        echo ""
        echo "###############################################"
        echo "restoring configs from backup"
        echo "copy etc/passwd"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp /tmp/splunk_backups/`hostname`/etc/passwd /opt/splunk/etc/'
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'mkdir -p /opt/splunk/etc/system/local'
        echo "copy etc/system/local/inputs.conf"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp /tmp/splunk_backups/`hostname`/etc/system/local/inputs.conf /opt/splunk/etc/system/local'
        echo "copy etc/system/local/outputs.conf"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp /tmp/splunk_backups/`hostname`/etc/system/local/outputs.conf /opt/splunk/etc/system/local'
        echo "copy etc/system/local/transforms.conf"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp /tmp/splunk_backups/`hostname`/etc/system/local/transforms.conf /opt/splunk/etc/system/local 2>/dev/null'
        echo "copy etc/system/local/web.conf"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp /tmp/splunk_backups/`hostname`/etc/system/local/web.conf /opt/splunk/etc/system/local'
        echo "copy etc/system/local/props.conf"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp /tmp/splunk_backups/`hostname`/etc/system/local/props.conf /opt/splunk/etc/system/local'
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp /tmp/splunk_backups/`hostname`/etc/system/local/*.xml /opt/splunk/etc/system/local 2>/dev/null'
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'cp -r /tmp/splunk_backups/`hostname`/etc/system/local/Backup /opt/splunk/etc/system/local 2>/dev/null'
        echo "copy change_conf.py script"
        if which parallel-scp > /dev/null; then
            parallel-scp -h $HOSTS_WIPE_OUT -p 3000 change_config.py /tmp
        else
            for i in `cat $HOSTS_WIPE_OUT`;do echo $i; scp change_config.py $i:/tmp;done;
        fi
        echo "run change_conf.py script, setting followTail for each inputs.conf stanzas"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT '/opt/splunk/bin/python /tmp/change_config.py -p /opt/splunk/etc/system/local -i 1 -f 1'
        echo "restart Splunk to apply followTail"
        $ONALL -q -t 120 -u splunk -f $HOSTS_WIPE_OUT 'sudo /etc/init.d/splunk stop' 1>/dev/null
        $ONALL -q -t 120 -u splunk -f $HOSTS_WIPE_OUT 'sudo /etc/init.d/splunk start' 1>/dev/null
        echo "Splunk is up, wait 30 seconds"
        sleep 30
        $ONALL -q -t 120 -u splunk -f $HOSTS_WIPE_OUT 'sudo /etc/init.d/splunk stop' 1>/dev/null
        echo "stop Splunk and remove followTail in each inputs.conf stanza"
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT '/opt/splunk/bin/python /tmp/change_config.py -p /opt/splunk/etc/system/local -i 0 -f 0'
        echo "###############################################"
        echo ""
        echo "###############################################"
        echo "deleting temp files"
        for h in `cat $HOSTS_WIPE_OUT`;do echo "deleting $h.tar.gz";rm $h.tar.gz;done;
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'rm -rf /tmp/splunk_backups'
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'rm  /tmp/`hostname`.tar.gz'
        $ONALL -t 10 -q -u splunk -f $HOSTS_WIPE_OUT 'rm  /tmp/change_config.py'
        echo "###############################################"
    fi
    echo ""
    echo "###############################################"
    echo "restarting Splunk on hosts:"
    cat $HOSTS
    $ONALL -q -t 120 -u splunk -f $HOSTS 'sudo /etc/init.d/splunk stop' 1>/dev/null
    $ONALL -q -t 120 -u splunk -f $HOSTS 'sudo /etc/init.d/splunk start' 1>/dev/null
    echo "###############################################"
fi
