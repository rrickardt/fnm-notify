#!/usr/bin/python

import smtplib
import sys
from sys import stdin
import optparse
import sys
import logging
import redis
import subprocess

LOG_FILE = "/var/log/fastnetmon-notify.log"
MAIL_HOSTNAME="localhost"
MAIL_FROM="root@flow.in.o2bs.sk"
#MAIL_TO="bohuslav.plucinsky@o2.sk,rastislav.rickardt@o2bs.sk"
MAIL_TO="rastislav.rickardt@o2bs.sk"


#sendmailto=['bohuslav.plucinsky@o2.sk', 'rastislav.rickardt@o2bs.sk']
sendmailto=['rastislav.rickardt@o2bs.sk']


logger = logging.getLogger("DaemonLog")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(formatter)
logger.addHandler(handler)


r = redis.StrictRedis(host='localhost', port=6379, db=0)
client_ip_as_string=sys.argv[1]
data_direction=sys.argv[2]
pps_as_string=int(sys.argv[3])
action=sys.argv[4]

logger.info(" - " . join(sys.argv))

def setban(client_ip_as_string):
    flows = [line.splitlines() for line in sys.stdin if client_ip_as_string in line][1:]
    flows = [str(flow)[29:].translate(None,'>').replace(': ',':').replace('  ',' ').split()[0:4] for flow in flows]
    addrule = "gobgp global rib -a flowvpn4 add rd 28952:2 match source %s/32 source-port %s destination %s/32 destination-port %s protocol %s then discard"
    output = []
    for flow in flows:
       srcip = str(flow[0]).split(':')[0]
       srcport =  str(flow[0]).split(':')[1]
       dstip = str(flow[1]).split(':')[0]
       dstport = str(flow[1]).split(':')[1]
       proto =  str(flow[2]).split(':')[1]
       flags =  str(flow[3]).split(':')[1]
       #flags are unused for now
#       output.append (addrule %(srcip, srcport, dstip, dstport, proto))
       cmdout = ['gobgp', 'global', 'rib', '-a', 'flowvpn4', 'add', 'rd', '28952:2', 'match', 'source', srcip + '/32', 'source-port', srcport, 'destination', dstip+'/32', 'destination-port', dstport, 'protocol', proto, 'then', 'discard']
#       output.append(['gobgp', 'global', 'rib', '-a', 'flowvpn4', 'add', 'rd', '28952:2', 'match', 'source', srcip + '/32', 'source-port', srcport, 'destination', dstip+'/32', 'destination-port', dstport, 'protocol', proto, 'then', 'discard'])
       output.append(cmdout)
    return output


def getredisdata(client_ip_as_string):
    redisout = []
    runout = []
    query = r.get(client_ip_as_string + '_packets_dump').splitlines()
    return [line[27:].translate(None,'>').replace(': ',':').replace('  ',' ').split() for line in query if "sample" in line]

def makeredisrule(action):
    rules = getredisdata(client_ip_as_string)
    addrule = "gobgp global rib -a flowvpn4 %s rd 28952:2 match source %s/32 source-port %s destination %s/32 destination-port %s protocol %s then discard"
    cmd = []
    for tuple in rules:
        if action == 'ban':
          act = "add"
        elif action == 'unban':
          act = "del"
        else:
          sys.exit(0)
        srcip = tuple[0].split(':')[0]
        sport = tuple[0].split(':')[1]
        dstip = tuple[1].split(':')[0]
        dport = tuple[1].split(':')[1]
        proto = tuple[2].split(':')[1]
        flags = tuple[3].split(':')[1]
       # cmd.append (addrule %(act, srcip, sport, dstip, dport, proto))
        cmd.append(['gobgp', 'global', 'rib', '-a', 'flowvpn4', act, 'rd', '28952:2', 'match', 'source', srcip+'/32', 'source-port', sport, 'destination', dstip+'/32', 'destination-port', dport, 'protocol', proto, 'then', 'discard'])
#    print cmd
    return cmd

def mail(subject, body):
    fromaddr = MAIL_FROM
    toaddrs  = [MAIL_TO]

    # Add the From: and To: headers at the start!
    headers = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n"
           % (
                fromaddr,
                ", ".join(toaddrs), 
                subject
            )
    )

    msg = headers + body

    server = smtplib.SMTP(MAIL_HOSTNAME)
    #server.set_debuglevel(1)
#    server.sendmail(fromaddr, toaddrs, msg)
    server.sendmail(fromaddr, sendmailto, msg)


    server.quit()


if action == "unban":
    subject = "Flowmon: IP %(client_ip_as_string)s unblocked, %(data_direction)s attack with power %(pps_as_string)d pps" % {
        'client_ip_as_string': client_ip_as_string,
        'data_direction': data_direction,
        'pps_as_string' : pps_as_string,
        'action' : action
    }

#    mail(subject, "unban")
#    mail(subject, str(makeredisrule(action)))
    for line in makeredisrule(action):
       subprocess.call(line) 
#    print makeredisrule(action)

    sys.exit(0)
elif action == "ban":
    subject = "Flowmon: IP %(client_ip_as_string)s information, %(data_direction)s attack with power %(pps_as_string)d pps" % {
        'client_ip_as_string': client_ip_as_string,
        'data_direction': data_direction,
        'pps_as_string' : pps_as_string,
        'action' : action
    }

    body = "".join(sys.stdin.readlines())
#    body = "test"
    mail(subject, body)
    

    sys.exit(0)
elif action == "attack_details":
    subject = "Flowmon: IP %(client_ip_as_string)s blocked, %(data_direction)s attack with power %(pps_as_string)d pps" % {
        'client_ip_as_string': client_ip_as_string,
        'data_direction': data_direction,
        'pps_as_string' : pps_as_string,
        'action' : action
    }
#    body = "".join(sys.stdin.readlines())
    
#    body =  str(setban(client_ip_as_string))
#    body = setban(client_ip_as_string)
#    mail(subject, body)
#    print body 
    for line in setban(client_ip_as_string):
       subprocess.call(line)

    sys.exit(0)
else:
    sys.exit(0)





