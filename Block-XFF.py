import os
import json
import time
import urllib2
import ssl
from xml.etree import ElementTree

#Firewall Details
gwMgmtIp = FW_MGT_IP
apiKey = FW_API_KEY

username = "baduser"
useridtimeout = "20"

aggressive_mode = "DISABLE"

fw_cmd1 = "https://"+gwMgmtIp+"/api/?type=user-id&action=set&key="+apiKey+"&cmd="+"%3Cuid-message%3E%3Cversion%3E1.0%3C/version%3E%3Ctype%3Eupdate%3C/type%3E%3Cpayload%3E%3Clogin%3E%3Centry%20name=%22"+username+"%22%20ip=%22"
fw_cmd2 = "%22%20timeout=%22"+useridtimeout+"%22%3E%3C/entry%3E%3C/login%3E%3C/payload%3E%3C/uid-message%3E"

fw_url_log_cmd1 = "https://"+gwMgmtIp+"/api/?type=log&log-type=url&key="+apiKey+"&dir=forward&query=((sessionid%20eq%20'"
fw_url_log_cmd2 = "')%20and%20(natsport%20eq%20'"
fw_url_log_cmd3 = "')%20and%20(receive_time%20geq%20'"
fw_url_log_cmd4 = "'))"

fw_url_xff_cmd = "https://"+gwMgmtIp+"/api/?type=log&action=get&key="+apiKey+"&job-id="

def uid_mapper(ipaddress):
    cmd = fw_cmd1+ipaddress+fw_cmd2
    response = urllib2.urlopen(cmd, timeout=5).read()
    print "Response from IP Mapping = ", response
    return

def url_log_jobid_extracter1(sessionid, natsport, rxtime):
    cmd = fw_url_log_cmd1+str(sessionid)+fw_url_log_cmd2+str(natsport)+fw_url_log_cmd3+rxtime.split(" ")[0]+"%20"+rxtime.split(" ")[1]+fw_url_log_cmd4
    print "The command to extract jobid is", cmd
    response = urllib2.urlopen(cmd, timeout=5).read()
    dom = ElementTree.fromstring(response)
    jobid = dom[0].find('job').text
    return jobid

def xff_extracter(jobid):
    cmd = fw_url_xff_cmd+str(jobid)
    print "The command to extract XFF is", cmd
    response = urllib2.urlopen(cmd, timeout=5).read()
    dom = ElementTree.fromstring(response)
    if dom[0][1][0].attrib['count'] == "0":
        return "RETRY"
    else:
        xff = dom.find('./result/log/logs/entry/xff').text
        return xff

print('Loading Function')
postreqdata = json.loads(open(os.environ['req']).read())
response = open(os.environ['res'], 'w')
response.write("hello world from "+postreqdata['sessionid'])
sessionid = postreqdata['sessionid']
natsport = postreqdata['natsport']
rxtime = postreqdata['receive_time']
response.close()
count = 0

print('Session id is:', sessionid)
print("NAT SPORT is:", natsport)
print("Receive time is:", rxtime)

while True:
    jobid = url_log_jobid_extracter1(sessionid, natsport, rxtime)
    print('Job id is:', jobid)
    print("Sleeping for 5 seconds...")
    time.sleep(5)
    xff = xff_extracter(jobid)
    if xff == "RETRY":
        count += 1
    else:
        print "XFF = ", xff
        ipaddress = xff.split(":")[0]
        print "Number of times through loop = ", count
        print "IP Address of XFF = ", ipaddress
        break
if ipaddress:
    uid_mapper_result = uid_mapper(ipaddress)
    print "uid_mapper_result = ", uid_mapper_result