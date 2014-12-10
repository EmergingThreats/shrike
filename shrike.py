#!/usr/bin/python
import tailer
import requests
import re
import json
import pprint
import struct
import socket
import time
import sys
import os
import urlparse
import random
import string
import urllib

alert_search_list_sid = []
alert_search_list_msg_re = []
http_search_list = []
autofire_blacklist = []
http_stack = []
http_stack_limit = 100000
alert_stack = []
alert_stack_limit = 200
alert_stack_timeout = 300
buffer_full = False
cuckoo_api = {"proxies": None, "user": None, "pass": None, "verifyssl": False, "target_append": None, "target_prepend": None}
googledoms = ["google.co.uk","google.com.ag","google.com.au","google.com.ar","google.com.br","google.ca","google.co.in","google.cn"]
WORDS=[]

################
# Requires requests
# pip install requests
# 
# Requires words file
# sudo apt-get install dictionaries-common wamerican wbritish
############### 


#### suricata.yaml eve config ####
#  - eve-log:
#      enabled: yes
#      type: file
#      filename: eve.json
#      types:
#        - alert
#        - http:
#            extended: yes     # enable this for extended logging information
#      append: yes
#
#################################

#send_method
#url Send Original url for match
#referer Match URL Send Referer
#landing If referer is found send landing URL

#search_type
#alert_sid
#alert_msg_re
#http_uri
#http_refer
#http_uri_re
#http_referer_re
#http_host
#http_host_re
#dest_ip
#src_ip

#hash_type
#hash4 hash of src,dst,sport,dport useful for landing page sigs where we know the refering site should be present in the flow
#haship hash of ip's useful when trying to find referer from say a java alert where EK entry will be on a seperate flow

#match
#if search type is alert_sid you must provide the signature id
#if search type is a none _re match we simply look for a match anywhere in the target buffer
#if search type is a _re match we compile the provided regex and try to match in the target buffer

#split these out to keep lists for event types as small as possible

def ip_to_uint32(ip):
   t = socket.inet_aton(ip)
   return struct.unpack("!I", t)[0]

def uint32_to_ip(ipn):
   t = struct.pack("!I", ipn)
   return socket.inet_ntoa(t)

def build_url_from_entry(hentry):
    if hentry["http"].has_key("url"):
        build_url = "http://"
        if hentry["http"].has_key("hostname"):
            build_url = build_url + hentry["http"]["hostname"]
        else:
            build_url = build_url + hentry["dest_ip"]

        if hentry["dest_port"] != "80":
            build_url = build_url + ":%s" % (hentry["dest_port"])
        build_url = build_url + hentry["http"]["url"]
        return build_url
    else:
        return None

def random_alpha_numeric(len):
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for i in range(len))
def random_alpha_numeric_upper(len):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(len))
def random_alpha_numeric_lower(len):
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(len))
def random_alpha_upper(len):
    return ''.join(random.choice(string.ascii_uppercase) for i in range(len))
def random_alpha_upper(len):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(len))
def random_alpha_mixed(len):
    return ''.join(random.choice(string.ascii_lowercase + string.ascii_lowercase) for i in range(len))
def random_yahoo_thingy(len):
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits + "-" + "_") for i in range(len))

def gen_fake_google(target,from_list):
    print "making fake google"
    dom = ""
    if from_list:
        dom = "www." + random.choice(googledoms)
    else:
        dom = "www.google.com"
    fake_url = "http://%s/url?sa=t&rct=j&q=&esrc=web&cd=%s&cad=rja&uact=%s&ved=%s&url=%s&ei=%s&usg=%s&bvm=bv.%s,d.%s" % (dom,random.randint(1,9),random.randint(1,9),random_alpha_numeric(8),urllib.quote_plus(target),random_alpha_numeric(22),random_alpha_numeric(32),random.randint(70000000, 80000000),random_alpha_numeric(3))
    return fake_url

def gen_fake_yahoo(target):
    print "making fake yahoo"
    dom = "r.search.yahoo.com"
    fake_url = "http://%s/_ylt=%s;_ylu=%s/RV=2/RE=%s/RU=%s/RK=0/RS=%s.%s" % (dom,random_yahoo_thingy(random.randint(9,20)),random_yahoo_thingy(random.randint(9,20)),int(time.time()),urllib.quote_plus(target),random_yahoo_thingy(random.randint(9,20)),random_yahoo_thingy(random.randint(9,20)))
    return fake_url

def gen_fake_bing():
     print "making fake bing"
     fake_url = "http://www.bing.com/search?q=" + random.choice(WORDS).rstrip() + "&form=" + random_alpha_upper(random.randint(1,6)) 
     return fake_url

def target_prepend_gen(target):
    return None
def target_append_gen(target):
##### Referer Injection ############
#    choice = random.randint(1,3)
#    if choice == 1:
#        fakeurl = "&SomeParam=" + gen_fake_google(target,False)
#    elif choice == 2:
#        fakeurl = "&SomeParam=" + gen_fake_bing()
#    elif choice == 3:
#        fakeurl = "&SomeParam=" + gen_fake_yahoo(target)
#    return fakeurl
    return None

def autofire(target):
    #see http://docs.python-requests.org/en/latest/ for requests
    if autofire_blacklist:
        for e in autofire_blacklist:
            if e["cmatch"].search(target) != None:
                print "Not sending %s as it matches our autofire blacklist" % (target)
                return 
    try:
        if cuckoo_api["target_prepend"]:
            target = cuckoo_api["target_prepend"] + target

        else:
            tprepend = target_prepend_gen(target)
            if tprepend:
                target = tprepend + target

        if cuckoo_api["target_append"]:
            target = target + cuckoo_api["target_append"]
        else:
            tappend = target_append_gen(target)
            if tappend:
                target = target + tappend

        data=dict(url=target)
        response = requests.post(cuckoo_api["url"], auth=(cuckoo_api["user"],cuckoo_api["pass"]), data=data, proxies=cuckoo_api["proxies"], verify=cuckoo_api["verifyssl"])
        print response
    except Exception as e:
        print "failed to send target:%s reason:%s" % (target,e)

def search_http_for_alert(e):
    try:
        for hentry in http_stack:
            match_found = False
            if e.has_key("hash4") and hentry["hash4"] == e["hash4"]:
                print ("hash match hash4 %s and %s" % (hentry["hash4"],e["hash4"])) 
                match_found = True
            elif e.has_key("haship") and hentry["haship"] == e["haship"]:
                print ("hash match haship %s and %s" % (hentry["haship"],e["haship"]))
                match_found = True

            if match_found:
                print ("hash match %s and %s" % (hentry,e))
                if (e["send_method"] == "referer" or e["send_method"] == "landing") and hentry["http"].has_key("http_refer") and hentry["http"].has_key("hostname") and hentry["http"]["hostname"]:
                    url = urlparse.urlsplit(hentry["http"]["http_refer"])
                    if hentry["http"]["hostname"] != url.hostname:
                        if e["send_method"] == "referer":
                            print "autofiring %s from search_http_for_alert" % (hentry["http"]["http_refer"])
                            autofire(hentry["http"]["http_refer"])
                            return match_found
                        elif e["send_method"] == "landing":
                            fire = build_url_from_entry(hentry)
                            if fire != None:
                                print "autofiring %s from search_http_for_alert" % (fire)
                                autofire(fire)
                                return match_found

                elif e["send_method"] == "url" and hentry["http"].has_key("url"):
                    fire = build_url_from_entry(hentry)
                    if fire != None:
                        print "autofiring %s from search_http_for_alert" % (fire)
                        autofire(fire)
                        return match_found

    except Exception as e:
        print "Exception resolving alert to url %s " % (e)
        return False 
    return match_found

def http_check_search_list(e):
    match_found = False
    for sle in http_search_list:
        if sle["search_type"] == "dest_ip":          
            if e["dest_ip"] == sle["match"]:
                match_found = True
        elif sle["search_type"] == "src_ip":          
            if e["src_ip"] == sle["match"]:
                match_found = True
        elif sle["search_type"] == "http_uri":          
            if sle["match"] in e["http"]["url"]:
                match_found = True
        elif sle["search_type"] == "http_referer":          
            if e["http"].has_key("http_refer") and sle["match"] in e["http"]["http_refer"]:
                match_found = True
        elif sle["search_type"] == "http_host":          
            if e["http"].has_key("hostname") and sle["match"] in e["http"]["hostname"]:
                match_found = True
        elif sle["search_type"] == "http_uri_re":          
            if e["http"].has_key("url") and sle["cmatch"].search(e["http"]["url"]) != None:
                match_found = True
        elif sle["search_type"] == "http_referer_re":          
            if e["http"].has_key("http_refer") and sle["cmatch"].search(e["http"]["http_refer"]) != None:
                match_found = True
        elif sle["search_type"] == "http_host_re":          
            if e["http"].has_key("hostname") and sle["cmatch"].search(e["http"]["hostname"]) != None:
                match_found = True
        else:
            print "skiping entry %s no supported search type found" % (sle)
            continue

        if match_found:       
            if sle["send_method"] == "referer" and e["http"].has_key("http_refer"):
                print "autofiring referer %s from http_search_list" % (e["http"]["http_refer"])
                autofire(e["http"]["http_refer"])
            elif sle["send_method"] == "url" and e["http"].has_key("url"):
                build_url = "http://"
                if e["http"].has_key("hostname"):
                    build_url = build_url + e["http"]["hostname"]
                else:
                    build_url = build_url + e["dest_ip"]

                if e["dest_port"] != "80":
                    build_url = build_url + ":%s" % (e["dest_port"])
                build_url = build_url + e["http"]["url"]
                print "autofiring url %s from http_search_list" % (build_url)
                autofire(build_url)
    return match_found

def alert_check_search_list(e):
    alert_sid_match = False
    for asl in alert_search_list_sid:
       if asl["search_type"] == "alert_sid" and e["alert"]["signature_id"] == asl["match"]:
           alert_sid_match = True
           entry_present = False
           if len(alert_stack) >= alert_stack_limit:
               alert_stack.pop(0)
           if asl["hash_type"] == "hash4":
                e["hash4"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"]) + e["src_port"] + e["dest_port"]
                for centry in alert_stack:
                     if centry.has_key("hash4") and e["hash4"] == centry["hash4"]:
                         entry_present == True
           elif asl["hash_type"] == "haship":
                e["haship"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"])
                for centry in alert_stack:
                     if centry.has_key("haship") and e["haship"] == centry["haship"]:
                         entry_present == True
           else:
                print "not adding alert unknown hash type in %s" % (asl)
                continue

           if entry_present:
               continue 

           e["send_method"] = asl["send_method"]
           e["timeout"] = int(time.time()) + alert_stack_timeout

           
           print "http search start %s" % (int(time.time()))
           found = search_http_for_alert(e)
           print "http search end %s" % (int(time.time()))
           if found:
               e["fired"] = True
           else:
               e["fired"] = False
               print "alert not found searching existing logs adding to alert stack %s" % (e)
           alert_stack.append(e)

    #Give static sids priority over RE matches. If we match we should hit the alert stack hash.
    if not alert_sid_match:
        for asl in alert_search_list_msg_re:
            if asl["search_type"] == "alert_msg_re" and asl["cmatch"].search(e["alert"]["signature"]) != None:
                entry_present = False
                print "REGEX alert MSG Match %s matchs %s" % (e["alert"]["signature"],asl["match"])
                if len(alert_stack) >= alert_stack_limit:
                    alert_stack.pop(0)
                if asl["hash_type"] == "hash4":
                    e["hash4"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"]) + e["src_port"] + e["dest_port"]
                    for centry in alert_stack:
                        if centry.has_key("hash4") and e["hash4"] == centry["hash4"]:
                            entry_present == True
                elif asl["hash_type"] == "haship":
                    e["haship"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"])
                    for centry in alert_stack:
                         if centry.has_key("haship") and e["haship"] == centry["haship"]:
                             entry_present == True
                else:
                    print "not adding alert unknown hash type in %s" % (asl)
                    continue

                if entry_present:
                   continue

                e["send_method"] = asl["send_method"]
                e["timeout"] = int(time.time()) + alert_stack_timeout

                print "http search start %s" % (int(time.time()))
                found = search_http_for_alert(e)
                print "http search end %s" % (int(time.time()))
                if found:
                    e["fired"] = True
                else:
                    e["fired"] = False
                    print "alert not found searching existing logs adding to alert stack %s" % (e)
                alert_stack.append(e)

#Start#
print "Start time:%s" % (int(time.time()))
try:
    f=open(sys.argv[1])
    conf=json.load(f)
except Exception as e:
    print "failed to load shrike config file %s\nshrike.py <conf.json>" % (e)
    sys.exit(1)

#Parse alert_search_list
if conf.has_key("alert_search_list"):
    for e in conf["alert_search_list"]:
        if e["search_type"] == "alert_msg_re":
            try:
                e["cmatch"] = re.compile(e["match"])
                alert_search_list_msg_re.append(e)  
            except Exception as err:
                print "failed to compile regex for re match %s" % (e)
                sys.exit(1)
        elif e["search_type"] == "alert_sid":
            alert_search_list_sid.append(e)

#wordlist gen
if conf.has_key("wordlist"):
    try:
        WORDS=open(conf["wordlist"]).readlines()
    except:
        print "failed to get words from user specified list %s" % (conf["wordlist"])
        sys.exit(1)
else:
    try:
        print "trying default location of /etc/dictionaries-common/words"
        WORDS=open("/etc/dictionaries-common/words").readlines()
    except:
        try:
            print "trying default location of /usr/share/dict/words"
            WORDS=open("/usr/share/dict/words").readlines()
        except:
            print "could not loading anything. See reqs. Until then, WORDS will consist of KillerKittens"
            WORDS = ["KillerKittens"]
            
#Parse http_search_list
if conf.has_key("http_search_list"):
    http_search_list = conf["http_search_list"]

    for e in http_search_list:
        if e["search_type"] == "http_uri_re" or e["search_type"] == "http_referer_re" or e["search_type"] == "http_host_re":
            try:
                e["cmatch"] = re.compile(e["match"])
            except Exception as err:
                print "failed to compile regex for re match %s" % (e)
                sys.exit(1)

#autofire blacklist
if conf.has_key("autofire_blacklist"):
    autofire_blacklist = conf["autofire_blacklist"]
    for e in autofire_blacklist:
        if e["search_type"] == "re":
            try:
                e["cmatch"] = re.compile(e["match"])
            except Exception as err:
                print "failed to compile regex for re match %s" % (e)
                sys.exit(1)

#http_stack_limit the number of lines we keep in buffer defaults to 100k
if conf.has_key("http_stack_limit") and conf["http_stack_limit"]:
    http_stack_limit = conf["http_stack_limit"]

#alert_stack_timeout the amount of time to remove an alert from the alert stack
if conf.has_key("alert_stack_timeout") and conf["alert_stack_timeout"]:
    alert_stack_timeout = conf["alert_stack_timeout"]

#alert_stack_limit the maximum number of active alerts to deal with
if conf.has_key("alert_stack_limit") and conf["alert_stack_limit"]:
    alert_stack_limit = conf["alert_stack_limit"]

#get settings for cuckoo_api url
if conf.has_key("cuckoo_api"):
    if conf["cuckoo_api"].has_key("url"):
        cuckoo_api["url"] = conf["cuckoo_api"]["url"]
    else:
        print "You must specify a url setting in the cuckoo_api portion of the config"
        sys.exit(1)

    #do or do not perform ssl verification. There is no try
    if conf["cuckoo_api"].has_key("verifyssl") and conf["cuckoo_api"]["verifyssl"] == 1:
        cuckoo_api["verifyssl"] = True 
    #basic auth stuff
    if conf["cuckoo_api"].has_key("user") and not conf["cuckoo_api"].has_key("pass"): 
        print "basic auth user specified but no password"
        sys.exit(1)
    elif conf["cuckoo_api"].has_key("pass") and not conf["cuckoo_api"].has_key("user"):
        print "basic auth pass specified but no user"
        sys.exit(1)
    elif conf["cuckoo_api"].has_key("user") and conf["cuckoo_api"]["user"] and conf["cuckoo_api"].has_key("pass") and conf["cuckoo_api"]["pass"]:
        cuckoo_api["user"] = conf["cuckoo_api"]["user"]
        cuckoo_api["pass"] = conf["cuckoo_api"]["pass"]
    #proxy
    if conf["cuckoo_api"].has_key("proxies") and conf["cuckoo_api"]["proxies"]:
        cuckoo_api["proxies"] = conf["cuckoo_api"]["proxies"]

    #if specified prepend something to the target uri
    if conf["cuckoo_api"].has_key("target_prepend"):
        cuckoo_api["target_prepend"] = conf["cuckoo_api"]["target_prepend"]

    #if specified append something to the target uri
    if conf["cuckoo_api"].has_key("target_append"):
        cuckoo_api["target_append"] = conf["cuckoo_api"]["target_append"]

else:
   print "did not find cuckoo_api key bailing"
   sys.exit(1)
#Get path to eve file and make sure it exists
if conf.has_key("eve_file"):
   if not os.path.exists(conf["eve_file"]):
       print "specified eve file does not exist %s" % (conf["eve_file"])
       sys.exit(1) 
else:
    print "No eve file specified with 'eve_file' key in config"
    sys.exit(1)

for line in tailer.follow(open(conf["eve_file"])):
    try:
        e = json.loads(line)
        if e["event_type"] == "http":
            if len(http_stack) >= http_stack_limit:
                if buffer_full == False:
                    print "HTTP Buffer Full: %s" % (int(time.time()))
                    buffer_full = True
                http_stack.pop(0)
            e["hash4"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"]) + e["src_port"] + e["dest_port"]
            e["haship"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"]) 
            http_stack.append(e)

            if http_search_list:
                try:
                    http_check_search_list(e)
                except Exception as err:
                    print "failed to run http_entry_search %s" % (err)

            if len(alert_stack) > 0:
                for a in alert_stack[:]:
                    if a["timeout"] < int(time.time()):
                        print "removing alert with hash %s due to timeout" % (a)
                        alert_stack.remove(a)
                    elif a.has_key("hash4"):
                        if e["hash4"] == a["hash4"] and a["fired"] == False:
                            print ("hash match %s and %s" % (a,e))
                            if e["http"].has_key("http_refer") and e["http"].has_key("hostname") and e["http"]["hostname"] not in e["http"]["http_refer"]:
                                print "autofiring entry found after alert %s " % (e["http"]["http_refer"])
                                autofire(e["http"]["http_refer"])
                                a["fired"] = True
                    elif a.has_key("haship"):
                        if e["haship"] == a["haship"] and a["fired"] == False:
                            print ("hash match %s and %s" % (a,e))
                            if e["http"].has_key("http_refer") and e["http"].has_key("hostname") and e["http"]["hostname"] not in e["http"]["http_refer"]:
                                print "autofiring entry after alert %s" % (e["http"]["http_refer"])
                                autofire(e["http"]["http_refer"])
                                a["fired"] = True
                    else:
                            alert_stack.remove(a)

        if e["event_type"] == "alert":
            try:
                alert_check_search_list(e)     
            except Exception as err:
                print "failed to run alert_check_search %s" % (err)

    except Exception as e:
        print "Exception parsing line %s:\n%s\n%s" % (e,line,sys.exc_info()[-1].tb_lineno)
