#!/usr/bin/python
import tailer
import requests
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
#from Queue import Queue
#from threading import Thread
from multiprocessing import Process
from multiprocessing import Queue
###### doesn't seem to actually help with perf at all. Unicode strings maybe?
try:
    import re2 as re
except ImportError:
    print "failling back to normal RE engine"
    import re
else:
    re.set_fallback_notification(re.FALLBACK_WARNING)

alert_search_list_sid = []
alert_search_list_msg_re = []
alert_search_ignore_sid = []
alert_search_ignore_ip = []
http_search_list = []
autofire_blacklist = []
http_stack = []
http_stack_limit = 100000
alert_stack = []
alert_stack_limit = 200
alert_stack_timeout = 300
buffer_full = False
cuckoo_api = {"proxies": None, "user": None, "pass": None, "verifyssl": False, "target_append": None, "target_prepend": None, "do_custom":True, "do_shrike_vars":True, "options":None, "tags":None, "priority":None, "gateway":None}
googledoms = ["google.co.uk","google.com.ag","google.com.au","google.com.ar","google.com.br","google.ca","google.co.in","google.cn"]
ipre_default=re.compile(r"\b(?P<ip>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))\b")
ipre_exact=re.compile(r"^(?P<ip>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$")
scrub_ipaddys = False
WORDS=[]
cuckoo_server_list = []
cuckoo_server_groups = {}
cuckoo_servers={}
log_queue = Queue()
autofire_queue = Queue()
do_logging = False
log_file = None
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
        if len(hentry["http"]["url"]) > 6 and hentry["http"]["url"][0:7] == "http://":
            return hentry["http"]["url"]
        else: 
            build_url = "http://"
            if hentry["http"].has_key("hostname"):
                build_url = build_url + hentry["http"]["hostname"]
            else:
                build_url = build_url + hentry["dest_ip"]

            if hentry["dest_port"] != 80:
                build_url = build_url + ":%s" % (hentry["dest_port"])
            build_url = build_url + hentry["http"]["url"]
            return build_url
    else:
        return None

def gen_random_ip():
    return "%s.%s.%s.%s" % (random.choice(range(1,256)),random.choice(range(256)),random.choice(range(256)),random.choice(range(1,255)))

#This can break stuff in default mode you should specify something other than the default ipre
def ip_scrubber(url):
    reobj = ipre_default
    try:
        p=urlparse.urlparse(url)
        m=reobj.sub(gen_random_ip(),p[4])
        if m:
            utuple=(p[0],p[1],p[2],p[3],m,p[5])
            new_url=urlparse.urlunparse(utuple)
            return new_url
        else:
            return url
    except Exception as e:
        print "Problem Scrubbing ip Address"
        return url

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
#    choice = random.randint(1,3)
#    if choice == 1:
#        fakeurl = "&SgtHugoStiglitz=" + gen_fake_google(target,False)
#    elif choice == 2:
#        fakeurl = "&SgtHugoStiglitz=" + gen_fake_bing()
#    elif choice == 3:
#        fakeurl = "&SgtHugoStiglitz=" + gen_fake_yahoo(target)
#    return fakeurl
    return None

def get_hashipdom_from_flowid(e):
    tmph4 = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"]) + e["src_port"] + e["dest_port"]
    try:
        for hentry in http_stack:
            if not hentry.has_key("flow_id"):
                print "HTTP entry does not have flow_id Are you sure your on suricata-2.1.x? returning"
                return False
             
            if e["flow_id"] == hentry["flow_id"] and hentry["hash4"] == tmph4 and hentry.has_key("hashipdom"):
                 return hentry["hashipdom"]

    except Exception as e:
        print "Exception resolving alert to ipdomhash %s " % (e)
        print 'Error on line {}'.format(sys.exc_info()[-1].tb_lineno)
        return False
    return False

def autofire(target,hentry,aentry):
    cuckoo_list_final = []
    cuckoo_list_tmp = []

    if aentry.has_key("asl") and aentry["asl"].has_key("server_group") and aentry["asl"]["server_group"] and cuckoo_server_groups.has_key(aentry["asl"]["server_group"]):
        cuckoo_list_tmp = cuckoo_server_groups.has_key(aentry["asl"]["server_group"])
        if aentry["asl"].has_key("exclude_server") and aentry["asl"]["exclude_server"]:
            for e in cuckoo_server_list:
                if e["label"] not in tmplist:
                   cuckoo_list_final.append(e)
        

    elif aentry.has_key("asl") and aentry["asl"].has_key("server") and aentry["asl"]["server"]:
        print "Sending to alert specific server" 
        cuckoo_list_final.append(aentry["asl"]["server"])

    else:
        cuckoo_list_final = cuckoo_server_groups["default"]

    #see http://docs.python-requests.org/en/latest/ for requests
    if autofire_blacklist:
        for e in autofire_blacklist:
            if e["cmatch"].search(target) != None:
                print "Not sending %s as it matches our autofire blacklist" % (target)
                return
    if scrub_ipaddys:
        target = ip_scrubber(target)

    try:
        if len(cuckoo_list_final) == 0:
            print "Error empty cuckoo list"
        for f in cuckoo_list_final:
            if cuckoo_servers.has_key(f):
                e = cuckoo_servers[f]
            else:
                continue
 
            custom_string=None
            shrike_sid = None
            shrike_msg = None
            shrike_url = None
            shrike_refer = None           
            skip_mangle = False
            gateway_string = None
            fakeref = None
            if aentry["asl"].has_key("no_server_target_mangle") and aentry["asl"]["no_server_target_mangle"] != 1:
                skip_mangle = True

              
            if skip_mangle == False:
                if e["target_prepend"]:
                    target = e["target_prepend"] + target
                else:
                    tprepend = target_prepend_gen(target)
                    if tprepend:
                        target = tprepend + target

                if e["target_append"]:
                    target = target + e["target_append"]
                else:
                    tappend = target_append_gen(target)
                    if tappend:
                        target = target + tappend

            #send ifnormation about the rule hit and http entries
            if e["do_custom"]:
                if scrub_ipaddys:
                    hurl = ip_scrubber(build_url_from_entry(hentry))
                else:
                    hurl = build_url_from_entry(hentry)
                custom_string = "shrike: %s,%s,%s" % (aentry["alert"]["signature_id"],aentry["alert"]["signature"],hurl)
                if hentry["http"].has_key("http_refer") and hentry["http"]["http_refer"]:
                    if scrub_ipaddys:
                        refurl = ip_scrubber(hentry["http"]["http_refer"])
                    else:
                        refurl = hentry["http"]["http_refer"]
                    custom_string = "%s,referer:%s" % (custom_string,refurl) 

            #shrike 
            if e["do_shrike_vars"]:
                shrike_sid = aentry["alert"]["signature_id"]
                shrike_msg = aentry["alert"]["signature"]
                shrike_url = build_url_from_entry(hentry)
                if hentry["http"].has_key("http_refer") and hentry["http"]["http_refer"]:
                    shrike_refer = "%s" % (hentry["http"]["http_refer"])

            #specify options if present
            if e["options"]:
                options_string=e["options"]
            else:
                options_string=None

            if e["gen_fake_refer"]:
                choice = random.randint(1,3)
                if choice == 1:
                    fakeref = gen_fake_google(target,False)
                elif choice == 2:
                    fakeref =  gen_fake_bing()
                elif choice == 3:
                    fakeref = gen_fake_yahoo(target)
                print "using fake referer %s" % (fakeref)                
            #specify tags if present
            if e["tags"]:
                tags_string=e["tags"]
            else:
                tags_string=None

            #specify priority if present
            if e["priority"]:
                priority_string=int(e["priority"])
            else:
                priority_string=None

            #specify gateway if present
            if e["gateway"]:
                gateway_string=e["gateway"]

            #Do the alert tags
            if aentry["asl"].has_key("package"):
                package_string=aentry["asl"]["package"]
            else:
                package_string=None

            if aentry["asl"].has_key("timeout"):
                timeout_string=aentry["asl"]["timeout"]
            else:            
                timeout_string=None
            
            if aentry["asl"].has_key("priority"):
                priority_string=aentry["asl"]["priority"]
            else:
                priority_string=None

            if aentry["asl"].has_key("machine"):
                machine_string=aentry["asl"]["machine"]
            else:
                machine_string=None

            if aentry["asl"].has_key("platform"):
                platform_string=aentry["asl"]["platform"]
            else:
                platform_string=None

            if aentry["asl"].has_key("gateway"):
                gateway_string=aentry["asl"]["gateway"]

            if aentry["asl"].has_key("options"):
                if options_string:
                   options_string += ",%s" % (aentry["asl"]["options"])
                else:
                   options_string = aentry["asl"]["options"]

            if aentry["asl"].has_key("tags"):
                if tags_string:
                   tags_string += ",%s" % (aentry["asl"]["tags"])
                else:
                   tags_string = aentry["asl"]["options"]
             
            #if aentry
            data=dict(url=target,custom=custom_string,options=options_string,tags=tags_string,shrike_sid=shrike_sid,shrike_refer=shrike_refer,shrike_msg=shrike_msg,shrike_url=shrike_url,package=package_string,timeout=timeout_string,priority=priority_string,machine=machine_string,platform=platform_string,gateway=gateway_string,referer=fakeref)
            response = requests.post(e["url"], auth=(e["user"],e["pass"]), data=data, proxies=e["proxies"], verify=e["verifyssl"])
    except Exception as err:
        print "failed to send target:%s reason:%s" % (target,err)

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
            elif e.has_key("hashipdom") and hentry.has_key("hashipdom") and hentry["hashipdom"] == e["hashipdom"]:
                print ("hash match hashipdom %s and %s" % (hentry["hashipdom"],e["hashipdom"]))
                match_found = True

            if match_found:
                print ("hash match %s and %s" % (hentry,e))
                tstamp=hentry["timestamp"]
                if e.has_key("http_matches"):
                   if e["http_matches"].has_key(tstamp):
                       continue
                   else:
                       e["http_matches"][tstamp]=hentry.copy()
                else:
                    e["http_matches"]={}
                    e["http_matches"][tstamp]=hentry.copy()
   
                if(e["asl"]["send_method"] == "referer" or e["asl"]["send_method"] == "landing") and hentry["http"].has_key("http_refer") and hentry["http"].has_key("hostname") and hentry["http"]["hostname"]:
                    url = urlparse.urlsplit(hentry["http"]["http_refer"])
                    if hentry["http"]["hostname"] != url.hostname:
                        if e["asl"]["send_method"] == "referer":
                            print "autofiring %s from search_http_for_alert no host referer split %s %s" % (hentry["http"]["http_refer"],hentry["http"]["hostname"],url.hostname)
                            e["fired_url"] = hentry["http"]["http_refer"]
                            autofire(hentry["http"]["http_refer"],hentry,e)
                            return match_found
                        elif e["asl"]["send_method"] == "landing":
                            if hentry["http"].has_key("url") and hentry["http"]["url"].endswith(".js") and hentry["http"].has_key("http_refer"):
                                print "autofiring %s from search_http_for_alert to avoid .js %s " % (["http"]["http_refer"],hentry["http"]["url"])
                                e["fired_url"] = hentry["http"]["http_refer"]
                                autofire(hentry["http"]["http_refer"],hentry,e)
                                return match_found

                            fire = build_url_from_entry(hentry)
                            if fire != None:
                                print "autofiring %s from search_http_for_alert landing on referer split %s %s" % (fire,hentry["http"]["hostname"],url.hostname)
                                e["fired_url"]=fire
                                autofire(fire,hentry,e)
                                return match_found

                   
                #We could have a landing with no referer via ssl redirect etc. Lets try to fire and avoid Java UA's and lack of UA's
                elif e["asl"]["send_method"] == "landing" and hentry["http"].has_key("url") and not hentry["http"].has_key("http_refer") and hentry["http"].has_key("http_user_agent") and "Java/1." not in hentry["http"]["http_user_agent"]:
                    fire = build_url_from_entry(hentry)
                    if fire != None:
                        print "autofiring %s from search_http_for_alert url entry with no referer" % (fire)
                        e["fired_url"]=fire
                        autofire(fire,hentry,e)
                        return match_found

                elif e["asl"]["send_method"] == "url" and hentry["http"].has_key("url"):
                    #the one case where we always inject rererer if present is if we have a .js that ends up as the url we will fire
                    if hentry["http"].has_key("url") and hentry["http"]["url"].endswith(".js") and hentry["http"].has_key("http_refer"):
                         print "autofiring %s from search_http_for_alert to avoid .js %s " % (["http"]["http_refer"],hentry["http"]["url"])
                         e["fired_url"] = hentry["http"]["http_refer"]
                         autofire(hentry["http"]["http_refer"],hentry,e)
                         return match_found
                    else:
                        fire = build_url_from_entry(hentry)
                        if fire != None:
                            print "autofiring %s from search_http_for_alert" % (fire)
                            e["fired_url"]=fire  
                            autofire(fire,hentry,e)
                        return match_found

    except Exception as e:
        print "Exception resolving alert to url %s " % (e)
        print 'Error on line {}'.format(sys.exc_info()[-1].tb_lineno)
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
                sle["fired_url"]=e["http"]["http_refer"]
                autofire(e["http"]["http_refer"],e,sle)
            elif sle["send_method"] == "url" and e["http"].has_key("url"):
                #deal with proxies
                if len(e["http"]["url"]) > 6 and e["http"]["url"][0:7] == "http://":
                    build_url = e["http"]["url"]
                else:
                    build_url = "http://"
                    if e["http"].has_key("hostname"):
                        build_url = build_url + e["http"]["hostname"]
                    else:
                        build_url = build_url + e["dest_ip"]

                    if e["dest_port"] != 80:
                        build_url = build_url + ":%s" % (e["dest_port"])
                    build_url = build_url + e["http"]["url"]

                print "autofiring url %s from http_search_list" % (build_url)
                sle["fired_url"] = build_url
                autofire(build_url,e,sle)
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
           elif asl["hash_type"] == "hashipdom":
                if e.has_key("flow_id"):
                    if e.has_key("http") and e["http"]["hostname"]:
                        e["hashipdom"]=ip_to_uint32(e["src_ip"]) + ip_to_uint32(e["dest_ip"]) + hash(e["http"]["hostname"])
                    else:
                        e["hashipdom"]=get_hashipdom_from_flowid(e)
                    if e["hashipdom"]:
                        for centry in alert_stack:
                            if centry.has_key("hashipdom") and e["hashipdom"] == centry["hashipdom"]:
                                entry_present == True
                    else:
                        print "Could not determine hashipdom skipping alert %s" % (e)
                        continue
                else:
                    print "Could not determine hashipdom skipping alert %s" % (e)
                    continue
                     
           else:
                print "not adding alert unknown hash type in %s" % (asl)
                continue

           if entry_present:
               continue 

           e["asl"] = asl
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
                elif asl["hash_type"] == "hashipdom":
                    if e.has_key("flow_id"):
                        if e.has_key("http") and e["http"]["hostname"]:
                            e["hashipdom"]=ip_to_uint32(e["src_ip"]) + ip_to_uint32(e["dest_ip"]) + hash(e["http"]["hostname"])
                        else:
                            e["hashipdom"]=get_hashipdom_from_flowid(e)
                        if e["hashipdom"]:
                             for centry in alert_stack:
                                if centry.has_key("hashipdom") and e["hashipdom"] == centry["hashipdom"]:
                                    entry_present == True
                        else:
                            print "Could not determine hashipdom skipping alert %s" % (e)
                            continue
                    else:
                        print "Could not determine hashipdom skipping alert %s" % (e)
                        continue

                else:
                    print "not adding alert unknown hash type in %s" % (asl)
                    continue

                if entry_present:
                   continue

                e["asl"] = asl
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
        elif e["search_type"] == "alert_sid_ignore":
            alert_search_ignore_sid.append(e["match"])
        elif e["search_type"] == "alert_ip_ignore":
            alert_search_ignore_ip.append(e["match"])
        
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

#cuckoo config
if conf.has_key("cuckoo_server_list"):
    for e in conf["cuckoo_server_list"]:
        tmpd = {}
        
        #cuckoo server name
        if e.has_key("label"):
            tmpd["label"] = e["label"]
        else:
            print "You must specify a label in the cuckoo_server_list portion of the config"
            sys.exit(1)

        #Group Servers
        if e.has_key("group") and e["group"]:
            if cuckoo_server_groups.has_key(e["group"]):
                cuckoo_server_groups[e["group"]].append(e["label"])
            else:
                cuckoo_server_groups[e["group"]]=[]
                cuckoo_server_groups[e["group"]].append(e["label"])

        #url to the cuckoo instance
        if e.has_key("url"):
            tmpd["url"] = e["url"]
        else:
            print "You must specify a url setting in the cuckoo_api portion of the config"
            sys.exit(1)

        #do or do not perform ssl verification. There is no try
        if e.has_key("verifyssl") and e["verifyssl"] == 1:
             tmpd["verifyssl"] = True
        else:
             tmpd["verifyssl"] = cuckoo_api["verifyssl"]

        #basic auth stuff
        if e.has_key("user") and not e.has_key("pass"): 
            print "basic auth user specified but no password"
            sys.exit(1)
        elif e.has_key("pass") and not e.has_key("user"):
            print "basic auth pass specified but no user"
            sys.exit(1)
        elif e.has_key("user") and e["user"] and e.has_key("pass") and e["pass"]:
             tmpd["user"] = e["user"]
             tmpd["pass"] = e["pass"]
        else:
             tmpd["user"]=cuckoo_api["user"]
             tmpd["pass"]=cuckoo_api["pass"]
        
        #proxy
        if e.has_key("proxies") and e["proxies"]:
            tmpd["proxies"] = e["proxies"]
        else:
            tmpd["proxies"] = cuckoo_api["proxies"]

        #if specified prepend something to the target uri
        if e.has_key("target_prepend"):
            tmpd["target_prepend"] = e["target_prepend"]
        else:
            tmpd["target_prepend"] = cuckoo_api["target_prepend"]

        #if specified append something to the target uri
        if e.has_key("target_append"):
            tmpd["target_append"] = e["target_append"]
        else:
            tmpd["target_append"] = cuckoo_api["target_append"]

        #do or do not perform ssl verification. There is no try
        if e.has_key("do_custom") and e["do_custom"] == 1:
             tmpd["do_custom"] = True
        elif e.has_key("do_custom") and e["do_custom"] != 1:
             tmpd["do_custom"] = False
        else:
             tmpd["do_custom"] = cuckoo_api["do_custom"]
 
        if e.has_key("do_shrike_vars") and e["do_shrike_vars"] == 1:
             tmpd["do_shrike_vars"] = True
        elif e.has_key("do_shrike_vars") and e["do_shrike_vars"] != 1:
             tmpd["do_shrike_vars"] = False 
        else:
             tmpd["do_shrike_vars"] = cuckoo_api["do_shrike_vars"]

        #do we want to generate a fake referer?
        if e.has_key("gen_fake_refer") and e["gen_fake_refer"] == 1:
             tmpd["gen_fake_refer"] = True
        else:
             tmpd["gen_fake_refer"] = False

        #cuckoo options
        if e.has_key("options"):
            tmpd["options"] = e["options"]
        else:
            tmpd["options"] = cuckoo_api["options"]

        #cuckoo options
        if e.has_key("tags"):
            tmpd["tags"] = e["tags"]
        else:
            tmpd["tags"] = cuckoo_api["tags"]

        #cuckoo priority 
        if e.has_key("priority"):
            tmpd["priority"] = e["priority"]
        else:
            tmpd["priority"] = cuckoo_api["priority"]

        #cuckoo options
        if e.has_key("gateway"):
            tmpd["gateway"] = e["gateway"]
        else:
            tmpd["gateway"] = cuckoo_api["gateway"]        

        cuckoo_servers[e["label"]]=tmpd
    
else:
   print "did not find cuckoo_server_list key bailing"
   sys.exit(1)

#check to see we have a default server for cases where one is not assigned in match
if not cuckoo_server_groups.has_key("default"):
       print "cuckoo default server group missing entry exiting"
       sys.exit(1) 
    
#Get path to eve file and make sure it exists
if conf.has_key("eve_file"):
   if not os.path.exists(conf["eve_file"]):
       print "specified eve file does not exist %s" % (conf["eve_file"])
       sys.exit(1) 

#Get path to log file and make sure it exists
if conf.has_key("log_file"):
    try:
        do_logging = True
        log_file = open(conf["log_file"],"a")
    except:
        print "could not open log file %s" % (conf["log_file"])
        sys.exit(1)

#Scrub ip addresses from url string
if conf.has_key("scrub_ip_addys") and conf["scrub_ip_addys"] == 1 :
    scrub_ipaddys = True

def ProcessLOG(q):
    while True:
        line = q.get()
        try:
            e = json.loads(line)
            global http_stack
            global http_stack_limit
            global http_search_list
            global alert_stack
            global buffer_full
            global log_file
            global do_logging
            if e["event_type"] == "http":
                if len(http_stack) >= http_stack_limit:
                    if buffer_full == False:
                        print "HTTP Buffer Full: %s" % (int(time.time()))
                        buffer_full = True
                    http_stack.pop(0)
                e["hash4"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"]) + e["src_port"] + e["dest_port"]
                e["haship"] = ip_to_uint32(e["dest_ip"]) + ip_to_uint32(e["src_ip"])
                if e["http"].has_key("hostname") and e["http"]["hostname"]:
                    e["hashipdom"]=ip_to_uint32(e["src_ip"]) + ip_to_uint32(e["dest_ip"]) + hash(e["http"]["hostname"])
                
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
                            #if do_logging and log_file:
                                #json.dump(a,log_file)
                                #log_file.write("\n")
                            alert_stack.remove(a)
#                        elif a.has_key("hash4"):
#                            if e["hash4"] == a["hash4"] and a["fired"] == False:
#                                print ("hash match %s and %s" % (a,e))
#                                if e["http"].has_key("http_refer") and e["http"].has_key("hostname") and e["http"]["hostname"] not in e["http"]["http_refer"]:
#                                    print "autofiring entry found after alert %s " % (e["http"]["http_refer"])
#                                    a["fired_url"]=e["http"]["http_refer"]
#                                    autofire(e["http"]["http_refer"],e,a)
#                                    a["fired"] = True
#                        elif a.has_key("haship"):
#                            if e["haship"] == a["haship"] and a["fired"] == False:
#                                print ("hash match %s and %s" % (a,e))
#                                if e["http"].has_key("http_refer") and e["http"].has_key("hostname") and e["http"]["hostname"] not in e["http"]["http_refer"]:
#                                    print "autofiring entry after alert %s" % (e["http"]["http_refer"])
#                                    a["fired_url"] = e["http"]["http_refer"]
#                                    autofire(e["http"]["http_refer"],e,a)
#                                    a["fired"] = True
                        if a["fired"] == False:
                            match_found = False

                            if a.has_key("hash4") and e["hash4"] == a["hash4"]:
                                match_found = True
                            elif a.has_key("haship") and e["haship"] == a["haship"]:
                                match_found = True
                            elif a.has_key("hashipdom") and e["hashipdom"] == a["hashipdom"]:
                                match_found = True

                            if match_found:
                                print ("hash match %s and %s" % (a,e))
                                if(a["asl"]["send_method"] == "referer" or a["asl"]["send_method"] == "landing") and e["http"].has_key("http_refer") and e["http"].has_key("hostname") and e["http"]["hostname"]:
                                    url = urlparse.urlsplit(e["http"]["http_refer"])
                                    if e["http"]["hostname"] != url.hostname:
                                        if a["asl"]["send_method"] == "referer":
                                            print "autofiring %s from search_http_for_alert" % (e["http"]["http_refer"])
                                            a["fired_url"] = e["http"]["http_refer"]
                                            autofire(e["http"]["http_refer"],e,a)
                                            a["fired"] = True
                                    elif a["asl"]["send_method"] == "landing":
                                        if e["http"].has_key("url") and e["http"]["url"].endswith(".js") and e["http"].has_key("http_refer"):
                                            print "autofiring %s from search_http_for_alert to avoid .js %s " % (e["http"]["http_refer"],e["http"]["url"])
                                            a["fired_url"] = e["http"]["http_refer"]
                                            autofire(e["http"]["http_refer"],e,a)
                                        else:
                                            fire = build_url_from_entry(e)
                                            if fire != None:
                                                print "autofiring %s from search_http_for_alert" % (fire)
                                                a["fired_url"]=fire
                                                autofire(fire,e,a)
                                                a["fired"] = True

                                #We could have a landing with no referer via ssl redirect etc. Lets try to fire and avoid Java UA's and lack of UA's
                                elif a["asl"]["send_method"] == "landing" and e["http"].has_key("url") and not e["http"].has_key("http_refer") and e["http"].has_key("http_user_agent") and "Java/1." not in e["http"]["http_user_agent"]:
                                    fire = build_url_from_entry(e)
                                    if fire != None:
                                        print "autofiring URL %s from search_http_for_alert" % (fire)
                                        a["fired_url"]=fire
                                        autofire(fire,e,a)
                                        a["fired"] = True

                                elif a["asl"]["send_method"] == "url" and e["http"].has_key("url"):
                                    if e["http"].has_key("url") and e["http"]["url"].endswith(".js") and e["http"].has_key("http_refer"):
                                        print "autofiring %s from search_http_for_alert to avoid .js %s " % (e["http"]["http_refer"],e["http"]["url"])
                                        a["fired_url"] = e["http"]["http_refer"]
                                        autofire(e["http"]["http_refer"],e,a)
                                    else:
                                        fire = build_url_from_entry(e)
                                        if fire != None:
                                            print "autofiring %s from search_http_for_alert" % (fire)
                                            a["fired_url"]=fire
                                            autofire(fire,e,a)
                                            a["fired"] = True

            if e["event_type"] == "alert":
                try:
                    if (e["alert"]["signature_id"] not in alert_search_ignore_sid) and (e["dest_ip"] not in alert_search_ignore_ip) and (e["src_ip"] not in alert_search_ignore_ip) :
                        alert_check_search_list(e)
                except Exception as err:
                    print "failed to run alert_check_search %s" % (err)
        except Exception as err:
            print "Exception parsing line %s:\n%s\n%s" % (err,line,sys.exc_info()[-1].tb_lineno)

worker = Process(target=ProcessLOG, args=(log_queue,))
worker.daemon = True
worker.start()
for line in tailer.follow(open(conf["eve_file"])):
    log_queue.put(line)
