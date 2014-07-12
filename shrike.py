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

http_stack = []
http_stack_limit = 100000
alert_stack = []
alert_stack_limit = 200
alert_stack_timeout = 300
buffer_full = False

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
#url Match URL Send Original
#referer Match URL Send Referer

#search_type
#alert_sid
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
alert_search_list = [
        {"send_method": "referer", "search_type": "alert_sid", "match": 2807913, "hash_type": "haship"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2017567, "hash_type": "hash4"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2017817, "hash_type": "hash4"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2017552, "hash_type": "hash4"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2018441, "hash_type": "hash4"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2018583, "hash_type": "haship"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2017667, "hash_type": "haship"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2017666, "hash_type": "haship"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2013036, "hash_type": "haship"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2015888, "hash_type": "haship"},
        {"send_method": "referer", "search_type": "alert_sid", "match": 2018259, "hash_type": "haship"},
        ]
http_search_list = [
        {"send_method": "referer", "search_type": "dest_ip", "match": "10.1.10.10"},
        {"send_method": "referer", "search_type": "http_uri_re", "match": "^\/\?PHPSSESID="},
        ]

for e in http_search_list:
    if e["search_type"] == "http_uri_re" or e["search_type"] == "http_referer_re" or e["search_type"] == "http_host_re":
        e["cmatch"] = re.compile(e["match"])


def ip_to_uint32(ip):
   t = socket.inet_aton(ip)
   return struct.unpack("!I", t)[0]

def uint32_to_ip(ipn):
   t = struct.pack("!I", ipn)
   return socket.inet_ntoa(t)

def autofire(target):
    #see http://docs.python-requests.org/en/latest/ for requests
    try:
        user="someuser"
        password="somepass"
        proxies = { "http": "192.168.1.1:3128", "https": "192.168.1.1:3128",}
        url = "https://cuckooapi.behind.rproxy.with.auth.and.ssl:8443/tasks/create/url"
        data=dict(url=target)
        response = requests.post(url, auth=(user,password), data=data, proxies=proxies, verify=False)
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

                if e["send_method"] == "referer" and hentry["http"].has_key("http_refer") and hentry["http"].has_key("hostname") and hentry["http"]["hostname"] not in hentry["http"]["http_refer"]:
                    print "autofiring %s from search_http_for_alert" % (hentry["http"]["http_refer"])
                    autofire(hentry["http"]["http_refer"])
                    return match_found

                elif e["send_method"] == "url" and hentry["http"].has_key("url"):
                    build_url = "http://"
                    if hentry["http"].has_key("hostname"):
                        build_url = build_url + hentry["http"]["hostname"]
                    else:
                        build_url = build_url + hentry["dest_ip"]

                    if hentry["dest_port"] != "80":
                        buld_url = build_url + ":%s" % (hentry["dest_port"])
                    build_url = build_url + hentry["http"]["url"]
                    print "autofiring url %s from http_search_list" % (build_url)
                                        
                    autofire(build_url)
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
                    buld_url = build_url + ":%s" % (e["dest_port"])
                build_url = build_url + e["http"]["url"]
                print "autofiring url %s from http_search_list" % (build_url)
                autofire(build_url)
    return match_found

def alert_check_search_list(e):
    for asl in alert_search_list:
       if asl["search_type"] == "alert_sid" and e["alert"]["signature_id"] == asl["match"]:
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

print "Start time:%s" % (int(time.time()))
#TODO: make this a cli option
for line in tailer.follow(open('eve.json')):
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
