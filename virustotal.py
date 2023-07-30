import requests
import json
x= "facebook.com"
key = "key"
def fhand(response):
    det = open('det.txt', 'a')
    det.write(response.text)
    det.write(
        "=========================================================================================================================================")
    det.close()
#######virustotal ip##########
def vtip(x,key):
    urlh = "https://www.virustotal.com/api/v3/search?query={}"
    url =  urlh.format(x)
    headers = {
        "Accept": "application/json",
        "x-apikey": key
    }

    response = requests.request("GET", url, headers=headers)
    #print(response.text)
    data = response.text
    data = json.loads(data)
    try:
        print("Country: ",data["data"][0]["attributes"]["country"])
    except: pass
    try:
        print("Owner: ",data["data"][0]["attributes"]["as_owner"])
    except: pass
    try:
        print("subject: ",data["data"][0]["attributes"]["last_https_certificate"]["subject"]["CN"])
    except: pass
    try:
        print("CERT Expire at : ",data["data"][0]["attributes"]["last_https_certificate"]["validity"]["not_after"])
    except: pass
    try:
        print("statistics: ",data["data"][0]["attributes"]["last_analysis_stats"])
    except: pass
    try:
        print("Reputation: ",data["data"][0]["attributes"]["reputation"])
    except: pass
    try:
        print("total_votes: ",data["data"][0]["attributes"]["total_votes"])
    except: pass
    try:
        print("Domains: ",data["data"][0]["attributes"]["last_https_certificate"]["extensions"]["subject_alternative_name"])
    except: pass
    fhand(response)
###############dns records #################
def rec(t,records):
    for i in records:
        if t == "SOA":
            if i["type"] == t:
                print("  ",i)
        elif t == "MX":
             if i["type"] == t:
                print("  ",i["value"]," Priority: ",i["priority"])
        else:
            if i["type"] == t:
                print("  ",i["value"])
#######virustotal domain##########
def vtdom(x,key):
    urlh = "https://www.virustotal.com/api/v3/search?query={}"
    url =  urlh.format(x)
    headers = {
        "Accept": "application/json",
        "x-apikey": key
    }
    response = requests.request("GET", url, headers=headers)
    #print(response.text)
    data = response.text
    data = json.loads(data)
    try:
        records =  data["data"][0]["attributes"]["last_dns_records"]
    except: pass
    #A record
    print("[A] record: ")
    rec("A",records)
    ###
    #AAAA record
    print("[AAAA] record: ")
    rec("AAAA",records)
    ### SOA records
    print(" [SOA] record: ")
    rec("SOA",records)
    ##### NS record
    print(" [NS] record: ")
    rec("NS",records)
    ##### MX record
    print(" [MX] record: ")
    rec("MX",records)
    ##### MX record
    print(" [TXT] record: ")
    rec("TXT",records)
    try:
        print("***********Whois***************")
    except:pass
    try:
        print("Creation Date: ", data["data"][0]["attributes"]["whois"])
    except:pass
    print("***********Statistics**********")
    try:
        print("Statistics: ", data["data"][0]["attributes"]["last_analysis_stats"])
    except:pass
    try:
        print("reputation: ", data["data"][0]["attributes"]["reputation"])
    except:pass
    try:
        print("total_votes: ",data["data"][0]["attributes"]["total_votes"])
    except:pass

    fhand(response)
###URL#########
def vturl(x,key):
    urlh = "https://www.virustotal.com/api/v3/search?query={}"
    url =  urlh.format(x)
    headers = {
        "Accept": "application/json",
        "x-apikey": key
    }
    response = requests.request("GET", url, headers=headers)
    #print(response.text)
    data = response.text
    data = json.loads(data)
    records = data["data"][0]["attributes"]["last_dns_records"]
    #print("Country: ",data["data"][0]["attributes"]["last_dns_records"])
    # A record
    print("[A] record: ")
    rec("A", records)
    # AAAA record
    print("[AAAA] record: ")
    rec("AAAA", records)
    ##### CNAME record
    print(" [CNAME] record: ")
    rec("CNAME", records)
    print("***********Whois***************")
    try:
        print("Creation Date: ", data["data"][0]["attributes"]["whois"])
    except:pass
    print("***********Statistics**********")
    try:
        print("Statistics: ", data["data"][0]["attributes"]["last_analysis_stats"])
    except:pass
    try:
        print("reputation: ", data["data"][0]["attributes"]["reputation"])
    except:pass
    print("************CERT***************")
    try:
        print("CERT Expire at : ", data["data"][0]["attributes"]["last_https_certificate"]["validity"]["not_after"])
    except:pass
    try:
        print("Domains: ", data["data"][0]["attributes"]["last_https_certificate"]["extensions"]["subject_alternative_name"])
    except:pass
    try:
        print("Subject: ", data["data"][0]["attributes"]["last_https_certificate"]["subject"])
    except:pass
    try:
        print("categories: ", data["data"][0]["attributes"]["categories"])
    except:pass
    try:
     print("Total Votes: ", data["data"][0]["attributes"]["total_votes"])
    except:pass

    fhand(response)





