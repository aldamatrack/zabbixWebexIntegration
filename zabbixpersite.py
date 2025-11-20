#!/usr/bin/env python3
import psycopg2 as p
from zabbix_utils import ZabbixAPI
import os
from dotenv import load_dotenv
load_dotenv()

# Getting environmental variables
# Tokens
ZabbixToken = os.getenv("Zabbix_API_Token")
# API requirements
ZabbixURL= os.getenv("Zabbix_URL")
# Database information
DatabaseName = os.getenv("Database_Name")
DatabaseUsername = os.getenv("Database_Username")
DatabasePassword = os.getenv("Database_Password")
DatabaseIp = os.getenv("Database_Ip")
DatabasePort = os.getenv("Database_Port")


# Initializing API objects
# Zabbix
apiZabbix = ZabbixAPI(url=ZabbixURL)
apiZabbix.login(token=ZabbixToken)

# --- ZABBIX FETCH FUNCTIONS ---

# 1. Getting Zabbix all severity 5 (disaster alerts) for Hosts 
def getHostDownIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],      
                    "severities" : 5,
                    "selectTags": "extend" 
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

# 2. Getting Zabbix all severity 5 (disaster alerts) for Site Alerts 
def getSiteDownIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],      
                    "severities" : 5,
                    "groupids" : [557], 
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

# 3. Getting Zabbix all severity 5 (disaster alerts) for CPOC 
def getCPOCDownIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],      
                    "severities" : 5,
                    "groupids" : [551], 
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

# --- DATA PREPARATION FUNCTIONS ---

# Prepares data for hostalerts (VMware host down alerts)
def prepareDBdata():
    data = []
    
    for element in getHostDownIssues(): 
        if element["name"] == "VMware: Hypervisor is down":
            internalList = []
            internalList.append(element["eventid"])
            internalList.append(element["name"])
            internalList.append(element["clock"])
            
            hostname_found = False
            for tag in element["tags"]:
                if tag["tag"] == "hostname":
                    internalList.append(tag["value"])
                    hostname_found = True
            
            if hostname_found and len(internalList) == 4:
                 data.append(internalList)
            
    return data

# Prepares data for siteAlerts (non-host alerts from group 557)
def prepareSitedata():
    data = []
    
    for element in getSiteDownIssues():
        internalList = []
        internalList.append(element["eventid"])
        internalList.append(element["name"])
        internalList.append(element["clock"])
        
        site_tag = "UNKNOWN"
        visname_tag = "UNKNOWN"
        
        for tag in element["tags"]:
            if tag["tag"] == "site":
                site_tag = tag["value"]
            if tag["tag"] == "visname":
                visname_tag = tag["value"]

        internalList.append(site_tag)
        internalList.append(visname_tag)

        if len(internalList) == 5:
             data.append(internalList)
             
    return data

# Prepares data for cpocalerts (alerts from group 551)
def prepareCPOCdata():
    data = []
    
    for element in getCPOCDownIssues():
        internalList = []
        internalList.append(element["eventid"])
        internalList.append(element["name"])
        internalList.append(element["clock"])
        
        site_tag = "UNKNOWN"
        visname_tag = "UNKNOWN"
        
        for tag in element["tags"]:
            if tag["tag"] == "site":
                site_tag = tag["value"]
            if tag["tag"] == "visname":
                visname_tag = tag["value"]

        internalList.append(site_tag)
        internalList.append(visname_tag)

        if len(internalList) == 5:
             data.append(internalList)
             
    return data




def CreateNewDB():
    try:
        conn = p.connect(
        dbname=DatabaseName,
        user=DatabaseUsername, 
        password=DatabasePassword, 
        host=DatabaseIp,      
        port=DatabasePort
        )
    except p.Error as e:
        print(f"Error connecting to database: {e}")
        return

    cur = conn.cursor()
    
    # HOST ALERTS
    print("Checking/Creating hostalerts table...")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS hostalerts (
        eventid INTEGER PRIMARY KEY,
        name VARCHAR(250) NOT NULL,
        clock VARCHAR(50) NOT NULL,
        hostname VARCHAR(50) NOT NULL
        );""")
        
    # SITE ALERTS
    print("Checking/Creating siteAlerts table...")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS siteAlerts (
        eventid INTEGER PRIMARY KEY,
        name VARCHAR(250) NOT NULL,
        clock VARCHAR(50) NOT NULL,
        site VARCHAR(50) NOT NULL,
        hostname VARCHAR(250) NOT NULL
        );""")
    
    # 3.CPOC ALERTS
    print("Checking/Creating cpocalerts table...")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS cpocalerts (
        eventid INTEGER PRIMARY KEY,
        name VARCHAR(250) NOT NULL,
        clock VARCHAR(50) NOT NULL,
        site VARCHAR(50) NOT NULL,
        hostname VARCHAR(250) NOT NULL
        );""")

    
    # 
    hostQuery = "INSERT INTO hostalerts (eventid, name, clock, hostname) VALUES (%s, %s, %s, %s) ON CONFLICT (eventid) DO NOTHING;"
    siteQuery = "INSERT INTO siteAlerts (eventid, name, clock, site, hostname) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (eventid) DO NOTHING;"
    cpocQuery = "INSERT INTO cpocalerts (eventid, name, clock, site, hostname) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (eventid) DO NOTHING;"
    
    # Poblamiento inicial de la DB
    print("Populating hostalerts (VMware down, all groups)...")
    for alert in prepareDBdata():
        cur.execute(hostQuery, (alert[0], alert[1], alert[2], alert[3]))
    
    print("Populating siteAlerts (from group 557)...")
    for alert in prepareSitedata():
        cur.execute(siteQuery, (alert[0], alert[1], alert[2], alert[3], alert[4]))
            
    print("Populating cpocalerts (from group 551)...")
    for alert in prepareCPOCdata():
        cur.execute(cpocQuery, (alert[0], alert[1], alert[2], alert[3], alert[4]))
            
    conn.commit()
    print("Database successfully created and tables initialized: hostalerts, siteAlerts, cpocalerts.")
    cur.close()
    conn.close()


CreateNewDB()