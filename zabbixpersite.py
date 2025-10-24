#!/usr/bin/env python3
import psycopg2 as p
from zabbix_utils import ZabbixAPI
import os
from dotenv import load_dotenv
load_dotenv()

#getting evironmental variables
#tokens
ZabbixToken = os.getenv("Zabbix_API_Token")
#api requirements
ZabbixURL= os.getenv("Zabbix_URL")
#database information
DatabaseName = os.getenv("Database_Name")
DatabaseUsername = os.getenv("Database_Username")
DatabasePassword = os.getenv("Database_Password")
DatabaseIp = os.getenv("Database_Ip")
DatabasePort = os.getenv("Database_Port")


#initializing API objects

#zabbix
apiZabbix = ZabbixAPI(url=ZabbixURL)
apiZabbix.login(token=ZabbixToken)

#getting zabbix all severity 5 (disaster alerts)
def getHostDownIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],       
                    "severities" : 5,
                    "groupids" : [557],
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

#preparing data for db inser, removing inecesary tags
def prepareDBdata():
    data = []
    internalList = []
    for element in getHostDownIssues():
        if  element["name"] == "VMware: Hypervisor is down" :
            internalList.append(element["eventid"])
            internalList.append(element["name"])
            internalList.append(element["clock"])
            for tag in element["tags"]:
                if tag["tag"] == "hostname":
                    internalList.append(tag["value"])
            data.append(internalList)
            internalList = []
        else:
            pass
    return data

def prepareSitedata():
    data = []
    internalList = []
    for element in getHostDownIssues():
        internalList.append(element["eventid"])
        internalList.append(element["name"])
        internalList.append(element["clock"])
        for tag in element["tags"]:
            if tag["tag"] == "site":
                internalList.append(tag["value"])
            if tag["tag"] == "visname":
                internalList.append(tag["value"])
            else:
                pass
        data.append(internalList)
        internalList = []
    return data

#create new database for Alert listing
def CreateNewDB():
    conn = p.connect(
    dbname=DatabaseName,
    user=DatabaseUsername,  #postgress user
    password=DatabasePassword, #postgres password
    host=DatabaseIp,       #Database IP, need to be allow the source IP and MD5 auth
    port=DatabasePort
    )
    cur = conn.cursor()
    # Create table with pdu_number
    cur.execute("""
    CREATE TABLE IF NOT EXISTS hostalerts (
        eventid INTEGER PRIMARY KEY,
        name VARCHAR(250) NOT NULL,
        clock VARCHAR(50) NOT NULL,
        hostname VARCHAR(50) NOT NULL
        );""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS siteAlerts (
        eventid INTEGER PRIMARY KEY,
        name VARCHAR(250) NOT NULL,
        clock VARCHAR(50) NOT NULL,
        site VARCHAR(50) NOT NULL,
        hostname VARCHAR(250) NOT NULL
        );""")
    query = "INSERT INTO hostalerts (eventid, name, clock, hostname) VALUES (%s, %s, %s, %s);"
    siteQuery = "INSERT INTO siteAlerts (eventid, name, clock, site, hostname) VALUES (%s, %s, %s, %s, %s);"
    
    for alert in prepareDBdata():
        cur.execute(query, (alert[0], alert[1], alert[2], alert[3]))
    
    for alert in prepareSitedata():
        if len(alert) == 5:
            cur.execute(siteQuery, (alert[0], alert[1], alert[2], alert[3], alert[4]))
    conn.commit()
    print("database succesfully created")

#CreateNewDB()
for element in prepareSitedata():
    print(element)
    print("\n")
CreateNewDB()

