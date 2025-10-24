#!/usr/bin/env python3
import psycopg2 as p
from webexteamssdk import WebexTeamsAPI
from zabbix_utils import ZabbixAPI
import os
from dotenv import load_dotenv
load_dotenv()

#getting evironmental variables
#tokens
tokenWebex = os.getenv("Webex_Api_Token")
ZabbixToken = os.getenv("Zabbix_API_Token")
#api requirements
ZabbixURL= os.getenv("Zabbix_URL")
WebexRoomID = os.getenv("Webex_Room_Id")
RTPRoomID = os.getenv("RTP_Room_Id")
SJCRoomID = os.getenv("SJC_Room_Id")
LONRoomID = os.getenv("LON_Room_Id")
SNGRoomID = os.getenv("SNG_Room_Id")
SYDRoomID = os.getenv("SYD_Room_Id")

#database information
DatabaseName = os.getenv("Database_Name")
DatabaseUsername = os.getenv("Database_Username")
DatabasePassword = os.getenv("Database_Password")
DatabaseIp = os.getenv("Database_Ip")
DatabasePort = os.getenv("Database_Port")

##querys
alertTobeAdded = "INSERT INTO hostalerts (eventid, name, clock, hostname) VALUES (%s, %s, %s, %s);"
alertToBeRemoved = "DELETE FROM hostalerts WHERE eventid = (%s)"
alertInformationById = "SELECT * FROM hostalerts WHERE eventid=(%s)"
clearMessage = "VMWare host: {} is up **resolved** "
addMessage = "New triggered alert for host: {} description: {}"
#initializing API objects
#Webex
apiWebex = WebexTeamsAPI(access_token=tokenWebex)
#zabbix
apiZabbix = ZabbixAPI(url=ZabbixURL)
apiZabbix.login(token=ZabbixToken)

#data base console params:
conn = p.connect(
    dbname=DatabaseName,
    user=DatabaseUsername,  #postgress user
    password=DatabasePassword, #postgres password
    host=DatabaseIp,       #Database IP, need to be allow the source IP and MD5 auth
    port=DatabasePort
    )


#getting zabbix all severity 5 (disaster alerts) for vmware hosts
def getHostDownIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],       
                    "severities" : 5,
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems
#getting zabbix all severity 5 (disaster alerts) for site
def getSiteIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],       
                    "severities" : 5,
                    "groupids" : [557],
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

#########################################HOSTS##################################################
def getCurrentProblems():
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
#########################################SITE##################################################
def getSiteProblems():
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

#print(prepareDBdata())

# connecting to db to check host alerts
def getDBexistingProblems():

    cur = conn.cursor()
    # Create table with pdu_number
    cur.execute("""
        SELECT eventid FROM hostalerts;
        """)
    dbdata = cur.fetchall()
    cur.close()
    
    return(dbdata)

# connecting to db to check site alerts
def getDBSiteProblems():

    cur = conn.cursor()
    # Create table with pdu_number
    cur.execute("""
        SELECT eventid FROM sitealerts;
        """)
    dbdata = cur.fetchall()
    cur.close()
    
    return(dbdata)

def alertChecking(zabbixData, postgresData):
    postgres_ids = {item[0] for item in postgresData}
    
    zabbix_ids = {int(item[0]) for item in zabbixData}
    # alert in zabbix not in postgres meaning new alert
    newAlert = zabbix_ids - postgres_ids
    
    # alert in postgres not in zabbix meaning alert clear
    clearAlert = postgres_ids - zabbix_ids
    cur = conn.cursor()
    if newAlert:

        for element in zabbixData:
            if int(element[0]) in newAlert:
                valores = (element[0],element[1],element[2],element[3])
                Message = addMessage.format(element[3],element[1])
                cur.execute( alertTobeAdded, valores)                
                
                apiWebex.messages.create(roomId=WebexRoomID, text=Message)

    if clearAlert:
        
        for id in clearAlert:
            cur.execute(alertInformationById,(id,))
            alert_info =cur.fetchall()
        
            for alert in alert_info:
                hostname = alert[3]
                Message = clearMessage.format(hostname)
                apiWebex.messages.create(roomId=WebexRoomID, text=Message)
            cur.execute( alertToBeRemoved,(id,)
            )
            
            
            
            print(Message)
        conn.commit()

    else:
        conn.commit()


alertChecking(getCurrentProblems(), getDBexistingProblems())