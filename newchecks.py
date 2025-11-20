#!/usr/bin/env python3
import psycopg2 as p
from webexteamssdk import WebexTeamsAPI
from zabbix_utils import ZabbixAPI
import os
from dotenv import load_dotenv
load_dotenv()

# Getting environmental variables
# Tokens
tokenWebex = os.getenv("Webex_Api_Token")
ZabbixToken = os.getenv("Zabbix_API_Token")
# API requirements
ZabbixURL= os.getenv("Zabbix_URL")
WebexRoomID = os.getenv("Webex_Room_Id") # Fallback for known but unmapped sites
RTPRoomID = os.getenv("RTP_Room_Id")
SJCRoomID = os.getenv("SJC_Room_Id")
LONRoomID = os.getenv("LON_Room_Id")
SNGRoomID = os.getenv("SNG_Room_Id")
SYDRoomID = os.getenv("SYD_Room_Id")
CPOCRoomID = os.getenv("CPOC_Room_Id")
ADMINRoomID = os.getenv("ADMIN_Room_Id") # Room for alerts with missing data

# --- Dashboard URLs per Site ---
ZabbixURL_RTP = os.getenv("ZabbixURL_RTP")
ZabbixURL_SJC = os.getenv("ZabbixURL_SJC")
ZabbixURL_LON = os.getenv("ZabbixURL_LON")
ZabbixURL_SNG = os.getenv("ZabbixURL_SNG")
ZabbixURL_SYD = os.getenv("ZabbixURL_SYD")
ZabbixURL_CPOC = os.getenv("ZabbixURL_CPOC")
ZabbixURL_ADMIN = os.getenv("ZabbixURL_ADMIN") 

# Database information
DatabaseName = os.getenv("Database_Name")
DatabaseUsername = os.getenv("Database_Username")
DatabasePassword = os.getenv("Database_Password")
DatabaseIp = os.getenv("Database_Ip")
DatabasePort = os.getenv("Database_Port")

siteRoomMap = {
    "SJC": SJCRoomID,
    "RTP": RTPRoomID,
    "LON": LONRoomID,
    "SNG": SNGRoomID,
    "SYD": SYDRoomID,
    "CPOC": CPOCRoomID
}

# --- New Mapping for Dashboards ---
siteDashboardMap = {
    "SJC": ZabbixURL_SJC,
    "RTP": ZabbixURL_RTP,
    "LON": ZabbixURL_LON,
    "SNG": ZabbixURL_SNG,
    "SYD": ZabbixURL_SYD,
    "CPOC": ZabbixURL_CPOC,
}

## Queries - HOSTS
hostAlertTobeAdded = "INSERT INTO hostalerts (eventid, name, clock, hostname) VALUES (%s, %s, %s, %s);"
hostAlertToBeRemoved = "DELETE FROM hostalerts WHERE eventid = (%s)"
hostAlertInformationById = "SELECT * FROM hostalerts WHERE eventid=(%s)"
hostClearMessage = "VMWare host: {} is up **resolved** "
hostAddMessage = "New triggered alert for host: {} description: {}"

## Queries - SITES
siteAlertTobeAdded = "INSERT INTO sitealerts (eventid, name, clock, site, hostname) VALUES (%s, %s, %s, %s, %s);"
siteAlertToBeRemoved = "DELETE FROM sitealerts WHERE eventid = (%s)"
siteAlertInformationById = "SELECT * FROM sitealerts WHERE eventid=(%s)"
siteClearMessage = "Site alert **resolved** in {}: {} (Host: {})"
siteAddMessage = "New site alert in {}: {} (Host: {})"

## Queries - CPOC
cpocAlertTobeAdded = "INSERT INTO cpocalerts (eventid, name, clock, site, hostname) VALUES (%s, %s, %s, %s, %s);"
cpocAlertToBeRemoved = "DELETE FROM cpocalerts WHERE eventid = (%s)"
cpocAlertInformationById = "SELECT * FROM cpocalerts WHERE eventid=(%s)"
cpocClearMessage = "CPOC alert **resolved** in {}: {} (Host: {})"
cpocAddMessage = "New CPOC alert in {}: {} (Host: {})"

# Message for alerts with 'UNKNOWN' data
missingInfoMessage = "Site alert with missing info (sent to Admin). Site: {}, Host: {}. Alert: {}"


# Initializing API objects
# Webex
apiWebex = WebexTeamsAPI(access_token=tokenWebex)
# Zabbix
apiZabbix = ZabbixAPI(url=ZabbixURL)
apiZabbix.login(token=ZabbixToken)

# Database connection params:
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
    exit(1)


# Getting zabbix all severity 5 (disaster alerts) for vmware hosts
def getHostDownIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],      
                    "severities" : 5,
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

# Getting zabbix all severity 5 (disaster alerts) for site (Group ID 557)
def getSiteIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],      
                    "severities" : 5,
                    "groupids" : [557],
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

# Getting zabbix all severity 5 (disaster alerts) for CPOC (Group ID 551)
def getCPOCIssues(): 
    request_param = {
                    "output" : ["name","eventid","clock"],      
                    "severities" : 5,
                    "groupids" : [551], # <-- Group ID 551
                    "selectTags": "extend"
                     }
    problems = apiZabbix.problem.get( request_param ) 
    return problems

#########################################HOSTS##################################################
def getCurrentProblems():
    data = []
    for element in getHostDownIssues():
        if  element["name"] == "VMware: Hypervisor is down" :
            internalList = []
            internalList.append(element["eventid"])
            internalList.append(element["name"])
            internalList.append(element["clock"])
            for tag in element["tags"]:
                if tag["tag"] == "hostname":
                    internalList.append(tag["value"])
            if len(internalList) == 4:
                data.append(internalList)
        else:
            pass
    return data

#########################################SITE##################################################
def getSiteProblems():
    data = []
    for element in getSiteIssues(): 
        tags_dict = {tag['tag']: tag['value'] for tag in element.get('tags', [])}
        
        # if it doesn't find the tag, assign "UNKNOWN"
        site = tags_dict.get("site", "UNKNOWN")
        visname = tags_dict.get("visname", "UNKNOWN") 

        internalList = [
            element["eventid"],
            element["name"],
            element["clock"],
            site,
            visname 
        ]
        data.append(internalList)
    return data

#########################################CPOC##################################################
def getCPOCProblems(): 
    data = []
    for element in getCPOCIssues(): 
        tags_dict = {tag['tag']: tag['value'] for tag in element.get('tags', [])}
        
        
        site = "CPOC" 
        
        
        visname = tags_dict.get("visname", "UNKNOWN_HOST") 

        internalList = [
            element["eventid"],
            element["name"],
            element["clock"],
            site,
            visname 
        ]
        data.append(internalList)
    return data

# Connecting to db to check host alerts
def getDBexistingProblems():
    dbdata = []
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT eventid FROM hostalerts;")
        dbdata = cur.fetchall()
    except p.Error as e:
        print(f"Error getting host problems from DB: {e}")
    finally:
        if cur:
            cur.close()
    return(dbdata)

# Connecting to db to check site alerts
def getDBSiteProblems():
    dbdata = []
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT eventid FROM sitealerts;")
        dbdata = cur.fetchall()
    except p.Error as e:
        print(f"Error getting site problems from DB: {e}")
    finally:
        if cur:
            cur.close()
    return(dbdata)

# Connecting to db to check CPOC alerts
def getDBCPOCProblems():
    dbdata = []
    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT eventid FROM cpocalerts;")
        dbdata = cur.fetchall()
    except p.Error as e:
        print(f"Error getting CPOC problems from DB: {e}")
    finally:
        if cur:
            cur.close()
    return(dbdata)


def alertCheckingHosts(zabbixData, postgresData):
    postgres_ids = {int(item[0]) for item in postgresData}
    zabbix_ids = {int(item[0]) for item in zabbixData}
    
    newAlert = zabbix_ids - postgres_ids
    clearAlert = postgres_ids - zabbix_ids
    
    cur = conn.cursor()
    try:
        if newAlert:
            for element in zabbixData:
                if int(element[0]) in newAlert:
                    valores = (element[0], element[1], element[2], element[3])
                    Message = hostAddMessage.format(element[3], element[1])
                    cur.execute(hostAlertTobeAdded, valores) 
                    apiWebex.messages.create(roomId=WebexRoomID, text=Message)

        if clearAlert:
            for id in clearAlert:
                cur.execute(hostAlertInformationById, (id,))
                alert_info = cur.fetchall()
            
                for alert in alert_info:
                    hostname = alert[3]
                    Message = hostClearMessage.format(hostname)
                    apiWebex.messages.create(roomId=WebexRoomID, text=Message)
                
                cur.execute(hostAlertToBeRemoved, (id,))
        
        conn.commit()
        
    except Exception as e:
        print(f"Error during alertCheckingHosts: {e}")
        conn.rollback()
    finally:
        cur.close()


def alertCheckingSites(zabbixData, postgresData):
    postgres_ids = {int(item[0]) for item in postgresData}
    zabbix_ids = {int(item[0]) for item in zabbixData}
    
    newAlert = zabbix_ids - postgres_ids
    clearAlert = postgres_ids - zabbix_ids
    
    cur = conn.cursor()
    try:
        if newAlert:
            for element in zabbixData:
                if int(element[0]) in newAlert:
                    valores = (element[0], element[1], element[2], element[3], element[4])
                    event_name = element[1]
                    site = element[3]
                    hostname = element[4]
                    
                    room_id = None
                    Message = ""

                    # Routing logic
                    if site == "UNKNOWN" or hostname == "UNKNOWN":
                        room_id = ADMINRoomID
                        Message = missingInfoMessage.format(site, hostname, event_name)
                        
                        if ZabbixURL_ADMIN: 
                            Message += f"\nMissing info Dashboard:({ZabbixURL_ADMIN})\n:q\n"
                    else:
                        # If info is present, use the map. If not in map, use WebexRoomID (general)
                        room_id = siteRoomMap.get(site, WebexRoomID) 
                        Message = siteAddMessage.format(site, event_name, hostname)
                        
                        # --- Add site dashboard link if it exists ---
                        dashboard_url = siteDashboardMap.get(site)
                        if dashboard_url:
                            Message += f"\nSITE Dashboard:({dashboard_url})\n\n"
                        
                    cur.execute(siteAlertTobeAdded, valores)
                    apiWebex.messages.create(roomId=room_id, text=Message)

        if clearAlert:
            for id in clearAlert:
                cur.execute(siteAlertInformationById, (id,))
                alert_info = cur.fetchall()
            
                for alert in alert_info:
                    event_name = alert[1]
                    site = alert[3]
                    hostname = alert[4]
                    
                    room_id = None
                    Message = ""

                    # Routing logic for resolved alerts
                    if site == "UNKNOWN" or hostname == "UNKNOWN":
                        room_id = ADMINRoomID
                        Message = f"Site alert RESOLVED or Data fixed (check site room) Site: {site}, Host: {hostname}, Alert: {event_name}"
                        # --- Add ADMIN dashboard link if it exists ---
                        if ZabbixURL_ADMIN: 
                            Message += f"\nMissing info Dashboard: ({ZabbixURL_ADMIN})\n\n"
                    else:
                        room_id = siteRoomMap.get(site, WebexRoomID)
                        Message = siteClearMessage.format(site, event_name, hostname)

                        # --- Add site dashboard link if it exists ---
                        dashboard_url = siteDashboardMap.get(site)
                        if dashboard_url:
                            Message += f"\nSITE Dashboard: ({dashboard_url})\n\n"

                    apiWebex.messages.create(roomId=room_id, markdown=Message )
                    
                cur.execute(siteAlertToBeRemoved, (id,))
        
        conn.commit()
        
    except Exception as e:
        print(f"Error during alertCheckingSites: {e}")
        conn.rollback()
    finally:
        cur.close()

#########################################CPOC CHECKING##################################################
def alertCheckingCPOC(zabbixData, postgresData):
    postgres_ids = {int(item[0]) for item in postgresData}
    zabbix_ids = {int(item[0]) for item in zabbixData}
    
    newAlert = zabbix_ids - postgres_ids
    clearAlert = postgres_ids - zabbix_ids
    
    cur = conn.cursor()
    try:
        
        if newAlert:
            for element in zabbixData:
                if int(element[0]) in newAlert:
                    valores = (element[0], element[1], element[2], element[3], element[4])
                    event_name = element[1]
                    site = element[3] 
                    hostname = element[4]
                    
                    
                    room_id = CPOCRoomID 
                    Message = cpocAddMessage.format(site, event_name, hostname)
                    
                    
                    dashboard_url = ZabbixURL_CPOC 
                    if dashboard_url:
                        Message += f"\nCPOC Dashboard:({dashboard_url})\n\n"
                    
                    cur.execute(cpocAlertTobeAdded, valores)
                    apiWebex.messages.create(roomId=room_id, text=Message)

        
        if clearAlert:
            for id in clearAlert:
                cur.execute(cpocAlertInformationById, (id,))
                alert_info = cur.fetchall()
            
                for alert in alert_info:
                    event_name = alert[1]
                    site = alert[3] 
                    hostname = alert[4]
                    
                    
                    room_id = CPOCRoomID # 
                    Message = cpocClearMessage.format(site, event_name, hostname)
                    
                    
                    dashboard_url = ZabbixURL_CPOC
                    if dashboard_url:
                        Message += f"\nCPOC Dashboard: ({dashboard_url})\n\n"

                    apiWebex.messages.create(roomId=room_id, markdown=Message )
                    
                cur.execute(cpocAlertToBeRemoved, (id,))
        
        conn.commit()
        
    except Exception as e:
        print(f"Error during alertCheckingCPOC: {e}")
        conn.rollback()
    finally:
        cur.close()



try:
    alertCheckingHosts(getCurrentProblems(), getDBexistingProblems())
    alertCheckingSites(getSiteProblems(), getDBSiteProblems())
    alertCheckingCPOC(getCPOCProblems(), getDBCPOCProblems()) # <-- Ejecución de la lógica CPOC

finally:
    conn.close()