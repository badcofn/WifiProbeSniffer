from scapy.all import *
import MySQLdb
import datetime

PROBE_REQUEST_TYPE=0
PROBE_REQUEST_SUBTYPE=4

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE:
            PrintPacket(pkt)

def PrintPacket(pkt):
    #database connection        
    db = MySQLdb.connect("localhost","wifiuser","WiFiPa$$word","snifferdb" )
    cursor = db.cursor()    
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') 
        
    print "Probe Request Captured:"
    try:
        extra = pkt.notdecoded
    except:
        extra = None
    if extra!=None:
        signal_strength = -(256-ord(extra[-4:-3]))
    else:
        signal_strength = -100
        print "No signal strength found"    
    print "Target: %s Source: %s SSID: %s RSSi: %d"%(pkt.addr3,pkt.addr2,pkt.getlayer(Dot11ProbeReq).info,signal_strength)
    
    #save to database
    mac_add = pkt.addr2
    ssid_probe = pkt.getlayer(Dot11ProbeReq).info  
    
    if ssid_probe != "":
        cursor.execute("INSERT INTO wifi_mac VALUES (%s, %s, %s, %s)",(mac_add, ssid_probe, st, signal_strength))
    db.commit()
    # disconnect from server
    db.close()
    
def main():
    
    print "Scanning for wireless probe requests:"
    sniff(iface=sys.argv[1],prn=PacketHandler)    

if __name__=="__main__":
    main()
