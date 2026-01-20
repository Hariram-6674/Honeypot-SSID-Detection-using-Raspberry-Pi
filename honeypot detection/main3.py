import time
import subprocess
import asyncio
import threading
from datetime import datetime
from typing import List, Dict, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from collections import defaultdict
import re
import logging
import os
import json
import requests
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn


class NetworkInfo(BaseModel):
    ssid: str
    bssid: str
    rssi: Optional[int] = None
    channel: Optional[int] = None
    security: Optional[str] = None
    vendor: Optional[str] = None
    is_suspicious: bool = False
    is_honeypot: bool = False
    is_whitelisted: bool = False
    first_seen: str
    last_seen: str

class WhitelistEntry(BaseModel):
    ssid: str
    bssids: List[str]

class SuspiciousAlert(BaseModel):
    ssid: str
    bssid: str
    vendor: str
    rssi: Optional[int]
    channel: Optional[int]
    security: Optional[str]
    alert_type: str  
    timestamp: str

class MonitorStatus(BaseModel):
    is_running: bool
    scan_count: int
    last_scan_time: str
    total_networks: int
    suspicious_networks: int
    uptime_seconds: int


SCAN_INTERFACE = "wlan0"
SCAN_INTERVAL = 20
ALERT_COOLDOWN_SECS = 30


CONFIG_FILE = "wifi_monitor_config.json"
WHITELIST_FILE = "whitelist.json"


DEFAULT_CONFIG = {
    "SCAN_INTERFACE": "wlan0",
    "SCAN_INTERVAL": 20,
    "ALERT_COOLDOWN_SECS": 180,
    "EMAIL_USER": "",
    "EMAIL_PASS": "",
    "EMAIL_TO": "",
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 587,
    "EMAIL_ENABLED": True,
    "KNOWN_HONEYPOT_SSIDS": r"^(Free[_ ]?Public[_ ]?WiFi|Starbucks[_ ]?Free|Evil[_ ]?Twin(Net)?)$"
}


DEFAULT_WHITELIST = {
    "HomeWiFi": ["00:11:22:33:44:55"],
    "OfficeNet": ["66:77:88:99:AA:BB"]
}


networks = defaultdict(set)
network_rssi = defaultdict(dict)
network_chan = defaultdict(dict)
network_sec = defaultdict(dict)
network_vendors = defaultdict(dict)
network_first_seen = defaultdict(dict)
network_last_seen = defaultdict(dict)
last_alert_time = {}
suspicious_alerts = []
monitor_stats = {
    "is_running": False,
    "scan_count": 0,
    "last_scan_time": "",
    "start_time": None,
    "total_networks": 0,
    "suspicious_networks": 0
}


monitor_thread = None
def get_vendor_from_mac(mac_address):
    try:
        
        mac = mac_address.upper().replace("-", ":").strip()
        print(f"Querying MAC: {mac}")

        url = f"https://api.macvendors.com/{mac}"
        headers = {"User-Agent": "Mozilla/5.0"}  
        response = requests.get(url, headers=headers, timeout=5)

        print(f"Status: {response.status_code}, Body: {response.text}")

        if response.status_code == 200 and response.text.strip():
            return response.text.strip()
        else:
            return "Unknown Vendor"

    except Exception as e:
        print(f"Error: {e}")
        return "Unknown Vendor"

def load_config():
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

def save_config(config):
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def load_whitelist():
    
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as f:
            return json.load(f)
    else:
        save_whitelist(DEFAULT_WHITELIST)
        return DEFAULT_WHITELIST

def save_whitelist(whitelist):
    
    with open(WHITELIST_FILE, 'w') as f:
        json.dump(whitelist, f, indent=2)


config = load_config()
WHITELIST_ENTRIES = load_whitelist()


def setup_logging():
    
    log_dir = "wifi_monitor_logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_filename = os.path.join(log_dir, f"wifi_monitor_api_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger(__name__)
    logger.info(f"API Logging initialized. Log file: {log_filename}")
    return logger

logger = setup_logging()


def send_email_alert(alert: SuspiciousAlert):
    
    try:
        if not config.get("EMAIL_ENABLED", False):
            logger.debug("Email alerts disabled in configuration")
            return False
        
        
        smtp_server = config.get("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = config.get("SMTP_PORT", 587)
        email_user = config.get("EMAIL_USER","")
        email_pass = config.get("EMAIL_PASS","")
        email_to = config.get("EMAIL_TO","")
        print(email_user)
        
        if not all([email_user, email_pass, email_to]):
            logger.warning("Email configuration incomplete, skipping email alert")
            return False
        logger.info(email_user,email_to)
        
        msg = MIMEMultipart()
        msg['From'] = email_user
        msg['To'] = email_to
        msg['Subject'] = f"WiFi Security Alert: {alert.alert_type.upper()} Network Detected"
        
        body = f"""
WiFi Security Monitor Alert

Alert Type: {alert.alert_type.upper()}
Network SSID: {alert.ssid}
BSSID (MAC): {alert.bssid}
Vendor: {alert.vendor}
Signal Strength: {alert.rssi} dBm
Channel: {alert.channel}
Security: {alert.security}
Timestamp: {alert.timestamp}

Alert Details:
"""
        
        if alert.alert_type == "rogue":
            body += f"- A rogue access point has been detected using the trusted SSID '{alert.ssid}'\n"
            body += f"- This could be an attempt to impersonate your legitimate network\n"
        elif alert.alert_type == "honeypot":
            body += f"- A potential honeypot network '{alert.ssid}' has been detected\n"
            body += f"- This network may be designed to capture user credentials\n"
        elif alert.alert_type == "untrusted":
            body += f"- An untrusted network '{alert.ssid}' has been detected\n"
            body += f"- This network is not in your whitelist of known safe networks\n"
        
        body += f"\nRecommendations:\n"
        body += f"- Investigate the network immediately\n"
        body += f"- Do not connect to suspicious networks\n"
        body += f"- Consider updating your network security policies\n"
        body += f"\nThis alert was generated by your WiFi Security Monitor at {alert.timestamp}\n"
        
        msg.attach(MIMEText(body, 'plain'))
        
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_user, email_pass)
        text = msg.as_string()
        server.sendmail(email_user, email_to, text)
        server.quit()
        
        logger.info(f"Email alert sent successfully for {alert.alert_type} network: {alert.ssid}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")
        return False


def ts():
    return time.strftime("%Y-%m-%d %H:%M:%S")

def nmcli_scan_multiline():
	try:
		output = subprocess.check_output(
            [
                "nmcli", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY",
                "dev", "wifi", "list", "ifname", config.get("SCAN_INTERFACE", "wlan0")
            ],
            text=True,
            timeout=30)
		logger.debug("WiFi scan completed successfully")
		return output
	except Exception as e:
		error_msg = f"Failed to scan WiFi with nmcli: {e}"
		logger.error(error_msg)
		return ""

def parse_nmcli_multiline(output):
    current_time = ts()
    network_count = 0
    
    lines = output.strip().split('\n')
    if len(lines) < 2:  
        return
        
    
    for line in lines[1:]:
        
        
        parts = line.strip().split()
        if len(parts) < 4:
            continue
            
        
        
        bssid_idx = -1
        for i, part in enumerate(parts):
            if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', part):
                bssid_idx = i
                break
        
        if bssid_idx == -1:
            continue
            
        
        if bssid_idx == 0:
            ssid = ""  
        else:
            ssid = " ".join(parts[:bssid_idx]).strip()
            
        bssid = parts[bssid_idx].lower()
        
        
        remaining = parts[bssid_idx + 1:]
        if len(remaining) < 2:
            continue
            
        chan_str = remaining[0]
        sig_str = remaining[1]
        sec_str = " ".join(remaining[2:]) if len(remaining) > 2 else ""
        
        
        try:
            chan = int(chan_str) if chan_str and chan_str != '--' else None
        except:
            chan = None
            
        try:
            rssi = int(sig_str) if sig_str and sig_str != '--' else None
        except:
            rssi = None
        
        
        if not ssid and not bssid:
            continue
            
        
        if not ssid:
            ssid = f"<Hidden Network>"
            
        
        process_network_block(ssid, bssid, chan, rssi, sec_str, current_time)
        network_count += 1
    
    
    current_time_epoch = time.time()
    expire_threshold = 300  
     
    for ssid in list(networks.keys()):
        for bssid in list(networks[ssid]):
            try:
                last_seen_str = network_last_seen.get(ssid, {}).get(bssid, "")
                if last_seen_str:
                    last_seen_epoch = time.mktime(time.strptime(last_seen_str, "%Y-%m-%d %H:%M:%S"))
                    if current_time_epoch - last_seen_epoch > expire_threshold:
                        networks[ssid].discard(bssid)
                        
                        network_rssi.get(ssid, {}).pop(bssid, None)
                        network_chan.get(ssid, {}).pop(bssid, None)
                        network_sec.get(ssid, {}).pop(bssid, None)
                        network_vendors.get(ssid, {}).pop(bssid, None)
                        network_first_seen.get(ssid, {}).pop(bssid, None)
                        network_last_seen.get(ssid, {}).pop(bssid, None)
            except:
                pass
         
        
        if ssid in networks and not networks[ssid]:
            del networks[ssid]

    total_network_count = sum(len(bssids) for bssids in networks.values())
    monitor_stats["total_networks"] = total_network_count
    logger.info(f"Current scan: {network_count} networks | Total accumulated: {total_network_count} networks")
    
def process_network_block(ssid, bssid, chan, rssi, security, current_time):
	if ssid and bssid:
			networks[ssid].add(bssid)   
			
			
			if rssi is not None:
				network_rssi[ssid][bssid] = rssi
			if chan is not None:
				network_chan[ssid][bssid] = chan
			if security is not None:
				network_sec[ssid][bssid] = security
			
			
			try:
				if ssid not in network_vendors or bssid not in network_vendors[ssid]:
					vendor = get_vendor_from_mac(bssid)
					if ssid not in network_vendors:
						network_vendors[ssid] = {}
					network_vendors[ssid][bssid] = vendor
					
					time.sleep(0.1)
			except Exception:
				if ssid not in network_vendors:
					network_vendors[ssid] = {}
				network_vendors[ssid][bssid] = "Unknown Vendor"
			
			
			if ssid not in network_first_seen or bssid not in network_first_seen[ssid]:
				if ssid not in network_first_seen:
					network_first_seen[ssid] = {}
				network_first_seen[ssid][bssid] = current_time
			
			if ssid not in network_last_seen:
				network_last_seen[ssid] = {}
			network_last_seen[ssid][bssid] = current_time

def is_whitelisted(ssid, bssid):
    bssid = bssid.lower()
    trusted_bssids = WHITELIST_ENTRIES.get(ssid, [])
    return bssid in [b.lower() for b in trusted_bssids]

def detect_suspicious():
    suspicious = []
    honeypot_pattern = config.get("KNOWN_HONEYPOT_SSIDS", DEFAULT_CONFIG["KNOWN_HONEYPOT_SSIDS"])
    
    for ssid, bssids in networks.items():
        for bssid in bssids:
            alert_type = None
            
            
            if ssid in WHITELIST_ENTRIES and not is_whitelisted(ssid, bssid):
                alert_type = "rogue"
            
            elif re.match(honeypot_pattern, ssid, re.IGNORECASE):
                alert_type = "honeypot"
            
            elif ssid not in WHITELIST_ENTRIES:
                alert_type = "untrusted"
            
            if alert_type:
                suspicious.append((ssid, bssid, alert_type))
    
    monitor_stats["suspicious_networks"] = len(suspicious)
    return suspicious

def should_alert(ssid, bssid, now):
    key = (ssid, bssid)
    last = last_alert_time.get(key)
    cooldown = config.get("ALERT_COOLDOWN_SECS", DEFAULT_CONFIG["ALERT_COOLDOWN_SECS"])
    
    if last is None or (now - last) >= cooldown:
        last_alert_time[key] = now
        return True
    return False

def create_alert(ssid, bssid, alert_type):
    
    vendor = network_vendors.get(ssid, {}).get(bssid, "Unknown Vendor")
    rssi = network_rssi.get(ssid, {}).get(bssid)
    channel = network_chan.get(ssid, {}).get(bssid)
    security = network_sec.get(ssid, {}).get(bssid)
    
    alert = SuspiciousAlert(
        ssid=ssid,
        bssid=bssid,
        vendor=vendor,
        rssi=rssi,
        channel=channel,
        security=security,
        alert_type=alert_type,
        timestamp=ts()
    )
    
    suspicious_alerts.append(alert)
    
    if len(suspicious_alerts) > 1000:
        suspicious_alerts.pop(0)
    
    logger.error(f"ALERT CREATED - {alert_type.upper()}: {ssid} ({bssid}) - {vendor}")
    
    
    success = send_email_alert(alert)
    if success:
        logger.info(f"Email sent for alert: {ssid} ({bssid})")
    else:
        logger.error(f"Email failed for alert: {ssid} ({bssid})")
    
    return alert



def monitoring_worker():
    logger.info("WiFi monitoring worker started")
    monitor_stats["is_running"] = True
    monitor_stats["start_time"] = time.time()
   
    
    while monitor_stats["is_running"]:
        try:
            monitor_stats["scan_count"] += 1
            logger.info(f"Starting WiFi scan #{monitor_stats['scan_count']}")
            
            output = nmcli_scan_multiline()
            parse_nmcli_multiline(output)
            suspicious = detect_suspicious()
            
            monitor_stats["last_scan_time"] = ts()
            
            if suspicious:
                now = time.time()
                new_alerts = [(s, b, t) for (s, b, t) in suspicious if should_alert(s, b, now)]
                
                for ssid, bssid, alert_type in new_alerts:
                    create_alert(ssid, bssid, alert_type)
                
                if new_alerts:
                    logger.critical(f"NEW ALERTS TRIGGERED - Count: {len(new_alerts)}")
                else:
                    logger.info(f"Suspicious networks in cooldown: {len(suspicious)}")
            else:
                logger.info("No suspicious networks detected")
            
            time.sleep(config.get("SCAN_INTERVAL", DEFAULT_CONFIG["SCAN_INTERVAL"]))
            
        except Exception as e:
            logger.error(f"Error in monitoring worker: {e}")
            time.sleep(10)  
    
    logger.info("WiFi monitoring worker stopped")


@asynccontextmanager
async def lifespan(app: FastAPI):
    
    global monitor_thread
    monitor_thread = threading.Thread(target=monitoring_worker, daemon=True)
    monitor_thread.start()
    logger.info("WiFi Monitor API started - Background monitoring initiated")
    yield
    
    monitor_stats["is_running"] = False
    if monitor_thread and monitor_thread.is_alive():
        monitor_thread.join(timeout=5)
    logger.info("WiFi Monitor API stopped")

app = FastAPI(
    title="WiFi Security Monitor",
    description="Raspberry Pi WiFi Network Security Monitoring System",
    version="1.0.0",
    lifespan=lifespan
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.get("/")
async def root():
    return {"message": "WiFi Security Monitor API", "status": "running"}

@app.get("/status", response_model=MonitorStatus)
async def get_monitor_status():
    uptime = int(time.time() - monitor_stats["start_time"]) if monitor_stats["start_time"] else 0
    return MonitorStatus(
        is_running=monitor_stats["is_running"],
        scan_count=monitor_stats["scan_count"],
        last_scan_time=monitor_stats["last_scan_time"],
        total_networks=monitor_stats["total_networks"],
        suspicious_networks=monitor_stats["suspicious_networks"],
        uptime_seconds=uptime
    )

@app.get("/networks", response_model=List[NetworkInfo])
async def get_all_networks():
    network_list = []
    honeypot_pattern = config.get("KNOWN_HONEYPOT_SSIDS", DEFAULT_CONFIG["KNOWN_HONEYPOT_SSIDS"])
    
    for ssid, bssids in networks.items():
        for bssid in bssids:
            is_whitelisted_flag = is_whitelisted(ssid, bssid)
            is_honeypot_flag = bool(re.match(honeypot_pattern, ssid, re.IGNORECASE))
            is_suspicious_flag = not is_whitelisted_flag or is_honeypot_flag
            
            network_info = NetworkInfo(
                ssid=ssid,
                bssid=bssid,
                rssi=network_rssi.get(ssid, {}).get(bssid),
                channel=network_chan.get(ssid, {}).get(bssid),
                security=network_sec.get(ssid, {}).get(bssid),
                vendor=network_vendors.get(ssid, {}).get(bssid, "Unknown Vendor"),
                is_suspicious=is_suspicious_flag,
                is_honeypot=is_honeypot_flag,
                is_whitelisted=is_whitelisted_flag,
                first_seen=network_first_seen.get(ssid, {}).get(bssid, "Unknown"),
                last_seen=network_last_seen.get(ssid, {}).get(bssid, "Unknown")
            )
            network_list.append(network_info)
    
    return network_list

@app.get("/networks/suspicious", response_model=List[NetworkInfo])
async def get_suspicious_networks():
    all_networks = await get_all_networks()
    return [network for network in all_networks if network.is_suspicious]

@app.get("/alerts", response_model=List[SuspiciousAlert])
async def get_alerts(limit: int = 100):
    return suspicious_alerts[-limit:] if suspicious_alerts else []

@app.get("/alerts/recent", response_model=List[SuspiciousAlert])
async def get_recent_alerts(hours: int = 24):
    cutoff_time = time.time() - (hours * 3600)
    recent_alerts = []
    
    for alert in suspicious_alerts:
        try:
            alert_time = time.mktime(time.strptime(alert.timestamp, "%Y-%m-%d %H:%M:%S"))
            if alert_time >= cutoff_time:
                recent_alerts.append(alert)
        except Exception:
            continue
    
    return recent_alerts

@app.get("/whitelist", response_model=Dict[str, List[str]])
async def get_whitelist():
    return WHITELIST_ENTRIES

@app.post("/whitelist/{ssid}")
async def add_to_whitelist(ssid: str, bssids: List[str]):
    global WHITELIST_ENTRIES
    
    
    bssids_lower = [bssid.lower() for bssid in bssids]
    
    if ssid in WHITELIST_ENTRIES:
        
        existing_bssids = set(b.lower() for b in WHITELIST_ENTRIES[ssid])
        existing_bssids.update(bssids_lower)
        WHITELIST_ENTRIES[ssid] = list(existing_bssids)
    else:
        
        WHITELIST_ENTRIES[ssid] = bssids_lower
    
    save_whitelist(WHITELIST_ENTRIES)
    logger.info(f"Added to whitelist - SSID: {ssid}, BSSIDs: {bssids}")
    
    return {"message": f"Added {ssid} to whitelist with {len(bssids)} BSSID(s)"}

@app.put("/whitelist/{ssid}")
async def update_whitelist_entry(ssid: str, bssids: List[str]):
    global WHITELIST_ENTRIES
    
    bssids_lower = [bssid.lower() for bssid in bssids]
    WHITELIST_ENTRIES[ssid] = bssids_lower
    save_whitelist(WHITELIST_ENTRIES)
    logger.info(f"Updated whitelist entry - SSID: {ssid}, BSSIDs: {bssids}")
    
    return {"message": f"Updated whitelist entry for {ssid}"}

@app.delete("/whitelist/{ssid}")
async def remove_from_whitelist(ssid: str):
    global WHITELIST_ENTRIES
    
    if ssid in WHITELIST_ENTRIES:
        del WHITELIST_ENTRIES[ssid]
        save_whitelist(WHITELIST_ENTRIES)
        logger.info(f"Removed from whitelist - SSID: {ssid}")
        return {"message": f"Removed {ssid} from whitelist"}
    else:
        raise HTTPException(status_code=404, detail="SSID not found in whitelist")

@app.delete("/whitelist/{ssid}/{bssid}")
async def remove_bssid_from_whitelist(ssid: str, bssid: str):
    global WHITELIST_ENTRIES
    
    if ssid not in WHITELIST_ENTRIES:
        raise HTTPException(status_code=404, detail="SSID not found in whitelist")
    
    bssid_lower = bssid.lower()
    if bssid_lower in [b.lower() for b in WHITELIST_ENTRIES[ssid]]:
        WHITELIST_ENTRIES[ssid] = [b for b in WHITELIST_ENTRIES[ssid] if b.lower() != bssid_lower]
        
        
        if not WHITELIST_ENTRIES[ssid]:
            del WHITELIST_ENTRIES[ssid]
        
        save_whitelist(WHITELIST_ENTRIES)
        logger.info(f"Removed BSSID from whitelist - SSID: {ssid}, BSSID: {bssid}")
        return {"message": f"Removed BSSID {bssid} from {ssid}"}
    else:
        raise HTTPException(status_code=404, detail="BSSID not found in whitelist entry")

@app.post("/monitoring/start")
async def start_monitoring():
    global monitor_thread
    
    if not monitor_stats["is_running"]:
        monitor_stats["is_running"] = True
        monitor_thread = threading.Thread(target=monitoring_worker, daemon=True)
        monitor_thread.start()
        logger.info("Monitoring started via API")
        return {"message": "Monitoring started"}
    else:
        return {"message": "Monitoring is already running"}

@app.post("/monitoring/stop")
async def stop_monitoring():
    if monitor_stats["is_running"]:
        monitor_stats["is_running"] = False
        logger.info("Monitoring stopped via API")
        return {"message": "Monitoring stopped"}
    else:
        return {"message": "Monitoring is not running"}

@app.get("/config")
async def get_config():
    return config

@app.put("/config")
async def update_config(new_config: dict):
    global config
    config.update(new_config)
    save_config(config)
    logger.info(f"Configuration updated: {new_config}")
    return {"message": "Configuration updated"}

@app.delete("/alerts")
async def clear_alerts():
    global suspicious_alerts
    count = len(suspicious_alerts)
    suspicious_alerts.clear()
    logger.info(f"Cleared {count} alerts via API")
    return {"message": f"Cleared {count} alerts"}

if __name__ == "__main__":
    uvicorn.run(
        "main3:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        access_log=True
    )
