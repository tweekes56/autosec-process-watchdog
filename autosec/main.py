import psutil
import time
import os

# List of suspicious keywords (you can expand this)
SUSPICIOUS_KEYWORDS = ["powershell", "netcat", "mimikatz", "cmd", "ncat"]

flagged_pids = set()
log_path = os.path.join(os.path.dirname(__file__), "logs", "alerts.log")

def log_event(message):
    with open(log_path, "a") as f:
        f.write(f"[{time.ctime()}] {message}\n")


def scan_processes():
    print("[*] Scanning running processes...\n")
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            process_info = proc.info
            pid = process_info['pid']
            pname = process_info['name'].lower()
            
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in pname:
                    if pid in flagged_pids:
                        continue

                    flagged_pids.add(pid)
                    print(f"[!] Suspicious process detected: {pname} (PID: {pid})")

                    log_event(f"Suspicious process detected: {pname} (PID: {pid})")

                    try:
                        proc.terminate()
                        print(f"[x] Process: {pname} (PID: {pid}) was killed")

                        log_event(f"Suspicious process was suspended: {pname} (PID: {pid})")

                    except Exception as e:
                        print(f"[!] Failed to kill process {pname} (PID: {pid}): {e}")
                        
                        log_event(f"Suspicious process failed to suspend: {pname} (PID: {pid})")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

if __name__ == "__main__":
    while True:
        scan_processes()
        time.sleep(10)  # Scan every 10 seconds 
