Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity


$resourceGroupNameOps = "ITOperations"
$bastionName = "bastion-gw01"



$BastionSimScript = @"
import os
import time
from random import choice, randint

# Map numeric severity levels to syslog priority names
SEVERITY_MAP = {
    0: "emerg",
    1: "alert",
    2: "crit",
    3: "err",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug"
}

def log_cef_message(severity, signature_id, name, extensions):
    """Helper function to log CEF-compliant messages using logger."""
    base_cef = f"CEF:0|Linux|SecurityMonitoring|1.0|{signature_id}|{name}|{severity}|"
    extension_str = " ".join([f"{key}={value}" for key, value in extensions.items()])
    cef_message = f"{base_cef}{extension_str}"

    # Map severity to a valid syslog priority name
    severity_name = SEVERITY_MAP.get(severity, "info")  # Default to "info" if unknown
    os.system(f"logger -p auth.{severity_name} '{cef_message}'")
    print(cef_message)

def generate_failed_ssh_logins():
    users = ["root", "admin", "user1", "contractor"]
    ip_addresses = ["192.168.1.10", "203.0.113.5", "10.0.0.25"]
    for _ in range(5):
        user = choice(users)
        ip = choice(ip_addresses)
        extensions = {
            "duser": user,
            "src": ip,
            "dst": "10.0.0.11",
            "spt": 22,
            "msg": f"Failed password for {user}"
        }
        log_cef_message(5, "1001", "Failed SSH login", extensions)
        time.sleep(randint(1, 10))

def generate_specific_failed_logons():
    accounts = ["candice.kevin", "reportAdmin"]
    source_ip = "10.0.0.10"
    for _ in range(3):
        user = choice(accounts)
        extensions = {
            "duser": user,
            "src": source_ip,
            "dst": "10.0.0.1",
            "spt": 22,
            "msg": f"Failed password for {user}"
        }
        log_cef_message(5, "1002", "Failed SSH login (non-existent user)", extensions)
        time.sleep(randint(1, 10))

def generate_successful_logins():
    users = ["root", "admin", "user1"]
    ip_addresses = ["192.168.1.10", "203.0.113.5", "10.0.0.25"]
    for _ in range(4):
        user = choice(users)
        ip = choice(ip_addresses)
        extensions = {
            "duser": user,
            "src": ip,
            "dst": "10.0.0.11",
            "spt": 22,
            "msg": f"Accepted password for {user}"
        }
        log_cef_message(6, "1003", "Successful SSH login", extensions)
        time.sleep(randint(1, 10))

def generate_privilege_escalation_logs():
    users = ["admin", "devops", "security_user"]
    for _ in range(3):
        user = choice(users)
        extensions = {
            "duser": user,
            "msg": f"User {user} attempted to execute 'sudo su' command"
        }
        log_cef_message(3, "1004", "Privilege escalation attempt", extensions)
        time.sleep(randint(1, 10))

def generate_system_alerts():
    extensions = {
        "msg": "Disk space usage exceeded threshold: /dev/sda1 at 95%",
        "disk": "/dev/sda1",
        "usage": "95%"
    }
    log_cef_message(2, "1005", "Critical system alert", extensions)
    time.sleep(randint(1, 10))

if __name__ == "__main__":
    print("Generating CEF-compliant security monitoring logs for Bastion Gateway...")
    generate_failed_ssh_logins()
    generate_specific_failed_logons()
    generate_successful_logins()
    generate_privilege_escalation_logs()
    generate_system_alerts()
"@

# Bash command to create and run the Python script
$BastionCommand = @"
#!/bin/bash
cat << 'EOF' > /tmp/simscript.py
$BastionSimScript
EOF
(crontab -l; echo "*/2 * * * * python3 /tmp/simscript.py >> /tmp/runlog.log 2>&1") | crontab -
"@



# Execute the command on the Linux VM
Write-Output "Executing script on the Linux VM bastion-gw01..."
try {
    $result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupNameOps -VMName $bastionName -CommandId "RunShellScript" -ScriptString $BastionCommand

    if ($result) {
        Write-Output "Command executed successfully. Output:"
        $result.Value[0].Message | Write-Output
    } else {
        Write-Output "Command execution failed or returned no output."
    }
} catch {
    Write-Error "Failed to execute command: $_"
}
