param (
    [string]$adminPassword,
    [string]$vmName,
    [string]$resourceGroupName,
    [string]$LDAPUserAccount1,
    [string]$LDAPUserAccount2
)

Import-Module Az.Compute
Import-Module Az.Accounts

Connect-AzAccount -Identity

$PythonScript = @"
from ldap3 import Server, Connection, ALL, SIMPLE

def connect_to_ad(server_address, user, password):
    server = Server(server_address, get_info=ALL)
    try:
        conn = Connection(
            server,
            user=user,
            password=password,
            authentication=SIMPLE,
            auto_bind=True
        )
        if conn.bind():
            print(f\"Successfully connected as {user}\")
        else:
            print(f\"Failed to bind: {conn.result}\")
    except Exception as e:
        print(f\"An error occurred: {e}\")
    finally:
        if conn:
            conn.unbind()

AD_SERVER = 'ldap://10.0.0.4'
AD_USER1 = 'ODOMAIN\\\\$LDAPUserAccount1'
AD_USER2 = 'ODOMAIN\\\\$LDAPUserAccount2'
AD_PASSWORD = '$adminPassword'

connect_to_ad(AD_SERVER, AD_USER1, AD_PASSWORD)
connect_to_ad(AD_SERVER, AD_USER2, AD_PASSWORD)
"@

$Command = @"
#!/bin/bash
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv freerdp2-x11 xvfb
python3 -m pip install --user pipx
python3 -m pipx ensurepath
export PATH="`$PATH`:`$HOME/.local/bin"
python3 -m pipx install impacket
pip3 install ldap3

cat << 'EOF' > /tmp/temp_script.py
$PythonScript
EOF

Xvfb :99 -screen 0 1024x768x16 &
sleep 30
su - adm0 -c 'whoami'
su - adm0 -c 'DISPLAY=:99 xfreerdp --version'
su - adm0 -c 'DISPLAY=:99 timeout 90 xfreerdp /v:10.0.0.6 /u:adm0 /p:'$adminPassword' /dynamic-resolution /cert:ignore &'
python3 /tmp/temp_script.py
sudo /root/.local/bin/GetUserSPNs.py -dc-ip 10.0.0.4 odomain.local/candice.kevin:'$adminPassword' -request | head -n 3 2>/dev/null
"@

$output = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroupName -VMName $vmName -CommandId "RunShellScript" -ScriptString $Command
# View the full output
$output.Value | ForEach-Object { $_.Message }
