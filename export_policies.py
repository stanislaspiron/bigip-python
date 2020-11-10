import bigip
import os, argparse, getpass, json, sys


#-----------------------------------------------------------------------
# MAIN
#----------------------------------------------------------------------- 
if __name__ == '__main__':
    target = "192.168.1.253"
    username = "admin"
    password = "stcl5801"
    # Get target from first argument
    target = sys.argv[1] if len(sys.argv) >= 2 else 'localhost'
    # Get username from second argument
    username = sys.argv[2] if  len(sys.argv) >= 3 else 'admin'
    # Get password from keyboard input
    password = getpass.getpass('Input ' + username + ' pass:')
    try:
        bigip_device=bigip.tmos(password = password, user=username, host=target)
        myASM=bigip.asm(bigip_device)
    except ValueError as ex:
        print(str(ex))
        sys.exit()
    except requests.exceptions.ConnectionError as ex:
        print('Connection to server error')
        sys.exit()
    # Update session timeout
    bigip_device.update_session_timeout(3600)
    # Get Failover device group
    bigip_device.get_failover_devicegroup()
    if bigip_device.ha_mode == 1 and bigip_device.get_failover_status() != 'active':
        print('running from non active device')
        sys.exit()
    
    print('.' * 100)
    # Get policy List
    myASM.get_policy_list()
    asm_policy_list_length = len(myASM.policies)
    first_item = True
    for index, p in enumerate(myASM.policies, start=1):
        # Add a timer between iteration to prevent CPU issues
        if first_item: first_item = False
        else: time.sleep(5)
        print('['+ str(index) +'/' + str(asm_policy_list_length) +'] - Policy ' + p[1]) 
        res = bigip_device.post('/mgmt/tm/asm/tasks/export-policy', {"filename":p + '.xml',"policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/" + p}})
        export_id = res.json()['id']
        while res.json()['status'] != 'COMPLETED':
            res = self.tmos.get('/mgmt/tm/asm/tasks/export-policy/' + export_id)
            time.sleep(5)
    print('.' * 100)
    print('## Finished. Goodbye')











import bigip, time
target = "192.168.1.253"
username = "admin"
password = "stcl5801"
bigip_device=bigip.tmos(password = password, user=username, host=target)
bigip_device.update_session_timeout(3600)
myASM=bigip.asm(bigip_device)

print('.' * 100)
# Get policy List
myASM.get_policy_list()
asm_policy_list_length = len(myASM.policies)
file_list = []
for index, p in enumerate(myASM.policies, start=1):
    print('['+ str(index) +'/' + str(asm_policy_list_length) +'] - Policy ' + p[1]) 
    filename = p[0] + '.xml'
    res = bigip_device.post('/mgmt/tm/asm/tasks/export-policy', {"filename": filename,"policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/" + p[0]}})
    export_id = res.json()['id']
    while res.json()['status'] != 'COMPLETED':
        res = bigip_device.get('/mgmt/tm/asm/tasks/export-policy/' + export_id)
        time.sleep(5)
    bigip_device.download('/mgmt/tm/asm/file-transfer/downloads/',  '/var/tmp/' + filename)
    file_list.append ({'filename' : filename, 'policy_name' : p[1]})





import bigip, time
target = "192.168.1.253"
username = "admin"
password = "stcl5801"
bigip_device=bigip.tmos(password = password, user=username, host=target)
bigip_device.update_session_timeout(3600)
myASM=bigip.asm(bigip_device)
for file in file_list:
    bigip_device.upload('/mgmt/tm/asm/file-transfer/uploads/',  '/var/tmp/' + file['filename'])
    res = bigip_device.post('/mgmt/tm/asm/tasks/import-policy', {"filename": file['filename'],"name": file['policy_name']})
    import_id = res.json()['id']
    while res.json()['status'] != 'COMPLETED' and res.json()['status'] != 'FAILURE':
        res = bigip_device.get('/mgmt/tm/asm/tasks/import-policy/' + import_id)
        time.sleep(5)
    print('Policy ' + file['policy_name'] + ' : ' + res.json()['status']) 
    
