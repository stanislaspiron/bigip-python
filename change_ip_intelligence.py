import bigip
import os, argparse, getpass, json, sys, time


#-----------------------------------------------------------------------
# MAIN
#----------------------------------------------------------------------- 
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        newMode = sys.argv[1]
    else:
        print("Usage : " + sys.argv[0] + " enable|disable [hostname [username]]")
        sys.exit()
    if len(sys.argv) >= 3:
        target = sys.argv[2]
    else:
        target = 'localhost'
    if  len(sys.argv) >= 4:
        username = sys.argv[3]
    else:
        username = 'admin'

    # Get target from second argument
    target = sys.argv[2] if len(sys.argv) >= 3 else 'localhost'
    # Get username from third argument
    username = sys.argv[3] if  len(sys.argv) >= 4 else 'admin'
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
        # Add a timer between iteration to prevent CPU issues>
        if first_item: first_item = False
        else: time.sleep(5)
        print('['+ str(index) +'/' + str(asm_policy_list_length) +'] - Policy ' + p[1]) 
        if newMode == 'disable':
            myASM.disable_ipi(p[0],p[1])
            myASM.apply_policy(p[0], p[1])
        else:
            myASM.enable_ipi(p[0],p[1])
            myASM.apply_policy(p[0], p[1])
    print('.' * 100)
    # Sync config
    bigip_device.sync_config()
    print('## Finished. Goodbye')