import requests, json, logging, os, time
from urllib.parse import urlparse

# disable warning messages for untrusted TLS certificate
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning 
except:
    print('module InsecureRequestWarning import error')
else:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    print('module InsecureRequestWarning import successfully')

#-----------------------------------------------------------------------
# tmos Class
# This class manage device base functions
#-----------------------------------------------------------------------
class tmos:
    def __init__(self, host='localhost', user='admin', password='admin', legacy=False, token = None):
        self.host = host
        # Authentication mode
        self.shared_auth_uri = {'login' : '/mgmt/shared/authn/login', 'token' : '/mgmt/shared/authz/tokens/'}
        self.session = requests.Session()
        self.legacy = legacy
        self.session_timeout = 15
        if token is not None:
            self.token = token
            self.session.headers.update({"Content-Type": "application/json", "X-F5-Auth-Token" : self.token})
            self.update_session_timeout(600)
        elif legacy:
            self.session.auth = (user, password)
            # Force request with basic auth to detect auth error
            self.get('/mgmt/tm/sys/management-ip?$select=name')
        else:
            self.get_token(user, password)
            self.session.headers.update({"Content-Type": "application/json", "X-F5-Auth-Token" : self.token})
            self.update_session_timeout(600)
          
    
    #-----------------------------------------------------------------------
    # get_token FUNCTION
    #-----------------------------------------------------------------------
    def get_token(self, user, password):
        authData = {"username" : user, "password" : password, 'loginProviderName' : 'tmos'}
        result = self.post(self.shared_auth_uri['login'], data = authData)
        if 'token' in result.json():
            self.token =  result.json()['token']['token']
        else:
            raise ValueError("No token value in login response." )

    #-----------------------------------------------------------------------
    # update_session_timeout FUNCTION
    #-----------------------------------------------------------------------
    def update_session_timeout(self, timeout):
        if self.legacy:
            print("Legacy Mode... No Session timeout")
        else:
            result = self.patch(self.shared_auth_uri['token'] + self.token, data = {"timeout" : timeout })
            if result.status_code >= 400:
                raise ValueError("URI : %s / wrong status code : %s" % (uri, res.status_code) )        
            print("Session timeout updated succesully")

    #-----------------------------------------------------------------------
    # get FUNCTION
    #-----------------------------------------------------------------------
    def get(self, uri, headers = None):
        return self.session.get('https://' + self.host + uri, verify=False, headers = headers, timeout = self.session_timeout)

    #-----------------------------------------------------------------------
    # post FUNCTION
    #-----------------------------------------------------------------------
    def post(self, uri, data, headers = {'Content-Type': 'application/json'}):
      if headers['Content-Type'] == 'application/json': 
        return self.session.post('https://' + self.host + uri, data=json.dumps(data), headers = headers, verify=False, timeout= self.session_timeout)
      else:
        return self.session.post('https://' + self.host + uri, data=data, headers = headers, verify=False, timeout= self.session_timeout)

    #-----------------------------------------------------------------------
    # patch FUNCTION
    #-----------------------------------------------------------------------
    def patch(self, uri, data, headers = {'Content-Type': 'application/json'}):
        return self.session.patch('https://' + self.host + uri, data=json.dumps(data), headers = headers, verify=False, timeout= self.session_timeout)

    #-----------------------------------------------------------------------
    # patch FUNCTION
    #-----------------------------------------------------------------------
    def get_failover_devicegroup(self):
        try:
            result = self.get('/mgmt/tm/cm/device-group?$select=name,type')

        except ValueError as e:
            print('Get Failover deviceGroup issue ' + str(e))
            self.device_group = ''
        else:
            if result.status_code >= 400:
                print('Get Failover deviceGroup issue ' + str(e))
                self.device_group = ''
            else:
                res = result.json()
                self.device_group = next((dg['name'] for dg in res['items'] if dg['type'] == 'sync-failover'), '')
        self.ha_mode = 1 if self.device_group != '' else 0
        return self.device_group

    #-----------------------------------------------------------------------
    # get_failover_status FUNCTION
    #-----------------------------------------------------------------------
    def get_failover_status(self,trafficGroup = 'traffic-group-1'):
        try:
            result = self.get('/mgmt/tm/cm/traffic-group/~Common~'+ trafficGroup +'/stats?$select=failoverState')
            res = result.json()
        except ValueError as e:
            print('Get Failover status issue ' + str(e))
            return ''
        return list(res['entries'].values())[0]['nestedStats']['entries']['failoverState']['description']
    #
    #-----------------------------------------------------------------------
    # sync_config FUNCTION
    #-----------------------------------------------------------------------
    def sync_config(self):
        if self.ha_mode == 1:
            postData = { "command" : "run" }
            try:
                res = self.post('/mgmt/tm/cm/config-sync?options=to-group+' + self.device_group, data=postData)
            except ValueError as e:
                print('Synchronization issue ' + str(e))
        else:
            print('no group to synchronize')

    def get_csr(self, name):
        postData = {"command": "run","utilCmdArgs": "-c 'tmsh list sys crypto csr " + name + "'"}
        result = self.post('/mgmt/tm/util/bash', data=postData)
        res = result.json()
        search = "-----END CERTIFICATE REQUEST-----"
        return res['commandResult'][:res['commandResult'].find(search)+len(search)]

    #-----------------------------------------------------------------------
    # iapplx_install_package FUNCTION
    #-----------------------------------------------------------------------

    def iapplx_install_package(file):
        filename = os.path.basename(file)
        targetURL = 'https://' + self.host + '/mgmt/shared/iapp/package-management-tasks'
        h = {"Content-Type": "application/json"}
        postData = {"operation":"INSTALL","packageFilePath":"/var/config/rest/downloads/"+ filename}
        res = self.session.get(targetURL, headers=h, verify=False, timeout= self.session_timeout)
        if res.status_code >= 400:
            return ""
        else:
            d = json.loads(res.text)
            if 'id' in d:
                return d['id']
            else:
                return ""

    #-----------------------------------------------------------------------
    # iapplx_check_task_status FUNCTION
    #-----------------------------------------------------------------------

    def iapplx_check_task_status(task_id):
        targetURL = 'https://' + self.host + '/mgmt/shared/iapp/package-management-tasks/'+ task_id
        h = {"Content-Type": "application/json"}
        res = self.session.get(targetURL, headers=h, verify=False, timeout= self.session_timeout)
        if res.status_code != 200:
            return 0
        else:
            return 1
    #-----------------------------------------------------------------------
    # download FUNCTION
    #-----------------------------------------------------------------------
    def download(self,uri, filepath, chunk_size = 1024 * 1024, resume = False):
        # Initialize variables
        if resume:
            start = os.path.getsize(filepath)
            write_mode = 'ab'
        else:
            start = 0
            write_mode = 'wb'
        end = start + chunk_size - 1
        size = '*'

        headers = {'Content-Type': 'application/octet-stream'}
        filename = os.path.basename(filepath)

        # Create file buffer
        try:
            with open(filepath, write_mode) as fileobj:
                while True:
                    # Set new content range header
                    content_range = "%s-%s/%s" % (start, end, size)
                    headers['Content-Range'] = content_range
                    # Lauch REST request
                    res = self.session.get('https://' + self.host + uri + filename, headers=headers, verify=False, stream=True, timeout=self.session_timeout)
                    if res.status_code != 200:
                        fileobj.close()
                        if not resume:
                            os.remove(filepath)
                        raise ValueError("wrong status code : %s" % res.status_code )
                    
                    fileobj.write(res.content)
                    # Read Content Range values
                    print (res.headers['Content-Range'])
                    range_str, size_str = res.headers['Content-Range'].split('/')
                    start_str, end_str = range_str.split('-')
                    end = int(end_str)
                    # Determine the total number of bytes to read
                    if size == '*':
                        size = int(size_str) if size_str != '*' else 0
                        # Stops if the file is empty
                        if size == 0:
                            print("Successful Transfer.")
                            break
                        elif size > 800000000:
                            self.update_session_timeout(3600)

                    if end == size - 1 :
                        print("Successful Transfer.")
                        break

                    # Set start 
                    start = end + 1
                    # Set End
                    end = min([start + chunk_size, size]) - 1
        except KeyboardInterrupt:
            print("Transfer interrupted.")
            fileobj.close()

    #-----------------------------------------------------------------------
    # upload FUNCTION
    #-----------------------------------------------------------------------
    def upload(self,uri, filepath, chunk_size = 1024 * 1024):
        # Initialize variables  
        start = 0
        size = os.path.getsize(filepath)
        filename = os.path.basename(filepath)
        headers = {'Content-Type': 'application/octet-stream'}

        # Extend token validity
        if size > 800000000:
            self.update_session_timeout(3600)
        # Create file buffer
        fileobj = open(filepath, 'rb')
        try:
            while True:
                # Slice source file
                file_slice = fileobj.read(chunk_size)
                if not file_slice:
                    print("Successful Transfer.")
                    break
                # Check file boundaries
                current_bytes = len(file_slice)
                end = min ([start + current_bytes, size]) -1

                # Set new content range header
                headers['Content-Range'] = "%s-%s/%s" % (start, end, size)
                print (headers['Content-Range'])
                # Lauch REST request
                res = self.session.post('https://' + self.host + uri + filename, data=file_slice, headers=headers, verify=False, timeout=self.session_timeout)
                if res.status_code != 200:
                    raise ValueError("wrong status code : %s" % res.status_code )
                # Shift to next slice
                start = end + 1
        except KeyboardInterrupt:
            print("Transfer interrupted.")
            fileobj.close()

#-----------------------------------------------------------------------
# asm Class
# This Class requires a tmos class object as single parameter
#-----------------------------------------------------------------------
class asm:
    def __init__(self, tmos):
        self.tmos = tmos
    #-----------------------------------------------------------------------
    # get_policy_list FUNCTION
    #-----------------------------------------------------------------------
    def get_policy_list(self):
        try:
            result = self.tmos.get('/mgmt/tm/asm/policies?$select=id,name')
            res = result.json()
        except ValueError as e:
            print('Get Policy list issue ' + str(res.e))
            return []
        else:
            self.policies = [(p['id'], p['name']) for p in res['items']] if 'items' in res and 'id' in res['items'][0] else []
            return self.policies
    #
    #-----------------------------------------------------------------------
    # set_policy_builder_parameter_list FUNCTION
    #-----------------------------------------------------------------------
    def set_policy_builder_parameter_list(self, policy_id, policy_name,parameter_dict):
        try:
            result = self.tmos.get('/mgmt/tm/asm/policies/' + policy_id + '/policy-builder')
            res = result.json()
        except ValueError as e:
            print(policy_name + ' - get current value error : ' + str(e))
            return 0
        nbChanges = 0
        patchData = {}
        for parameter, value in parameter_dict.items():
            if parameter not in res:
                print(policy_name + ' - error : ' + parameter + " not in list")
            elif type(res[parameter]) != bool and res[parameter] == value:
                print(policy_name + ' - parameter ' + parameter + ' value is already set to ' + value)
            elif type(res[parameter]) == bool and str(res[parameter]).lower() == value.lower():
                print(policy_name + ' - parameter ' + parameter + ' value is already set to ' + str(value))
            else:
                nbChanges += 1
                print(policy_name + ' - changing parameter ' + parameter + ' from ' + str(res[parameter]) + ' to ' + value)
                if value.lower() == 'true' or value.lower() == 'false': value = value.lower()
                patchData[parameter] = str(value).lower()
        #   
        if nbChanges > 0:
            try:
                result = self.tmos.patch('/mgmt/tm/asm/policies/' + policy_id + '/policy-builder', data = patchData)
                res = result.json()
            except ValueError as e:
                print('Change error' + str(e))
                return 0
            return 1
        else:
            return 0

    #-----------------------------------------------------------------------
    # enable_ipi FUNCTION
    #-----------------------------------------------------------------------
    def enable_ipi(self, policy_id, policy_name):
        patchData = {"ipIntelligenceCategories":[], 'enabled': 'true'}
        for cat in ['Cloud-based Services', 'Mobile Threats', 'Tor Proxies', 'Windows Exploits', 'Web Attacks', 'BotNets', 'Scanners', 'Denial of Service', 'Infected Sources', 'Phishing Proxies', 'Anonymous Proxy']:
            patchData['ipIntelligenceCategories'].append( {'category': cat , 'alarm': 'true', 'block': 'false'} )
        result = self.tmos.patch('/mgmt/tm/asm/policies/' + policy_id + '/ip-intelligence',data = patchData)
        return result.json()

    #-----------------------------------------------------------------------
    # disable_ipi FUNCTION
    #-----------------------------------------------------------------------
    def disable_ipi(self, policy_id, policy_name):
        patchData = {"ipIntelligenceCategories":[], 'enabled': 'false'}
        for cat in ['Cloud-based Services', 'Mobile Threats', 'Tor Proxies', 'Windows Exploits', 'Web Attacks', 'BotNets', 'Scanners', 'Denial of Service', 'Infected Sources', 'Phishing Proxies', 'Anonymous Proxy']:
            patchData['ipIntelligenceCategories'].append( {'category': cat , 'alarm': 'false', 'block': 'false'} )
        result = self.tmos.patch('/mgmt/tm/asm/policies/' + policy_id + '/ip-intelligence',data = patchData)
        return result.json()
    
    #-----------------------------------------------------------------------
    # get_policy FUNCTION
    #-----------------------------------------------------------------------
    def get_policy(self, policy_id):
        res = self.tmos.post('/mgmt/tm/asm/tasks/export-policy', {"filename":policy_id + '.xml',"policyReference":{"link":"https://localhost/mgmt/tm/asm/policies/" + policy_id}})
        export_id = res.json()['id']
        while res.json()['status'] != 'COMPLETED':
            res = self.tmos.get('/mgmt/tm/asm/tasks/export-policy/' + export_id)
            time.sleep(5)
        return self.tmos.get('/mgmt/tm/asm/file-transfer/downloads/' + policy_id + '.xml') 
        

    #-----------------------------------------------------------------------
    # apply_policy FUNCTION
    #----------------------------------------------------------------------- 
    def apply_policy(self, policy_id, policy_name):
        postData = { "policyReference" : {"link" : "https://localhost/mgmt/tm/asm/policies/" + policy_id } }
        try:
            result = self.tmos.post('/mgmt/tm/asm/tasks/apply-policy',data = postData)
            res = result.json()
        except ValueError as e:
            print(policy_name + ' - Apply Policy error : ' + str(e))
            return 0
        if 'code' in res:
            print(policy_name + ' - failed to apply policy')
            return 0
        else:
            print(policy_name + ' - Apply Successful')
            return 1
