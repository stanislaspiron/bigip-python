import requests, json, logging, os
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
    def __init__(self, host='localhost', user='admin', password='admin', legacy=False):
        self.host = host
        self.user, self.password = user, password
        self.session = requests.Session()
        self.legacy = legacy
        self.session_timeout = 15
        #self.session.headers.update({"Content-Type": "application/json"})
        # Authentication mode
        self.shared_auth_uri = {'login' : '/mgmt/shared/authn/login', 'token' : '/mgmt/shared/authz/tokens/'}
        if legacy:
          self.session.auth = (self.user, self.password)
          # Force request with basic auth to detect auth error
          self.get('/mgmt/tm/sys/management-ip?$select=name')
        else:
          self.get_token()
          self.session.headers.update({"Content-Type": "application/json", "X-F5-Auth-Token" : self.token})
          self.update_session_timeout(600)
    
    #-----------------------------------------------------------------------
    # get_token FUNCTION
    #-----------------------------------------------------------------------
    def get_token(self):
        authData = {"username" : self.user, "password" : self.password, 'loginProviderName' : 'tmos'}
        result = self.post(self.shared_auth_uri['login'], data = authData)
        if 'token' in result:
            self.token =  result['token']['token']
        else:
            raise ValueError("No token value in login response." )

    #-----------------------------------------------------------------------
    # update_session_timeout FUNCTION
    #-----------------------------------------------------------------------
    def update_session_timeout(self, timeout):
        if self.legacy:
            print("Legacy Mode... No Session timeout")
        else:
            self.patch(self.shared_auth_uri['token'] + self.token, data = {"timeout" : timeout })
            print("Session timeout updated succesully")

    #-----------------------------------------------------------------------
    # get FUNCTION
    #-----------------------------------------------------------------------
    def get(self, uri, headers = None, format = 'json'):
        res = self.session.get('https://' + self.host + uri, verify=False, headers = headers, timeout = self.session_timeout)
        if res.status_code >= 400:
            raise ValueError("URI : %s / wrong status code : %s" % (uri, res.status_code) )
        elif format == 'json':
            return res.json()
        else:
            return res.content
    
    #-----------------------------------------------------------------------
    # post FUNCTION
    #-----------------------------------------------------------------------
    def post(self, uri, data, headers = None, format = 'json'):
        if format == 'json':
            if headers:
                headers['Content-Type'] = 'application/json'
            else:
                headers = {'Content-Type': 'application/json'}
        res = self.session.post('https://' + self.host + uri, data=json.dumps(data), headers = headers, verify=False, timeout= self.session_timeout)
        if res.status_code >= 400:
            raise ValueError("wrong status code : %s" % res.status_code )
        elif format == 'json':
            return res.json()
        else:
            return res.content
    
    #-----------------------------------------------------------------------
    # patch FUNCTION
    #-----------------------------------------------------------------------
    def patch(self, uri, data, headers = None, format = 'json'):
        if format == 'json':
            if headers:
                headers['Content-Type'] = 'application/json'
            else:
                headers = {'Content-Type': 'application/json'}
        res = self.session.patch('https://' + self.host + uri, data=json.dumps(data), headers = headers, verify=False, timeout= self.session_timeout)
        if res.status_code >= 400:
            raise ValueError("wrong status code : %s" % res.status_code )
        elif format == 'json':
            return res.json()
        else:
            return res.content
    #-----------------------------------------------------------------------
    # patch FUNCTION
    #-----------------------------------------------------------------------
    def get_failover_devicegroup(self):
        try:
            res = self.get('/mgmt/tm/cm/device-group?$select=name,type')
        except ValueError as e:
            print('Get Failover deviceGroup issue ' + str(e))
            self.device_group = ''
        else:
            self.device_group = next((dg['name'] for dg in res['items'] if dg['type'] == 'sync-failover'), '')
        self.ha_mode = 1 if self.device_group != '' else 0
        return self.device_group

    #-----------------------------------------------------------------------
    # get_failover_status FUNCTION
    #-----------------------------------------------------------------------
    def get_failover_status(self,trafficGroup = 'traffic-group-1'):
        try:
            res = self.get('/mgmt/tm/cm/traffic-group/~Common~'+ trafficGroup +'/stats?$select=failoverState')
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

    #-----------------------------------------------------------------------
    # download FUNCTION
    #-----------------------------------------------------------------------
    def download(self,uri, filepath, chunk_size = 512 * 1024, resume = False):
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
                        size = int(size_str)
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
    def upload(self,uri, filepath, chunk_size = 512 * 1024):
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
            res = self.tmos.get('/mgmt/tm/asm/policies?$select=id,name')
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
            res = self.tmos.get('/mgmt/tm/asm/policies/' + policy_id + '/policy-builder')
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
                res = self.tmos.patch('/mgmt/tm/asm/policies/' + policy_id + '/policy-builder', data = patchData)
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
        return self.tmos.patch('/mgmt/tm/asm/policies/' + policy_id + '/ip-intelligence',data = patchData)

    #-----------------------------------------------------------------------
    # disable_ipi FUNCTION
    #-----------------------------------------------------------------------
    def disable_ipi(self, policy_id, policy_name):
        patchData = {"ipIntelligenceCategories":[], 'enabled': 'false'}
        for cat in ['Cloud-based Services', 'Mobile Threats', 'Tor Proxies', 'Windows Exploits', 'Web Attacks', 'BotNets', 'Scanners', 'Denial of Service', 'Infected Sources', 'Phishing Proxies', 'Anonymous Proxy']:
            patchData['ipIntelligenceCategories'].append( {'category': cat , 'alarm': 'false', 'block': 'false'} )
        return self.tmos.patch('/mgmt/tm/asm/policies/' + policy_id + '/ip-intelligence',data = patchData)

    #-----------------------------------------------------------------------
    # apply_policy FUNCTION
    #----------------------------------------------------------------------- 
    def apply_policy(self, policy_id, policy_name):
        postData = { "policyReference" : {"link" : "https://localhost/mgmt/tm/asm/policies/" + policy_id } }
        try:
            res = self.tmos.post('/mgmt/tm/asm/tasks/apply-policy',data = postData)
        except ValueError as e:
            print(policy_name + ' - Apply Policy error : ' + str(e))
            return 0
        if 'code' in res:
            print(policy_name + ' - failed to apply policy')
            return 0
        else:
            print(policy_name + ' - Apply Successful')
            return 1