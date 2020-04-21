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
# device Class
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