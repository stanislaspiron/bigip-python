import bigip
import requests, argparse, getpass

if __name__ == "__main__":
    # Configure parsers
    parser = argparse.ArgumentParser(description='Remove tcp:443 from self-allow')
    parser.add_argument("filename", help='filename')
    parser.add_argument("username", help='BIG-IP Username')

    args = vars(parser.parse_args())
    # Set variables
    filename = args['filename']
    username = args['username']
    print('Enter \'{}\' password: '.format(args['username']))
    password = getpass.getpass()
    f = open(filename)
    for line in f:
        hostname = line.strip()
        print(hostname)
        try:
            f5ve = bigip.tmos(hostname, username, password, legacy = True)
            res = f5ve.get ('/mgmt/tm/net/self-allow')
            services = res.json()['defaults']
            services.append ('udp:520')
            services.append ('tcp:443')
            res = f5ve.patch('/mgmt/tm/net/self-allow', {'defaults': services })
        except:
            print (hostname + ' : error')
        else:
            print(hostname + ' : Change done')
    f.close()
    

    