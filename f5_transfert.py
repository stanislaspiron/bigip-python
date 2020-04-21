import bigip
import os, requests, argparse, getpass, json

transfert_uri = {
    'upload': {
        'image': '/mgmt/cm/autodeploy/software-image-uploads/',
        'ucs': '/mgmt/shared/file-transfer/ucs-uploads/',
        'file': '/mgmt/shared/file-transfer/uploads/'
    },
    'download' :{
        'image': '/mgmt/cm/autodeploy/software-image-downloads/',
        'ucs': '/mgmt/shared/file-transfer/ucs-downloads/'
    }
}

if __name__ == "__main__":
    # Configure parsers
    parser = argparse.ArgumentParser(description='Transfer File from/to BIG-IP')
    parser.add_argument("mode", help='Select mode \'download\' or \'upload\'')
    parser.add_argument("host", help='BIG-IP IP or Hostname')
    parser.add_argument("username", help='BIG-IP Username')
    #parser.add_argument("password", help='BIG-IP Password')
    parser.add_argument("filepath", help='filename & path')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--image', action='store_true',
                       help='Select location as SW Image/MD5 file -- /shared/images/')
    group.add_argument('-u', '--ucs', action='store_true', help='Select location as UCS file -- /var/local/ucs/')
    group.add_argument('-g', '--general', action='store_true',
                       help='Select location as general stuff -- /var/config/rest/downloads/')
    args = vars(parser.parse_args())
    # Set variables
    mode = args['mode']
    hostname = args['host']
    username = args['username']
    print('Enter \'{}\' password: '.format(args['username']))
    password = getpass.getpass()
    #password = args['password']
    filepath = args['filepath']
    # set location parameter
    ext = os.path.splitext(filepath)[-1]
    if mode == 'download':
        if args['ucs'] or ext == '.ucs':
            type = 'ucs'
        # elif args['image'] or ext == '.iso' or ext == '.md5':
        else:
            type = 'image'
        if args['general']:
            print('Selector \'-g|--general\' is not valid with download mode.')
        else:
            try:
                f5ve = bigip.tmos(hostname, username, password)
            except Exception as e:
                print (e)
                exit()
            try:
                f5ve.download(transfert_uri[mode][type],filepath)
            except Exception as e:
                print (e)
                exit()
    elif mode == 'upload':
        if args['general']:
            type = 'file'
        elif args['ucs'] or ext == '.ucs':
            type = 'ucs'
        elif args['image'] or ext == '.iso' or ext == '.md5':
            type = 'image'
        else:
            type = 'file'
        try:
            f5ve = bigip.tmos(hostname, username, password)
        except Exception as e:
            print (e)
            exit()
        try:
            f5ve.upload(transfert_uri[mode][type], filepath)
        except Exception as e:
                print (e)
                exit()
    else:
        print('Transfer mode not supported.')