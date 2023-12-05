import subprocess
import os
import sys
import shutil

CN = '/CN=ca\.self\.com/'
ttpkeys = 'ttpkeys'
clientkeys = 'clientkeys'
serverkeys = 'serverkeys'

ca_privkey_path = os.path.join(ttpkeys, 'ca-privkey.pem')
ca_pubkey_path = os.path.join(ttpkeys, 'ca-pubkey.pem')
ca_cert_path = os.path.join(ttpkeys, 'ca-cert.pem')
def create_ca():
    # Generate CA key
    subprocess.run(['openssl', 'genrsa', '-out', ca_privkey_path])
    subprocess.run(['openssl', 'rsa', '-pubout', '-in', ca_privkey_path, '-out', ca_pubkey_path])

    subprocess.run(['openssl', 'req', '-new', '-x509', '-key', ca_privkey_path,
                    '-out', ca_cert_path, '-nodes', '-subj', CN])
    

    shutil.copy2(ca_cert_path, os.path.join(clientkeys, 'ca-cert.pem'))
    shutil.copy2(ca_cert_path, os.path.join(serverkeys, 'ca-cert.pem'))

    print(f'CA created with key {ca_privkey_path} and cert {ca_cert_path}')

def create_server_cert(key_path):

    csr_path = os.path.join(serverkeys, 'server-ca-csr.pem')    
    cert_path = os.path.join(serverkeys, 'server-ca-cert.pem')
    server_cn = '/CN=server\.self\.com'

    cmd = ["openssl", "req", "-new", "-key", key_path, "-out", csr_path, "-nodes", "-subj", server_cn]
    subprocess.run(cmd)
    cmd = ["openssl", "x509", "-req", "-CA", ca_cert_path, "-CAkey", ca_privkey_path, "-CAcreateserial", "-in", csr_path, "-out", cert_path]
    subprocess.run(cmd)

if __name__ == '__main__':
    if (sys.argv[1] == 'create_server_cert' and len(sys.argv) == 3):
        create_server_cert(sys.argv[2])
    elif (sys.argv[1] == 'create_ca' and len(sys.argv) == 2):
        create_ca()
    else:
        print("Unknown arguments")