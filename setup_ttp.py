import subprocess
import os
import sys
import shutil

CN = '/CN=ca\.self\.com/'
ttpkeys = 'ttpkeys'
clientkeys = 'clientkeys'
serverkeys = 'serverkeys'

def create_ca():
    # Generate CA key
    ca_key_path = os.path.join(ttpkeys, 'ca-key.pem')
    subprocess.run(['openssl', 'genrsa', '-out', ca_key_path])

    ca_cert_path = os.path.join(ttpkeys, 'ca-cert.pem')
    subprocess.run(['openssl', 'req', '-new', '-x509', '-key', ca_key_path,
                    '-out', ca_cert_path, '-nodes', '-subj', CN])
    

    shutil.copy(ca_cert_path, os.path.join(clientkeys, 'ca-cert.pem'))
    shutil.copy(ca_cert_path, os.path.join(serverkeys, 'ca-cert.pem'))

    print(f'CA created with key {ca_key_path} and cert {ca_cert_path}')

def create_server_cert(key_path, ca_cert, ca_key):

    csr_path = os.path.join(serverkeys, 'server-ca-csr.pem')
    cert_path = os.path.join(serverkeys, 'server-ca-cert.pem')

    cmd = f"openssl req -new -key {key_path} -out {csr_path} -nodes -subj {CN}".split(" ")
    subprocess.run(cmd)
    cmd = f"openssl x509 -req -CA {ca_cert} -CAkey {ca_key} -CAcreateserial -in {csr_path} -out {cert_path}".split(" ")
    subprocess.run(cmd)

if __name__ == '__main__':
    if (sys.argv[1] == 'create_server_cert' and len(sys.argv) == 5):
        create_server_cert(*(sys.argv[2:5]))
    elif (sys.argv[1] == 'create_ca' and len(sys.argv) == 2):
        create_ca()
    else:
        print("Unknown arguments")