import os
import subprocess
import sys

def generate_key_pair(directory, tag):
    # Generate private key
    private_key_path = os.path.join(directory, f'privkey-{tag}.pem')
    subprocess.run(['openssl', 'genrsa', '-out', private_key_path])

    # Generate public key from private key
    public_key_path = os.path.join(directory, f'pubkey-{tag}.pem')
    subprocess.run(['openssl', 'rsa', '-pubout', '-in', private_key_path, '-out', public_key_path])

    print(f'Key pair generated and saved in {directory}')
    print(f'Private key: {private_key_path}')
    print(f'Public key: {public_key_path}')

if __name__ == "__main__":
    if (len(sys.argv) != 3):
        exit

    generate_key_pair(sys.argv[1], sys.argv[2])