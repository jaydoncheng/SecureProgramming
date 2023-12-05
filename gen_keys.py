import os
import subprocess
import argparse

def generate_key_pair(output_directory):
    # Ensure the output directory exists
    os.makedirs(output_directory, exist_ok=True)

    # Generate private key
    private_key_path = os.path.join(output_directory, 'privkey.pem')
    subprocess.run(['openssl', 'genrsa', '-out', private_key_path])

    # Generate public key from private key
    public_key_path = os.path.join(output_directory, 'pubkey.pem')
    subprocess.run(['openssl', 'rsa', '-pubout', '-in', private_key_path, '-out', public_key_path])

    print(f'Key pair generated and saved in {output_directory}')
    print(f'Private key: {private_key_path}')
    print(f'Public key: {public_key_path}')

def main():
    parser = argparse.ArgumentParser(description='Generate OpenSSL private-public key pair')
    parser.add_argument('output_directory', help='Directory to store the generated keys')

    args = parser.parse_args()
    generate_key_pair(args.output_directory)

if __name__ == "__main__":
    main()