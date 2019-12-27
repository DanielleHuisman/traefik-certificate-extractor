import sys
import os
import errno
import time
import json
import glob
import argparse
from base64 import b64decode
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class Handler(FileSystemEventHandler):
    def __init__(self, args):
        self.traefik_version = args.traefikVersion
        self.challenge = args.challenge

    def on_created(self, event):
        self.handle_event(event)

    def on_modified(self, event):
        self.handle_event(event)

    def handle_event(self, event):
        # Check if it's a JSON file
        if not event.is_directory and event.src_path.endswith('.json'):
            print('Certificate storage changed (' + os.path.basename(event.src_path) + ')')
            self.handle_file(event.src_path)

    def handle_file(self, file):        
        try:
            self.extract_certs(file)
        except Exception as error:
            print('Error while handling file ' + file + ': ' + repr(error))

    def extract_certs(self, file):
        # Read JSON file
        data = json.loads(open(file).read())
        
        # Determine challenge
        if self.traefik_version == 2:
            if self.challenge:
                challengeData = data[self.challenge]
            elif len(list(data.keys())) == 1:
                self.challenge = list(data.keys())[0]
                print('Using challenge: ' + self.challenge)
                challengeData =  data[self.challenge]
            else:
                print('Available challenges: ' + (', '.join([str(x) for x in list(data.keys())])))
                raise ValueError('Multiple challenges found, please choose one with --challenge option')
        else:
            challengeData = data
            
        # Determine ACME version
        try:
            acme_version = 2 if 'acme-v02' in challengeData['Account']['Registration']['uri'] else 1
        except TypeError:
            if 'DomainsCertificate' in challengeData:
                acme_version = 1
            else:
                acme_version = 2

        # Find certificates
        if acme_version == 1:
            certs = challengeData['DomainsCertificate']['Certs']
        elif acme_version == 2:
            certs = challengeData['Certificates']

        print('Certificate storage contains ' + str(len(certs)) + ' certificates')

        # Loop over all certificates
        for c in certs:
            if acme_version == 1:
                name = c['Certificate']['Domain']
                privatekey = c['Certificate']['PrivateKey']
                fullchain = c['Certificate']['Certificate']
                sans = c['Domains']['SANs']
            elif acme_version == 2 and self.traefik_version == 1:
                name = c['Domain']['Main']
                privatekey = c['Key']
                fullchain = c['Certificate']
                sans = c['Domain']['SANs']
            elif acme_version == 2 and self.traefik_version == 2:
                name = c['domain']['main']
                privatekey = c['key']
                fullchain = c['certificate']
                sans = c['domain'].get('sans')

            # Decode private key, certificate and chain
            privatekey = b64decode(privatekey).decode('utf-8')
            fullchain = b64decode(fullchain).decode('utf-8')
            start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
            cert = fullchain[0:start]
            chain = fullchain[start:]

            # Create domain directory if it doesn't exist
            directory = 'certs/' + name + '/'
            try:
                os.makedirs(directory)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise

            # Write private key, certificate and chain to file
            with open(directory + 'privkey.pem', 'w') as f:
                f.write(privatekey)

            with open(directory + 'cert.pem', 'w') as f:
                f.write(cert)

            with open(directory + 'chain.pem', 'w') as f:
                f.write(chain)

            with open(directory + 'fullchain.pem', 'w') as f:
                f.write(fullchain)

            # Write private key, certificate and chain to flat files
            directory = 'certs_flat/'

            with open(directory + name + '.key', 'w') as f:
                f.write(privatekey)
            with open(directory + name + '.crt', 'w') as f:
                f.write(fullchain)
            with open(directory + name + '.chain.pem', 'w') as f:
                f.write(chain)

            if sans:
                for name in sans:
                    with open(directory + name + '.key', 'w') as f:
                        f.write(privatekey)
                    with open(directory + name + '.crt', 'w') as f:
                        f.write(fullchain)
                    with open(directory + name + '.chain.pem', 'w') as f:
                        f.write(chain)

            print('Extracted certificate for: ' + name + (', ' + ', '.join(sans) if sans else ''))

if __name__ == "__main__":
    # Determine args
    parser = argparse.ArgumentParser(description='Traefik certificate extractor')
    parser.add_argument('path', nargs='?', default='./data', help='Path to traefik acme file')
    parser.add_argument('-tv', '--traefikVersion', type=int, choices=[1, 2], default=1, help='Traefik version')
    parser.add_argument('-c', '--challenge', help='Traefik challenge to use (only for traefik v2)')

    args = parser.parse_args()

    print('Path: ' + args.path)
    print('Traefik version: ' + str(args.traefikVersion))

    if args.traefikVersion >= 2 and args.challenge:
        print('Traefik challenge: ' + args.challenge)

    # Create output directories if it doesn't exist
    try:
        os.makedirs('certs')
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise
    try:
        os.makedirs('certs_flat')
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    # Create event handler and observer
    event_handler = Handler(args)
    observer = Observer()

    # Extract certificates from current file(s) before watching
    files = glob.glob(os.path.join(args.path, '*.json'))
    for file in files:
        print('Certificate storage found (' + os.path.basename(file) + ')')
        event_handler.handle_file(file)

    # Register the directory to watch
    observer.schedule(event_handler, args.path)

    # Main loop to watch the directory
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
