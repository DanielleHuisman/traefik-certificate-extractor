import sys
import os
import errno
import time
import json
from base64 import b64decode
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class Handler(FileSystemEventHandler):
    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        # Check if it's a JSON file
        if not event.is_directory and event.src_path.endswith('.json'):
            print('Certificates changed')

            # Read JSON file
            data = json.loads(open(event.src_path).read())
            certs = data['DomainsCertificate']['Certs']

            # Loop over all certificates
            for c in certs:
                # Decode private key, certificate and chain
                privatekey = b64decode(c['Certificate']['PrivateKey']).decode('utf-8')
                fullchain = b64decode(c['Certificate']['Certificate']).decode('utf-8')
                start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
                cert = fullchain[0:start]
                chain = fullchain[start:]

                # Create domain directory if it doesn't exist
                directory = 'certs/' + c['Certificate']['Domain'] + '/'
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

                with open(directory + c['Certificate']['Domain'] + '.key', 'w') as f:
                    f.write(privatekey)
                with open(directory + c['Certificate']['Domain'] + '.crt', 'w') as f:
                    f.write(fullchain)
                with open(directory + c['Certificate']['Domain'] + '.chain.pem', 'w') as f:
                    f.write(chain)

                if c['Domains']['SANs']:
                    for name in c['Domains']['SANs']:
                        with open(directory + name + '.key', 'w') as f:
                            f.write(privatekey)
                        with open(directory + name + '.crt', 'w') as f:
                            f.write(fullchain)
                        with open(directory + name + '.chain.pem', 'w') as f:
                            f.write(chain)

                print('Extracted certificate for: ' + c['Domains']['Main'] + (', ' + ', '.join(c['Domains']['SANs']) if c['Domains']['SANs'] else ''))

if __name__ == "__main__":
    # Determine path to watch
    path = sys.argv[1] if len(sys.argv) > 1 else './data'

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
    event_handler = Handler()
    observer = Observer()

    # Register the directory to watch
    observer.schedule(event_handler, path)

    # Main loop to watch the directory
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
