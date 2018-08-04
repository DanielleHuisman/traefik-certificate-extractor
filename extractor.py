import sys
import os
import errno
import time
import json
import docker

from base64 import b64decode
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path


def restartContainerWithDomain(domain):
    client = docker.from_env()
    container = client.containers.list(filters = {"label" : "com.github.SnowMB.traefik-certificate-extractor.restart_domain"})
    for c in container:
#        print(c.labels['com.github.SnowMB.traefik-certificate-extractor.restart_domain'])
        domains = str.split(c.labels["com.github.SnowMB.traefik-certificate-extractor.restart_domain"], ',')
        if domain in domains:
            print('restarting container ' + c.id)
            c.restart()



def createCerts(file):
    # Read JSON file
    data = json.loads(open(file).read())

    # Determine ACME version
    acme_version = 2 if 'acme-v02' in data['Account']['Registration']['uri'] else 1

    # Find certificates
    if acme_version == 1:
        certs = data['DomainsCertificate']['Certs']
    elif acme_version == 2:
        certs = data['Certificates']

    # Loop over all certificates
    for c in certs:
        if acme_version == 1:
            name = c['Certificate']['Domain']
            privatekey = c['Certificate']['PrivateKey']
            fullchain = c['Certificate']['Certificate']
            sans = c['Domains']['SANs']
        elif acme_version == 2:
            name = c['Domain']['Main']
            privatekey = c['Key']
            fullchain = c['Certificate']
            sans = c['Domain']['SANs']

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
        restartContainerWithDomain(name)




class Handler(FileSystemEventHandler):

    def __init__(self):
        self.filename = 'acme.json'

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        # Check if it's a JSON file
        print ('DEBUG : event fired')
        if not event.is_directory and event.src_path.endswith(self.filename):
            print('Certificates changed')

            createCerts(event.src_path)


if __name__ == "__main__":
    # Determine path to watch
    val = sys.argv[1] if len(sys.argv) > 1 else './data/acme.json'

    path = Path(val)

    if not path.exists() or path.is_dir():
        print ('ERROR ' + str(path) + ' does not exist.')
        sys.exit(1)

    print('watching path: ' + str(path))

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
    event_handler.filename = str(path.name)
    observer = Observer()

    # Register the directory to watch
    observer.schedule(event_handler, str(path.parent))

    # Main loop to watch the directory
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
