import sys
import os
import errno
import time
import json
#import docker
import argparse
from argparse import ArgumentTypeError as err
from base64 import b64decode
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path


class PathType(object):
    def __init__(self, exists=True, type='file', dash_ok=True):
        '''exists:
                True: a path that does exist
                False: a path that does not exist, in a valid parent directory
                None: don't care
           type: file, dir, symlink, None, or a function returning True for valid paths
                None: don't care
           dash_ok: whether to allow "-" as stdin/stdout'''

        assert exists in (True, False, None)
        assert type in ('file', 'dir', 'symlink',
                        None) or hasattr(type, '__call__')

        self._exists = exists
        self._type = type
        self._dash_ok = dash_ok

    def __call__(self, string):
        if string == '-':
            # the special argument "-" means sys.std{in,out}
            if self._type == 'dir':
                raise err(
                    'standard input/output (-) not allowed as directory path')
            elif self._type == 'symlink':
                raise err(
                    'standard input/output (-) not allowed as symlink path')
            elif not self._dash_ok:
                raise err('standard input/output (-) not allowed')
        else:
            e = os.path.exists(string)
            if self._exists == True:
                if not e:
                    raise err("path does not exist: '%s'" % string)

                if self._type is None:
                    pass
                elif self._type == 'file':
                    if not os.path.isfile(string):
                        raise err("path is not a file: '%s'" % string)
                elif self._type == 'symlink':
                    if not os.path.symlink(string):
                        raise err("path is not a symlink: '%s'" % string)
                elif self._type == 'dir':
                    if not os.path.isdir(string):
                        raise err("path is not a directory: '%s'" % string)
                elif not self._type(string):
                    raise err("path not valid: '%s'" % string)
            else:
                if self._exists == False and e:
                    raise err("path exists: '%s'" % string)

                p = os.path.dirname(os.path.normpath(string)) or '.'
                if not os.path.isdir(p):
                    raise err("parent path is not a directory: '%s'" % p)
                elif not os.path.exists(p):
                    raise err("parent directory does not exist: '%s'" % p)

        return string


def restartContainerWithDomain(domain):
    return
#    client = docker.from_env()
#    container = client.containers.list(filters = {"label" : "com.github.SnowMB.traefik-certificate-extractor.restart_domain"})
#    for c in container:
#        domains = str.split(c.labels["com.github.SnowMB.traefik-certificate-extractor.restart_domain"], ',')
#        if domain in domains:
#            print('restarting container ' + c.id)
#            c.restart()


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

        print('Extracted certificate for: ' + name +
              (', ' + ', '.join(sans) if sans else ''))
        restartContainerWithDomain(name)


class Handler(FileSystemEventHandler):

    def __init__(self, args):
        self.args = args

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        # Check if it's a JSON file
        print('DEBUG : event fired')
        if not event.is_directory and event.src_path.endswith(str(self.args.FILE)):
            print('Certificates changed')

            createCerts(event.src_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Extract traefik letsencrypt certificates.')
    parser.add_argument('FILE', nargs='?', default='acme.json', type=PathType(
        exists=True), help='file that contains the traefik certificates (default acme.json)')
    parser.add_argument('OUTPUT', nargs='?', default='.',
                        type=PathType(type='dir'), help='output folder')
    parser.add_argument('-f', '--flat', action='store_true',
                        help='outputs all certificates into one folder')
    args = parser.parse_args()

    print('DEBUG: watching path: ' + str(args.FILE))
    print('DEBUG: output path: ' + str(args.OUTPUT))

    # Create output directories if it doesn't exist
    try:
        os.makedirs(args.OUTPUT)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    # Create event handler and observer
    event_handler = Handler(args)
    observer = Observer()

    # Register the directory to watch
    observer.schedule(event_handler, str(args.FILE.parent))

    # Main loop to watch the directory
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
