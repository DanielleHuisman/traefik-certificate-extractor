import sys
import os
import errno
import time
import json
import docker
import threading
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


def restartContainerWithDomains(domains):
    client = docker.from_env()
    container = client.containers.list(filters = {"label" : "com.github.DanielHuisman.traefik-certificate-extractor.restart_domain"})
    for c in container:
        restartDomains = str.split(c.labels["com.github.DanielHuisman.traefik-certificate-extractor.restart_domain"], ',')
        if not set(domains).isdisjoint(restartDomains):
            print('restarting container ' + c.id)
            if not args.dry:
                c.restart()


def createCerts(args):
    # Read JSON file
    data = json.loads(open(args.certificate).read())

    # Determine ACME version
    acme_version = 2 if 'acme-v02' in data['Account']['Registration']['uri'] else 1

    # Find certificates
    if acme_version == 1:
        certs = data['DomainsCertificate']['Certs']
    elif acme_version == 2:
        certs = data['Certificates']

    # Loop over all certificates
    names = []

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

        if (args.include and name not in args.include) or (args.exclude and name in args.exclude):
            continue

        # Decode private key, certificate and chain
        privatekey = b64decode(privatekey).decode('utf-8')
        fullchain = b64decode(fullchain).decode('utf-8')
        start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
        cert = fullchain[0:start]
        chain = fullchain[start:]

        if not args.dry:
            # Create domain     directory if it doesn't exist
            directory = Path(args.directory)
            if not directory.exists():
                directory.mkdir()

            if args.flat:
                # Write private key, certificate and chain to flat files
                with (directory / name + '.key').open('w') as f:
                    f.write(privatekey)
                with (directory / name + '.crt').open('w') as f:
                    f.write(fullchain)
                with (directory / name + '.chain.pem').open('w') as f:
                    f.write(chain)

                if sans:
                    for name in sans:
                        with (directory / name + '.key').open('w') as f:
                            f.write(privatekey)
                        with (directory / name + '.crt').open('w') as f:
                            f.write(fullchain)
                        with (directory / name + '.chain.pem').open('w') as f:
                            f.write(chain)
            else:
                directory = directory / name
                if not directory.exists():
                    directory.mkdir()

                # Write private key, certificate and chain to file
                with (directory / 'privkey.pem').open('w') as f:
                    f.write(privatekey)

                with (directory / 'cert.pem').open('w') as f:
                    f.write(cert)

                with (directory / 'chain.pem').open('w') as f:
                    f.write(chain)

                with (directory / 'fullchain.pem').open('w') as f:
                    f.write(fullchain)

        print('Extracted certificate for: ' + name +
              (', ' + ', '.join(sans) if sans else ''))
        names.append(name)
    return names


class Handler(FileSystemEventHandler):

    def __init__(self, args):
        self.args = args
        self.isWaiting = False
        self.timer = threading.Timer(0.5, self.doTheWork)
        self.lock = threading.Lock()

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        # Check if it's a JSON file
        print('DEBUG : event fired')
        if not event.is_directory and event.src_path.endswith(str(self.args.certificate)):
            print('Certificates changed')

            with self.lock:
                if not self.isWaiting:
                    self.isWaiting = True #trigger the work just once (multiple events get fired)
                    self.timer = threading.Timer(2, self.doTheWork)
                    self.timer.start()

    def doTheWork(self):
        print('DEBUG : starting the work')
        domains = createCerts(self.args)
        if (self.args.restart_container):
            restartContainerWithDomains(domains)

        with self.lock:
            self.isWaiting = False
        print('DEBUG : finished')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Extract traefik letsencrypt certificates.')
    parser.add_argument('-c', '--certificate', default='acme.json', type=PathType(
        exists=True), help='file that contains the traefik certificates (default acme.json)')
    parser.add_argument('-d', '--directory', default='.',
                        type=PathType(type='dir'), help='output folder')
    parser.add_argument('-f', '--flat', action='store_true',
                        help='outputs all certificates into one folder')
    parser.add_argument('-r', '--restart_container', action='store_true',
                        help="uses the docker API to restart containers that are labeled with 'com.github.DanielHuisman.traefik-certificate-extractor.restart_domain=<DOMAIN>' if the domain name of a generated certificates matches. Multiple domains can be seperated by ','")
    parser.add_argument('--dry-run', action='store_true', dest='dry',
                        help="Don't write files and do not start docker containers.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--include', nargs='*')
    group.add_argument('--exclude', nargs='*')

    args = parser.parse_args()

    print('DEBUG: watching path: ' + str(args.certificate))
    print('DEBUG: output path: ' + str(args.directory))

    # Create event handler and observer
    event_handler = Handler(args)
    observer = Observer()

    # Register the directory to watch
    observer.schedule(event_handler, str(Path(args.certificate).parent))

    # Main loop to watch the directory
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
