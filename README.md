# Traefik Certificate Extractor

Tool to extract Let's Encrypt certificates from Traefik's ACME storage file.

## Installation
```
git clone https://github.com/DanielHuisman/traefik-certificate-extractor
```

## Usage
```
python3 extractor.py [directory]
```
Default directory is `./data`. The output directory is `./certs`.

## Output
```
certs/
    example.com/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
    sub.example.nl/
        cert.pem
        chain.pem
        fullchain.pem
        privkey.pem
```
