#!/usr/bin/env python3
# pylint: disable=C0301,R0913,R0914
""" gpg encrypt to autodecrypt shell/raw """
import sys
import argparse
from subprocess import run, PIPE, DEVNULL
from textwrap import dedent
from uuid import uuid4
try:
    from pwinput import pwinput
except ModuleNotFoundError:
    from getpass import getpass as pwinput

GPG = 'gpg --armor --quiet --no-default-keyring --no-options --batch --yes --cipher-algo AES256'

def crypt(data, password=None):
    """ crypt data """
    gpgenc = f'{GPG} -c'
    if password:
        gpgenc += f" --passphrase-fd 3 3<<<'{password}'"
    #print(gpgenc, file=sys.stderr)
    runsh = run(gpgenc, input=data, stdout=PIPE, shell=True,
                stderr=DEVNULL, encoding='utf-8', check=False, executable='/bin/bash')
    if runsh.returncode != 0:
        print('Error: Failed to encrypt', file=sys.stderr)
        return False
    return runsh.stdout

def decrypt(data, password=None):
    """ decrypt data """
    password = password or pwinput('🔐 Password: ')
    runsh = run(f"{GPG} -d --passphrase-fd 3 3<<<'{password}'", shell=True, input=data, stdout=PIPE,
                stderr=DEVNULL, encoding='utf-8', check=False, executable='/bin/bash')
    if runsh.returncode != 0:
        print('Error: Failed to decrypt', file=sys.stderr)
        return False
    return runsh.stdout

def sshsign(sshkey=None, signtext='constant_sign'):
    """ ssh signature using sshkey """
    sshkey = sshkey or '~/.ssh/id_rsa'
    sign = f"ssh-keygen -Y sign -f {sshkey} -n file - <<<'{signtext}'"
    #print(sign, file=sys.stderr)
    runsh = run(sign, stdout=PIPE,
                stderr=DEVNULL, encoding='utf-8', check=False, shell=True, executable='/bin/bash')
    if runsh.returncode != 0:
        print('Error: Failed to get ssh signature (openssl version ?)', file=sys.stderr)
        return False
    return ''.join([s for s in runsh.stdout.strip().split('\n') if '---' not in s])

def cryptas(data, mode='shellout', pwmode='passwd', passvar=None,
            varname=None, sshkey=None, password=None):
    """ crypt data to shell auto-decrypt """
    sshkey = sshkey or '~/.ssh/id_rsa'
    passvar = passvar or uuid4().hex
    sshkeyfind = f"$([ -f {sshkey} ] && echo '{sshkey}' || echo '<(ssh-add -L 2>/dev/null|head -n 1)')"
    signwithkey= f"eval ssh-keygen -Y sign -f {sshkeyfind} -n file - <<<'{passvar}' 2>/dev/null |awk '!/---/' ORS=''"
    if pwmode == 'sshsign':
        password = sshsign(sshkey, passvar)
    else:
        password = password or pwinput('🔐 Password: ')
    #print(password, file=sys.stderr)
    crypted = crypt(data, password)
    passvar = f'__{passvar}[$$]'
    bashpass = f''': ${{{passvar}:=$(bash -c 'read -s -p "🔐 Password: " p;echo >&2;base64 <<<"$p"')}}'''
    failmsg = "echo 'Error: Failed to decrypt' >&2"
    pwmodes = {
        'passwd': {'bashpass':'', 'gpgpass': '', 'unset': ':' },
        'pwcache': {
            'bashpass': bashpass,
            'gpgpass': f'--passphrase-file <(base64 -d <<<"${{{passvar}}}")',
            'unset': f'unset {passvar}',
        },
        'pwcache2': {
            'bashpass': bashpass,
            'gpgpass': f'--passphrase pass:$(base64 -d <<<"${{{passvar}}}")',
            'unset': f'unset {passvar}',
        },
        'sshsign': {
            'bashpass': '',
            'gpgpass': f"--passphrase-file <({signwithkey})",
            'unset': ':',
        }
    }
    pwm = pwmodes[pwmode]
    modes = {
        'shellenv': {
            'pregpg': '. <(',
            'postgpg': f" 2>/dev/null|grep -x '.*' || {{ {failmsg}; echo '{pwm['unset']};return 1'; }}",
            'postcrypt': ')',
        },
        'shellvar': {
            'pregpg': f'{varname}=$(',
            'postgpg': " 2>/dev/null|grep -x '.*'",
            'postcrypt': f") || {{ {failmsg};{pwm['unset']}; }}"
        },
        'shellout': {
            'pregpg': '',
            'postgpg': f" 2>/dev/null|grep -x '.*' || {{ {failmsg};{pwm['unset']}; }}",
            'postcrypt': ""
        }
    }
    mod = modes[mode]
    shell = dedent("""\
        {bashpass}
        {pregpg}{gpg} -d {gpgpass} <<<'{crypted}' {postgpg} 
        {postcrypt}
    """).format(gpg=GPG, crypted=crypted, **mod, **pwm)
    b64shell = run("base64", shell=True, input=shell, stdout=PIPE, stderr=DEVNULL, encoding='utf-8', check=False, executable='/bin/bash').stdout
    shell2 = f". <(base64 -d <<<'{b64shell}')"
    return shell2

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", default='shellenv', help="output mode",
                        choices=['raw', 'shellenv', 'shellvar', 'shellout'])
    parser.add_argument("-p", "--pwmode", default='pwcache', help="password mode",
                        choices=['password', 'pwcache', 'sshsign', 'pwcache2'])
    parser.add_argument("-v", "--var", required=False, help="variable name (shvar)")
    parser.add_argument("-k", "--key", required=False, help="sshkey to get signature password (sshsign)")
    parser.add_argument("-c", "--cachevar", required=False, help="password cache variable")
    parser.add_argument("-d", "--decrypt", default=False, action='store_true', help='decrypt raw')
    parser.add_argument("-i", "--interactive", default=False, action='store_true', help='Get secret from console (1 line only)')
    parser.add_argument("-P", "--passfile", help="file containing the password")
    args = parser.parse_args()

    if sys.stdin.isatty() and args.interactive :
        stdout = sys.stdout
        sys.stdout = sys.stderr
        indata = pwinput('🔐 Secret: ')
        sys.stdout = stdout
    else:
        indata = sys.stdin.read()

    if args.var:
        args.mode = 'shellvar'

    if args.passfile:
        with open(args.passfile, 'r') as f:
            password = f.read().strip()
    else:
        password = None

    if args.decrypt:
        if args.pwmode == 'sshsign':
            sys.stdout.write(decrypt(indata, sshsign(args.key)))
        else:
            sys.stdout.write(decrypt(indata))
        sys.exit(0)

    if args.mode == 'raw':
        if args.pwmode == 'sshsign':
            sys.stdout.write(crypt(indata, sshsign(args.key)))
        else:
            sys.stdout.write(crypt(indata))
        sys.exit(0)
    sys.stdout.write(cryptas(indata, args.mode, args.pwmode, args.cachevar, args.var, args.key, password))
