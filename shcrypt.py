#!/usr/bin/env python3
# pylint: disable=C0301,R0913,R0914
""" openssl encrypt to autodecrypt shell/raw """
import os
import sys
import argparse
from subprocess import run, PIPE, DEVNULL
from textwrap import dedent
from uuid import uuid4
from getpass import getpass

OSSL = 'openssl enc -aes256 -md sha512 -a'

def crypt(data, password=None):
    """ crypt data """
    osslenc = f'{OSSL} -salt'
    if password:
        osslenc += f" -pass fd:3 3<<<'{password}'"
    runsh = run(osslenc, input=data, stdout=PIPE, shell=True,
                stderr=DEVNULL, encoding='utf-8', check=False, executable='/bin/bash')
    if runsh.returncode != 0:
        print('Error: Failed to encrypt', file=sys.stderr)
        return False
    return runsh.stdout

def decrypt(data, password=None):
    """ decrypt data """
    password = password or getpass('🔐 Password: ')
    runsh = run(f"{OSSL} -d -pass fd:3 3<<<'{password}'", shell=True, input=data, stdout=PIPE,
                stderr=DEVNULL, encoding='utf-8', check=False, executable='/bin/bash')
    if runsh.returncode != 0:
        print('Error: Failed to decrypt', file=sys.stderr)
        return False
    return runsh.stdout

def sshsign(sshkey=None, signtext='constant_sign'):
    """ ssh signature using sshkey """
    sshkey = sshkey or os.path.expanduser('~') + '/.ssh/id_rsa'
    runsh = run(f"ssh-keygen -Y sign -f '{sshkey}' -n file - <<<'{signtext}'", stdout=PIPE,
                stderr=DEVNULL, encoding='utf-8', check=False, shell=True, executable='/bin/bash')
    if runsh.returncode != 0:
        print('Error: Failed to get ssh signature (openssl version ?)', file=sys.stderr)
        return False
    return ''.join(runsh.stdout.strip().split('\n')[1:])

def cryptas(data, mode='shellout', pwmode='passwd', passvar=None,
            varname=None, sshkey=None, password=None):
    """ crypt data to shell auto-decrypt """
    sshkey = sshkey or os.path.expanduser('~') + '/.ssh/id_rsa'
    passvar = passvar or uuid4().hex
    sshkeyfind = f"$([ -f '{sshkey}' ] && echo '{sshkey}' || echo '<(ssh-add -L 2>/dev/null|head -n 1)')"
    signwithkey= f"$(ssh-keygen -Y sign -f {sshkeyfind} -n file - <<<'{passvar}' 2>/dev/null |awk 'NR>1' ORS='')"
    if pwmode == 'sshsign':
        password = sshsign(sshkey, passvar)
    crypted = crypt(data, password)
    passvar = f'__{passvar}[$$]'
    bashpass = f''': ${{{passvar}:=$(bash -c 'read -s -p "🔐 Password: " p;echo >&2;echo "$p"'|base64)}}'''
    failmsg = "echo 'Error: Failed to decrypt' >&2"
    pwmodes = {
        'passwd': {'bashpass':'', 'osslpass': '', 'unset': ':' },
        'pwcache': {
            'bashpass': bashpass,
            'osslpass': f'-pass fd:3 3<<<$(base64 -d <<<"${{{passvar}}}")',
            'unset': f'unset {passvar}',
        },
        'pwcache2': {
            'bashpass': bashpass,
            'osslpass': f'-pass pass:$(base64 -d <<<"${{{passvar}}}")',
            'unset': f'unset {passvar}',
        },
        'sshsign': {
            'bashpass': '',
            'osslpass': f"-pass fd:3 3<<<{signwithkey}",
            'unset': ':',
        }
    }
    pwm = pwmodes[pwmode]
    modes = {
        'shellenv': {
            'preossl': '. <(',
            'postossl': f"|grep -x '.*' || {{ {failmsg}; echo '{pwm['unset']};return 1'; }}",
            'postcrypt': ')',
        },
        'shellvar': {
            'preossl': f'{varname}=$(',
            'postossl': "|grep -x '.*'",
            'postcrypt': f") || {{ {failmsg};{pwm['unset']}; }}"
        },
        'shellout': {
            'preossl': '',
            'postossl': f"|grep -x '.*' || {{ {failmsg};{pwm['unset']}; }}",
            'postcrypt': ""
        }
    }
    mod = modes[mode]
    shell = dedent("""\
        {bashpass}
        {preossl}{ossl} -d {osslpass} <<'EOZ' 2>/dev/null {postossl}
        {crypted}
        EOZ
        {postcrypt}
    """).format(ossl=OSSL, crypted=crypted, **mod, **pwm)
    return shell


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
    parser.add_argument("-i", "--interactive", default=False, action='store_true', help='Get secret from console')
    args = parser.parse_args()

    if sys.stdin.isatty() and args.var :
        indata = getpass('🔐 Secret: ')
    else:
        indata = sys.stdin.read()

    if args.var:
        args.mode = 'shellvar'

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
    sys.stdout.write(cryptas(indata, args.mode, args.pwmode, args.cachevar, args.var, args.key))
