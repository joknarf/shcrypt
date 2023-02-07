#!/usr/bin/env python3
import os
import sys
from subprocess import run, PIPE, DEVNULL
from textwrap import dedent
from uuid import uuid4

ossl = 'openssl enc -aes256 -md sha512 -a'

def crypt(data, password=None):
    osslenc = f'{ossl} -salt'
    if password:
        osslenc += f" -pass fd:3 3<<<'{password}'"
    runsh = run(osslenc, input=data, stdout=PIPE, shell=True,
                stderr=DEVNULL, encoding='utf-8', check=False, executable='/bin/bash')
    if runsh.returncode != 0:
        print('Error: Failed to encrypt', file=sys.stderr)
        return False
    return runsh.stdout

def cryptas(data, mode='shellout', pwmode='passwd', password=None, passvar=None, varname=None, sshkey=None):
    sshkey = os.path.expanduser('~') + '/.ssh/id_rsa'
    passvar = passvar or uuid4().hex
    sshkeyfind = f"$([ -f '{sshkey}' ] && echo '{sshkey}' || echo '<(ssh-add -L 2>/dev/null|head -n 1)')"
    signwithkey= f"$(ssh-keygen -Y sign -f {sshkeyfind} -n file - <<<'{passvar}' 2>/dev/null |awk 'NR>1' ORS='')"
    if pwmode == 'sshsign':
        runsh = run(f"ssh-keygen -Y sign -f '{sshkey}' -n file - <<<'{passvar}'", stdout=PIPE, 
                    stderr=DEVNULL, encoding='utf-8', check=False, shell=True, executable='/bin/bash')
        if runsh.returncode != 0:
            print('Error: Failed to get ssh signature (openssl version ?)', file=sys.stder)
            return False
        password = ''.join(runsh.stdout.strip().split('\n')[1:])
        #print(password)

    crypted = crypt(data, password)
    passvar = f'__{passvar}[$$]'
    bashpass = f''': ${{{passvar}:=$(bash -c 'read -s -p "🔐 Password: " p;echo >&2;echo "$p"'|base64)}}'''
    failmsg = "echo 'Error: Failed to decrypt' >&2"
    pwmodes = {
        'passwd': {'bashpass':'', 'osslpass': '', 'unset': ':' },
        'cachepw': {
            'bashpass': bashpass, 
            'osslpass': f'-pass fd:3 3<<<$(base64 -d <<<"${{{passvar}}}")',
            'unset': f'unset {passvar}',
        },
        'cachepw2': {
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
    shell = dedent("""
        {bashpass}
        {preossl}{ossl} -d {osslpass} <<'EOZ' 2>/dev/null {postossl}
        {crypted}
        EOZ
        {postcrypt}
    """).format(ossl=ossl, crypted=crypted, **mod, **pwm)
    return shell


tocrypt = sys.stdin.read()
#print(crypt(tocrypt))
print(cryptas(tocrypt, 'shellenv', 'sshsign'))

