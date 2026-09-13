#!/usr/bin/env bash
# gpg encrypt to autodecrypt shell/raw
# Bash translation of the original python3 script.
#
# Notes on fidelity to the original:
#  - Same limitations apply: passwords containing single quotes will
#    break the embedded heredocs, exactly as in the python version.
#  - Command substitution in bash strips trailing newlines from stdin,
#    unlike python's sys.stdin.read(); this is an unavoidable minor
#    difference from a pure-bash translation.

set -o pipefail

GPG=(gpg --armor --quiet --no-default-keyring --no-options --batch --yes --cipher-algo AES256 --no-symkey-cache)

# --- helpers ---------------------------------------------------------------

pwinput() {
    # pwinput <prompt>  -> prints entered secret (1 line) to stdout
    local prompt="$1"
    local pass
    read -r -s -p "$prompt" pass 1>&2
    echo >&2
    printf '%s' "$pass"
}

uuid_hex() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr -d '-' | tr 'A-Z' 'a-z'
    elif [[ -r /proc/sys/kernel/random/uuid ]]; then
        tr -d '-' < /proc/sys/kernel/random/uuid
    else
        printf '%08x%08x%08x%08x' "$RANDOM$RANDOM" "$RANDOM$RANDOM" "$RANDOM$RANDOM" "$RANDOM$RANDOM"
    fi
}

# --- core crypto functions ---------------------------------------------------

crypt() {
    # crypt <data> [password]  -> prints ciphertext to stdout, returns 1 on failure
    local data="$1" password="${2:-$(pwinput '🔐 Password: ')}"
    local gpgenc=("${GPG[@]}" -c --passphrase-fd 3)
    
    local out rc
    out=$("${gpgenc[@]}" 3<<<"$password" <<<"$data" 2>/dev/null)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo 'Error: Failed to encrypt' >&2
        return 1
    fi
    printf '%s' "$out"
}

decrypt() {
    # decrypt <data> [password]  -> prints plaintext to stdout, returns 1 on failure
    local data="$1" password="${2:-$(pwinput '🔐 Password: ')}"
    local out rc
    out=$("${GPG[@]}" -d --passphrase-fd 3 3<<<"$password" <<<"$data" 2>/dev/null)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo 'Error: Failed to decrypt' >&2
        return 1
    fi
    printf '%s' "$out"
}

sshsign() {
    # sshsign [sshkey] [signtext]  -> prints signature (newlines stripped), returns 1 on failure
    local sshkey="$1"
    local signtext="$2"
    local out rc
    out=$(eval ssh-keygen -Y sign -f "$sshkey" -n file - <<<"$signtext" 2>/dev/null)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo 'Error: Failed to get ssh signature (openssl version ?)' >&2
        return 1
    fi
    printf '%s' "$out" | grep -v -- '---' | tr -d '\n'
}

cryptas() {
    # cryptas <data> [mode] [pwmode] [passvar] [varname] [sshkey] [password]
    # -> prints a self-decrypting shell snippet (base64-wrapped) to stdout
    local data="$1"
    local mode="${2:-shellout}"
    local pwmode="${3:-passwd}"
    local passvar="$4"
    local varname="$5"
    local sshkey="$6"
    local password="$7"

    sshkey="${sshkey:-~/.ssh/id_rsa}"

    local sshkeyfind="\$([ -f $sshkey ] && echo '$sshkey' || echo '<(ssh-add -L 2>/dev/null|head -n 1)')"
    local signwithkey="eval ssh-keygen -Y sign -f $sshkeyfind -n file - <<<'$passvar' 2>/dev/null |awk '!/---/' ORS=''"

    local crypted
    crypted=$(crypt "$data" "$password") || return 1

    passvar="__${passvar}[\$\$]"
    local bashpass=": \${${passvar}:=\$(bash -c 'read -s -p \"🔐 Password: \" p;echo >&2;base64 <<<\"\$p\"')}"
    local failmsg="echo 'Error: Failed to decrypt' >&2"

    local pwm_bashpass pwm_gpgpass pwm_unset
    case "$pwmode" in
        passwd)
            pwm_bashpass=''
            pwm_gpgpass=''
            pwm_unset=':'
            ;;
        pwcache)
            pwm_bashpass="$bashpass"
            pwm_gpgpass="--passphrase-file <(base64 -d <<<\"\${${passvar}}\")"
            pwm_unset="unset ${passvar}"
            ;;
        pwcache2)
            pwm_bashpass="$bashpass"
            pwm_gpgpass="--passphrase pass:\$(base64 -d <<<\"\${${passvar}}\")"
            pwm_unset="unset ${passvar}"
            ;;
        sshsign)
            pwm_bashpass=''
            pwm_gpgpass="--passphrase-file <($signwithkey)"
            pwm_unset=':'
            ;;
        *)
            echo "Error: unknown pwmode '$pwmode'" >&2
            return 1
            ;;
    esac

    local pregpg postgpg postcrypt
    case "$mode" in
        shellenv)
            pregpg='. <('
            postgpg=" 2>/dev/null || { $failmsg; echo '${pwm_unset};return 1'; }"
            postcrypt=')'
            ;;
        shellvar)
            pregpg="${varname}=\$("
            postgpg=" 2>/dev/null"
            postcrypt=") || { $failmsg;${pwm_unset}; }"
            ;;
        shellout)
            pregpg=''
            postgpg=" 2>/dev/null || { $failmsg;${pwm_unset}; }"
            postcrypt=''
            ;;
        *)
            echo "Error: unknown mode '$mode'" >&2
            return 1
            ;;
    esac

    local shell
    shell=$(cat <<EOF
${pwm_bashpass}
${pregpg}${GPG[@]} -d ${pwm_gpgpass} <<<'${crypted}' ${postgpg} 
${postcrypt}
EOF
)

    local b64shell
    b64shell=$(base64 <<<"$shell" | tr -d '\n')
    printf ". <(base64 -d <<<'%s')" "$b64shell"
}

# --- argument parsing --------------------------------------------------------

usage() {
    cat >&2 <<EOF
Usage: $0 [-m mode] [-p pwmode] [-v var] [-k key] [-c cachevar]
          [-d] [-i] [-P passfile]

  -m, --mode      raw|shellenv|shellvar|shellout   (default: shellenv)
  -p, --pwmode    passwd|pwcache|sshsign|pwcache2 (default: pwcache)
  -v, --var       variable name (implies mode=shellvar)
  -k, --key       ssh key for sshsign
  -c, --cachevar  password cache variable name
  -d, --decrypt   decrypt raw input instead of encrypting
  -i, --interactive  read secret interactively (single line) instead of stdin
  -P, --passfile  file containing the password
EOF
    exit 1
}

mode='shellenv'
pwmode='pwcache'
varname=''
sshkey='~/.ssh/id_rsa'
cachevar=''
decrypt_flag=false
interactive_flag=false
passfile=''

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--mode) mode="$2"; shift 2;;
        -p|--pwmode) pwmode="$2"; shift 2;;
        -v|--var) varname="$2"; shift 2;;
        -k|--key) sshkey="$2"; shift 2;;
        -c|--cachevar) cachevar="$2"; shift 2;;
        -d|--decrypt) decrypt_flag=true; shift;;
        -i|--interactive) interactive_flag=true; shift;;
        -P|--passfile) passfile="$2"; shift 2;;
        -h|--help) usage;;
        *) echo "Unknown option: $1" >&2; usage;;
    esac
done

case "$mode" in
    raw|shellenv|shellvar|shellout) ;;
    *) echo "Error: invalid mode '$mode'" >&2; exit 1;;
esac
case "$pwmode" in
    passwd|pwcache|sshsign|pwcache2) ;;
    *) echo "Error: invalid pwmode '$pwmode'" >&2; exit 1;;
esac

if [[ -t 0 && "$interactive_flag" == true ]]; then
    indata=$(pwinput '🔐 Secret: ')
else
    indata=$(cat)
    exec </dev/tty
fi

if [[ -n "$varname" ]]; then
    mode='shellvar'
fi

password=''
if [[ -n "$passfile" ]]; then
    password=$(<"$passfile")
elif [[ "$pwmode" == "sshsign" ]]; then
    : ${cachevar:=$(uuid_hex)}
    password=$(sshsign "$sshkey" "$cachevar") || exit 1
fi

if $decrypt_flag; then
    decrypt "$indata" "$password"
    exit $?
fi

if [[ "$mode" == "raw" ]]; then
    crypt "$indata" "$password"
    exit $?
fi

cryptas "$indata" "$mode" "$pwmode" "$cachevar" "$varname" "$sshkey" "$password"
