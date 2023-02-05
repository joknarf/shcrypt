# shcrypt
openssl encrypt shell/text protected by password to autodecrypt shell

`shcrypt` is a small utility to store secrets in shell environment file, that can be sourced providing a password.  
Prevent having clear password stored in files, without complicated gpg / vault ... configurations and dependencies.  
The file generated can be taken and used easily everywhere, only the password is needed.  
When sourcing the generated file, it will prompt for password to decrypt and source it.  
Most often to use in interactive mode, to set for example, account_id, client_id, client_secret to use to call APIs.

`shcrypt` can also cache the password in shell session local variable, when needed to switch often variables from one value to another
(change client_id)

The generated files are shell, and can be modified to add other variables not encrypted, and so on.  
The generated files acts like auto-decrypt with password

## usage
>    shell content encrypt : `shcrypt -s[cu] <file|-> [<passvar>]`  
>    shell variable encrypt  : `shcrypt -v[cu] <varname> [<passvar>]`  
>    text/any encrypt : `shcrypt -t[cu] <file|-> [<passvar>]`  

The secrets can be loaded from stdin

* Encrypt to a sourceable shell code protected by password:  
      `$ shcrypt -s <<<'myvar="mysecret"' >config.env`

* Encrypt to a sourceable shell with variable content protected by password:  
      `$ shcrypt -v myvar <<<'mysecret' >config.env`  
      if no stdin value, the secret to store will be asked without echoing

* Encrypt to a shell that will output the content when sourced/executed:  
      `$ shcrypt -t <<<'mysecret' >mysecret.sh`
    
* `-(s|v|t)` : password required each time sourcing shell
* `-(sc|vc|tc)` : (`c` for cache password)  
            the password is cached in shell local variable `<passvar>`  
            the password is securely passed to openssl through fd  
* `-(scu|vcu|tcu)` : (`u` for unsafe)  
            the password is cached in shell local variable `<passvar>`  
            the password is passed to openssl through `-pass pass:<pass>`  
            /!\ the password will appear in process table when decrypting  

* `<passvar>` : name of the variable to put cached password  
            the password will be cached base64 encoded in `$passvar[$$]`  
            needed if want to share same password/cache for multiple env files  
            default: uuid based varname  

## Examples:

### crypt whole shell to be sourced

* crypt shell file
    ```
    config.env:
    myvar=mysecret
    myvar2=mysecret2
    ...
    ```
    ```
    $ shcrypt -s ./config.env >./secret.env
    enter AES-256-CBC encryption password:
    Verifying - enter AES-256-CBC encryption password:
    ```
* decrypt and source in current shell:
    ```
    $ . ./secret.env
    enter AES-256-CBC decryption password: 
    $ echo $myvar
    mysecret
    ```
* Look at the file generated (`secret.env`):
    ```
    eval $(openssl enc -aes256 -md sha512 -a -d <<EOZ 2>/dev/null|grep -x '.*'
    U2FsdGVkX1+ZauSKeakM4+Mci2U/w3PWw3wVU8Xrf3UeYVv8jjVUsAcRPQTFRwPR
    EOZ
    ) ||{ echo 'ERROR: Decrypt failed'; }  
    ```
    The file includes the openssl command needed to decrypt the shell env file, and `eval` its content  
    An error messsage will be displayed if decryption failed (wrong password)  
    You can of course add/customize shell inside this file.  

### crypt a shell variable to be sourced

we'll be using password cache this time

* crypt single variable to env file
    need to store the secret `mysecret` into myvar
    ```
    $ shcrypt -vc myvar >myvar.env
    Secret value: <not echoing input value>
    enter AES-256-CBC encryption password:
    Verifying - enter AES-256-CBC encryption password:
    ```
* decrypt and source single variable:
    ```
    $ . ./myvar.env
    🔐Password: 
    $ echo $myvar
    mysecret
    ```

* Look at the file generated:
    ```
    : ${__edbb11c1188d457ab07efa555646aebe[$$]:=$(bash -c 'read -s -p "🔐Password: " p;echo >&2;echo "$p"'|base64)}
    myvar=$(openssl enc -aes256 -md sha512 -a -d -pass fd:3 <<EOZ 3<<<$(base64 -d <<<"${__edbb11c1188d457ab07efa555646aebe[$$]}") 2>/dev/null|grep -x '.*'
    U2FsdGVkX18dWr6IiYksXJv31qLGmqBrtVKZW8UE4Fc=
    EOZ
    ) ||{ echo 'ERROR: Decrypt failed';unset __edbb11c1188d457ab07efa555646aebe[$$]; }
    ```
    ok, now with cache enable, little more code.  
    get the password from local variable if available else ask for password. (force bash as ksh does not have read -s)  
    the password is stored base64 encoded, to prevent accidentaly display directly clear password in your console.  
    decrypt the secret and assign to `myvar`

### crypt any file content 

* crypt any file content (not necessarily shell):
    ```
    $ shcrypt -tc <<<'my secret text' >secret.sh
    enter AES-256-CBC encryption password:
    Verifying - enter AES-256-CBC encryption password:
    ```
* decrypt file and display secret content:
    ```
    $ . ./secret.sh
    🔐Password: 
    my secret text
    ```

## Reminders

* Shell exported variables can be seen easily by root using a simple ps command  
    use local shell variable when possible, and pass them as fd
* Clear password on command lines appears in process table and could be intercepted when the process is launched
* Password protection can be brute forced, set correct permissions on the generated files (`chmod go-r`)
* secrets typed on interactive command line goes to your shell history file

`shcrypt` uses local shell variable for password cache.  
`shcrypt` does not put clear password on command lines executed (except for unsafe cache mode)  
