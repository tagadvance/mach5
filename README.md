# Mach 5

## Testing
```bash
curl --cacert mach5_root.pem --connect-to mach5.example.com:443:localhost:1443 https://mach5.example.com
openssl s_client -connect localhost:1443 </dev/null 2>/dev/null | openssl x509 -inform pem -text | less
```
