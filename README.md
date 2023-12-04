# singo

### Create Keys .pem

```
openssl ecparam -name prime256v1 -genkey -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
```

### Transform in base64

```
cat private.pem | base64 > private.base64
cat public.pem | base64 > public.base64
```

Create and Verify signature cryptograph ecdsa with sha256 utility
