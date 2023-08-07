
## Generate your keys

```sh
openssl ecparam -name prime256v1 -genkey -noout -out priv_key.pem
openssl pkey -in priv_key.pem -pubout -out pub_key.pem
```
## Convert the pem content to base64

```sh
cat priv_key.pem | base64 > priv.base64
cat pub_key.pem | base64 > pub.base64
```
