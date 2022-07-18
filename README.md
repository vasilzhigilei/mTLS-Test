# mTLS-Test
Go test setup for mutual TLS

## Setup
Place your certificates in a `certs/` folder
* `origin.pem` (for regular TLS) (can be self-signed for testing purposes)
* `origin.key` (for regular TLS) (can be self-signed for testing purposes)
* `root.crt` (for mutual authentication) (can be chain of certificates)

## Run
`(sudo) go run server.go (-port=#) (-verbose)`
* port default is 443
* verbose default is false (verbose=true prints entire human-readable certificate)

## Test
Example curl command (replace local address with your server address):

`curl https://127.0.0.1:443/ --cert leaf.pem --key leaf.key -k`

**Note for Cloudflare Warp users: you may have to disable Cloudflare Warp if you're trying to curl to a remote server running this code**