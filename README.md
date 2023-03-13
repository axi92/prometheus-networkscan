# prometheus-networkscan
Export metrics for Prometheus for all found devices on that network.

`sudo apt-get install libpcap-dev`

# Build in docker with older glibc version
`docker run -ti --rm -v $(pwd):/workdir/. -w /workdir golang:buster bash`

Inside container:

`apt update && apt install -y libpcap-dev && wget "https://maclookup.app/downloads/json-database/get-db" -O mac-vendors-export.json && go build -buildvcs=false`