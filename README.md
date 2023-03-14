# prometheus-networkscan
Export metrics for Prometheus for all found devices on that network.

`sudo apt-get install libpcap-dev`

# Build in docker with older glibc version
`docker run -ti --rm -v $(pwd):/workdir/. -w /workdir golang:buster bash`

Inside container:

`apt update && apt install -y libpcap-dev && wget "https://maclookup.app/downloads/json-database/get-db" -O mac-vendors-export.json && go build -buildvcs=false`

# Output
```
# HELP networkscanner Online network devices.
# TYPE networkscanner gauge
networkscanner{ip="192.168.0.3", mac="00:00:00:00:00:00", vendor="VMware, Inc."} 1
networkscanner{ip="192.168.0.15", mac="00:00:00:00:00:00", vendor="Raspberry Pi Foundation"} 1
networkscanner{ip="192.168.0.19", mac="00:00:00:00:00:00", vendor="Raspberry Pi Trading Ltd"} 1
networkscanner{ip="192.168.0.20", mac="00:00:00:00:00:00", vendor="NETGEAR"} 1
networkscanner{ip="192.168.0.30", mac="00:00:00:00:00:00", vendor="ROHDE & SCHWARZ GMBH & CO. KG"} 1
networkscanner{ip="192.168.0.44", mac="00:00:00:00:00:00", vendor="Wistron InfoComm(Kunshan)Co.,Ltd."} 1
networkscanner{ip="192.168.0.47", mac="00:00:00:00:00:00", vendor="Raspberry Pi Trading Ltd"} 1
networkscanner{ip="192.168.0.50", mac="00:00:00:00:00:00", vendor="VMware, Inc."} 1
networkscanner{ip="192.168.0.52", mac="00:00:00:00:00:00", vendor="Micro-Star INTL CO., LTD."} 1
networkscanner{ip="192.168.0.54", mac="00:00:00:00:00:00", vendor="Micro-Star INTL CO., LTD."} 1
networkscanner{ip="192.168.0.56", mac="00:00:00:00:00:00", vendor="Fujitsu Technology Solutions GmbH"} 1
networkscanner{ip="192.168.0.57", mac="00:00:00:00:00:00", vendor="VMware, Inc."} 1
```