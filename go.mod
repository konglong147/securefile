module github.com/konglong147/securefile

go 1.20

require (
	github.com/konglong147/securefile/local/sing v0.5.1
	github.com/konglong147/securefile/local/sing-dns v0.3.0
	github.com/konglong147/securefile/local/sing-mux v0.2.1
	github.com/konglong147/securefile/local/sing-tun v0.4.5
	github.com/konglong147/securefile/local/sing-vmess v0.1.12
	github.com/metacubex/tfo-go v0.0.0-20241006021335-daedaf0ca7aa
	github.com/miekg/dns v1.1.62
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/sagernet/cloudflare-tls v0.0.0-20231208171750-a4483c1b7cd1
	github.com/sagernet/gomobile v0.1.4
	github.com/sagernet/utls v1.6.7
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/crypto v0.29.0
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56
	golang.org/x/mod v0.20.0
	golang.org/x/net v0.31.0
	golang.org/x/sys v0.27.0
)

replace (
	github.com/konglong147/securefile/local/sing v0.5.1 => ./local/sing
	github.com/konglong147/securefile/local/sing-dns v0.3.0 => ./local/sing-dns
	github.com/konglong147/securefile/local/sing-mux v0.2.1 => ./local/sing-mux
	github.com/konglong147/securefile/local/sing-quic v0.3.1 => ./local/sing-quic
	github.com/konglong147/securefile/local/sing-tun v0.4.5 => ./local/sing-tun
	github.com/konglong147/securefile/local/sing-vmess v0.1.12 => ./local/sing-vmess
)


require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.3.7 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/gofrs/uuid/v5 v5.3.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/sagernet/fswatch v0.1.1 // indirect
	github.com/sagernet/gvisor v0.0.0-20241123041152-536d05261cff // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-beta.4 // indirect
	github.com/sagernet/quic-go v0.48.2-beta.1 // indirect
	github.com/sagernet/reality v0.0.0-20230406110435-ee17307e7691 // indirect
	github.com/sagernet/sing v0.5.1 // indirect
	github.com/sagernet/smux v0.0.0-20231208180855-7041f6ea79e7 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/sync v0.9.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	golang.org/x/tools v0.24.0 // indirect
)
