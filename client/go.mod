module main

go 1.15

replace github.com/notcat/tcpsockettest/client/commands => ./commands

require (
	github.com/ProtonMail/gopenpgp/v2 v2.1.3
	github.com/gorilla/websocket v1.4.2
	github.com/kr/pretty v0.1.0 // indirect
	github.com/notcat/tcpsockettest/client/commands v0.0.0-00010101000000-000000000000
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)
