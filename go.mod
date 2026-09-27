module github.com/osto/cli-login-system

go 1.22.2

require (
	github.com/chzyer/readline v1.5.1
	github.com/google/uuid v1.6.0
	github.com/mattn/go-sqlite3 v1.14.52
	github.com/pquerna/otp v1.5.0
	golang.org/x/crypto v0.31.0
)

require (
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	golang.org/x/sys v0.28.0 // indirect
)

replace golang.org/x/sys => github.com/golang/sys v0.29.0

replace golang.org/x/crypto => github.com/golang/crypto v0.31.0

replace golang.org/x/term => github.com/golang/term v0.27.0
