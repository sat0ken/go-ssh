module gossh

go 1.19

require golang.org/x/crypto v0.1.0

require golang.org/x/sys v0.1.0 // indirect

replace golang.org/x/crypto => ./debug/crypto
