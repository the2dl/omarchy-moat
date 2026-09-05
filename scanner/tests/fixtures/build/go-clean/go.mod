module example.com/ordinary

go 1.22

require (
	github.com/spf13/cobra v1.8.0
	golang.org/x/tools v0.21.0
)

replace example.com/ordinary/internal/util => ./internal/util
