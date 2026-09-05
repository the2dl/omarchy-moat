module example.com/hostile

go 1.22

require (
	github.com/spf13/cobra v1.8.0
)

replace github.com/spf13/cobra => ../../../elsewhere/cobra

replace example.com/other => ./internal/other
