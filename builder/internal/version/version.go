package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Injected at build time via -ldflags
var (
	Version   = "dev"
	GitCommit = ""
	BuildTime = ""
)

// Info returns formatted version information
func Info() string {
	goVersion := runtime.Version()

	// Try to get VCS info from build info
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if GitCommit == "" {
					GitCommit = setting.Value
				}
			case "vcs.time":
				if BuildTime == "" {
					BuildTime = setting.Value
				}
			}
		}
	}

	result := fmt.Sprintf("rookery-builder %s", Version)
	if GitCommit != "" {
		if len(GitCommit) > 7 {
			result += fmt.Sprintf(" (%s)", GitCommit[:7])
		} else {
			result += fmt.Sprintf(" (%s)", GitCommit)
		}
	}
	if BuildTime != "" {
		result += fmt.Sprintf("\nBuilt: %s", BuildTime)
	}
	result += fmt.Sprintf("\nGo: %s", goVersion)

	return result
}
