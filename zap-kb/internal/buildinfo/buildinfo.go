// Package buildinfo exposes the identity embedded in a zap-kb build.
//
// Release automation sets these values with Go linker flags.  The defaults are
// deliberately stable so local builds do not claim an unverifiable revision.
package buildinfo

import "fmt"

var (
	Version   = "dev"
	Revision  = "unknown"
	BuildTime = "unknown"
)

// String is intentionally line-oriented so operators can use it from a
// running container without parsing human-oriented help output.
func String() string {
	return fmt.Sprintf("zap-kb version=%s revision=%s build_time=%s", Version, Revision, BuildTime)
}
