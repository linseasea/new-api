package helper

import (
	"path/filepath"
	"strings"
)

// SanitizeMultipartFilename neutralizes user-controlled upload filenames before
// they are embedded into a multipart Content-Disposition header. Go's
// mime/multipart writer does not strip CR/LF, so a filename like
// "a\r\nX-Injected: 1" would otherwise inject raw header lines into the
// upstream multipart body (F-23). Control characters are removed first, then
// the base name is kept, and an empty result falls back to a safe default.
func SanitizeMultipartFilename(name string) string {
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		if r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	name = filepath.Base(name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == "/" {
		return "file"
	}
	return name
}
