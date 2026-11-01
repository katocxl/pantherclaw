// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package scan

import (
	"regexp"
	"slices"
	"strings"
)

// launcherFlags says how a launcher reads its flags, so the first positional
// argument is its package. A flag it does not list could take a value, which
// could be anything, so reading stops there and no package is reported.
type launcherFlags struct {
	plain, value, pkg []string
}

var (
	npxFlags = launcherFlags{
		plain: []string{"-y", "--yes", "--no", "-q", "--quiet", "--no-install", "--ignore-existing"},
		value: []string{"--cache", "--registry", "--userconfig", "--node-options"},
		pkg:   []string{"-p", "--package"},
	}
	bunxFlags = launcherFlags{
		plain: []string{"-b", "--bun", "--silent", "--no-install"},
		pkg:   []string{"-p", "--package"},
	}
	uvxFlags = launcherFlags{
		plain: []string{"-q", "--quiet", "-v", "--verbose", "--isolated", "--refresh", "--offline", "--no-cache", "-n", "--no-progress"},
		value: []string{"--with", "--with-editable", "--with-requirements", "-p", "--python", "--index", "--index-url", "--default-index"},
		pkg:   []string{"--from"},
	}
	pipxFlags = launcherFlags{
		plain: []string{"-q", "--quiet", "-v", "--verbose", "--no-cache", "--system-site-packages", "--pypackages"},
		value: []string{"--python", "--pip-args", "--index-url", "--backend"},
		pkg:   []string{"--spec"},
	}
	dockerFlags = launcherFlags{
		plain: []string{
			"-i", "--interactive", "-t", "--tty", "-it", "-ti", "-d", "--detach", "--rm", "--init", "--privileged", "--read-only",
			"-P", "--publish-all", "--no-healthcheck", "--oom-kill-disable",
		},
		value: []string{
			"-a", "--attach", "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "--network", "--net", "-p", "--publish",
			"-u", "--user", "-w", "--workdir", "--entrypoint", "--label", "-l", "--label-file", "--add-host", "--cap-add", "--cap-drop",
			"--cpus", "-m", "--memory", "--memory-swap", "--pull", "--platform", "--restart", "--runtime", "--security-opt", "--tmpfs",
			"--ulimit", "--volumes-from", "--hostname", "-h", "--dns", "--expose", "--gpus", "--pids-limit", "--shm-size", "--stop-signal",
			"--stop-timeout", "--ipc", "--pid", "--uts", "--userns", "--device", "--group-add", "--cidfile",
		},
	}
)

// The shapes a package or image token can have. A token that fits none is not
// reported: it may be a path, a URL with a credential in it or anything else
// a command line holds.
var (
	npmRef    = regexp.MustCompile(`^(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+(@[A-Za-z0-9._+~-]+)?$`)
	pythonRef = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?((==|@)[A-Za-z0-9._+!-]+)?$`)
	imageRef  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(:[0-9]{1,5})?(/[A-Za-z0-9._-]+)*(:[A-Za-z0-9._-]{1,128})?(@sha256:[0-9a-f]{64})?$`)
)

const maxPackageRef = 200

// packageRef returns the package or image a launcher command runs, for npx,
// bunx, uvx, pipx run and docker run: that token alone, never another
// argument. It is "" for any other command, and whenever the token cannot be
// told apart from the arguments around it.
func packageRef(command string, args []string) string {
	name := strings.ToLower(baseName(command))
	for _, ext := range []string{".exe", ".cmd", ".bat"} {
		name = strings.TrimSuffix(name, ext)
	}
	var (
		flags launcherFlags
		shape *regexp.Regexp
	)
	switch name {
	case "cmd": // cmd /c npx …, as Windows configurations start a launcher
		if len(args) >= 2 && strings.EqualFold(args[0], "/c") {
			return packageRef(args[1], args[2:])
		}
		return ""
	case "npx":
		flags, shape = npxFlags, npmRef
	case "bunx":
		flags, shape = bunxFlags, npmRef
	case "uvx":
		flags, shape = uvxFlags, pythonRef
	case "pipx":
		if len(args) == 0 || args[0] != "run" {
			return ""
		}
		flags, shape, args = pipxFlags, pythonRef, args[1:]
	case "docker":
		if len(args) == 0 || args[0] != "run" {
			return ""
		}
		flags, shape, args = dockerFlags, imageRef, args[1:]
	default:
		return ""
	}
	ref := firstPositional(args, flags)
	if kind, _ := knownPrefix(ref); kind != "" || len(ref) > maxPackageRef || !shape.MatchString(ref) {
		return ""
	}
	return ref
}

// firstPositional returns the package a launcher's flags name or else its
// first positional argument, "" when a flag it cannot read comes first.
func firstPositional(args []string, flags launcherFlags) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return arg
		}
		name, value, inline := strings.Cut(arg, "=")
		switch {
		case slices.Contains(flags.pkg, name):
			if inline {
				return value
			}
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		case slices.Contains(flags.value, name):
			if !inline {
				i++
			}
		case slices.Contains(flags.plain, name):
		default:
			return ""
		}
	}
	return ""
}

// baseName is the last element of a path written for any platform.
func baseName(path string) string {
	if i := strings.LastIndexAny(path, `/\`); i >= 0 {
		return path[i+1:]
	}
	return path
}
