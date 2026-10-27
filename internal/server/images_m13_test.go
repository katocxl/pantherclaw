// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestHR374_ImagesAreDistrolessNonRootShellLessAndTrimmed reads the server
// and gateway Dockerfiles: a static (CGO_ENABLED=0) -trimpath build from
// the Taskfile's pinned Go image, cross-compiled for the target platform,
// on distroless static pinned by digest, as the nonroot user, with an
// exec-form entrypoint and nothing that needs a shell in the final stage.
func TestHR374_ImagesAreDistrolessNonRootShellLessAndTrimmed(t *testing.T) {
	task, err := os.ReadFile(filepath.Join("..", "..", "Taskfile.yml"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`GOLANG_IMAGE: (golang:\S+@sha256:[0-9a-f]{64})`).FindSubmatch(task)
	if m == nil {
		t.Fatal("Taskfile.yml has no pinned GOLANG_IMAGE")
	}
	goImage := string(m[1])
	for _, name := range []string{"server", "gateway"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("..", "..", "deploy", "docker", name+".Dockerfile"))
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			stages := regexp.MustCompile(`(?m)^FROM `).Split(s, -1)
			if len(stages) != 3 {
				t.Fatalf("want a build stage and a final stage, got %d stages", len(stages)-1)
			}
			build, final := stages[1], stages[2]
			if !strings.HasPrefix(build, "--platform=$BUILDPLATFORM "+goImage+" ") {
				t.Errorf("build stage is not the pinned toolchain %s on the build platform", goImage)
			}
			for _, want := range []string{
				"CGO_ENABLED=0", "GOOS=$TARGETOS", "GOARCH=$TARGETARCH", "-trimpath", "GOTOOLCHAIN=local",
				"./cmd/pantherclaw-" + name, "ARG VERSION",
			} {
				if !strings.Contains(build, want) {
					t.Errorf("build stage lacks %q", want)
				}
			}
			if !regexp.MustCompile(`^gcr\.io/distroless/static-debian12@sha256:[0-9a-f]{64}\n`).MatchString(final) {
				t.Errorf("final stage is not distroless static pinned by digest: %q", strings.SplitN(final, "\n", 2)[0])
			}
			if !regexp.MustCompile(`(?m)^USER 65532:65532$`).MatchString(final) {
				t.Error("final stage does not run as distroless's nonroot user 65532")
			}
			if !regexp.MustCompile(`(?m)^ENTRYPOINT \["/pantherclaw-` + name + `"\]$`).MatchString(final) {
				t.Error("final stage has no exec-form entrypoint")
			}
			for _, line := range strings.Split(final, "\n") {
				f := strings.Fields(line)
				if len(f) == 0 || strings.HasPrefix(f[0], "#") {
					continue
				}
				switch f[0] {
				case "RUN", "SHELL", "HEALTHCHECK":
					t.Errorf("final stage uses %s, which needs a shell or tools distroless lacks", f[0])
				case "CMD", "ENTRYPOINT":
					if !strings.HasPrefix(f[1], "[") {
						t.Errorf("%s in shell form", f[0])
					}
				}
			}
		})
	}
}
