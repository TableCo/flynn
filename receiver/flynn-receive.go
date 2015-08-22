package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/flynn/flynn/controller/client"
	ct "github.com/flynn/flynn/controller/types"
	"github.com/flynn/flynn/host/types"
	"github.com/flynn/flynn/pkg/cluster"
	"github.com/flynn/flynn/pkg/exec"
	"github.com/flynn/flynn/pkg/random"
)

var clusterc = cluster.NewClient()

func init() {
	log.SetFlags(0)
}

var typesPattern = regexp.MustCompile("types.* -> (.+)\n")

const blobstoreURL = "http://blobstore.discoverd"
const scaleTimeout = 20 * time.Second

func main() {
	client, err := controller.NewClient("", os.Getenv("CONTROLLER_KEY"))
	if err != nil {
		log.Fatalln("Unable to connect to controller:", err)
	}

	appName := os.Args[1]

	app, err := client.GetApp(appName)
	if err == controller.ErrNotFound {
		log.Fatalf("Unknown app %q", appName)
	} else if err != nil {
		log.Fatalln("Error retrieving app:", err)
	}
	prevRelease, err := client.GetAppRelease(app.Name)
	if err == controller.ErrNotFound {
		prevRelease = &ct.Release{}
	} else if err != nil {
		log.Fatalln("Error getting current app release:", err)
	}

	fmt.Printf("-----> Building %s...\n", app.Name)

	var output bytes.Buffer
	slugURL := fmt.Sprintf("%s/%s.tgz", blobstoreURL, random.UUID())
	cmd := exec.Command(exec.DockerImage(os.Getenv("SLUGBUILDER_IMAGE_URI")), slugURL)
	cmd.Stdout = io.MultiWriter(os.Stdout, &output)
	cmd.Stderr = os.Stderr
	cmd.Meta = map[string]string{
		"flynn-controller.app":      app.ID,
		"flynn-controller.app_name": app.Name,
		"flynn-controller.release":  prevRelease.ID,
		"flynn-controller.type":     "slugbuilder",
	}
	if len(prevRelease.Env) > 0 {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			log.Fatalln(err)
		}
		go appendEnvDir(os.Stdin, stdin, prevRelease.Env)
	} else {
		cmd.Stdin = os.Stdin
	}
	cmd.Env = make(map[string]string)
	cmd.Env["BUILD_CACHE_URL"] = fmt.Sprintf("%s/%s-cache.tgz", blobstoreURL, app.ID)
	if buildpackURL, ok := prevRelease.Env["BUILDPACK_URL"]; ok {
		cmd.Env["BUILDPACK_URL"] = buildpackURL
	}

	if err := cmd.Run(); err != nil {
		log.Fatalln("Build failed:", err)
	}

	var types []string
	if match := typesPattern.FindSubmatch(output.Bytes()); match != nil {
		types = strings.Split(string(match[1]), ", ")
	}

	fmt.Printf("-----> Creating release...\n")

	artifact := &ct.Artifact{Type: "docker", URI: os.Getenv("SLUGRUNNER_IMAGE_URI")}
	if err := client.CreateArtifact(artifact); err != nil {
		log.Fatalln("Error creating artifact:", err)
	}

	release := &ct.Release{
		ArtifactID: artifact.ID,
		Env:        prevRelease.Env,
	}
	procs := make(map[string]ct.ProcessType)
	for _, t := range types {
		proc := prevRelease.Processes[t]
		proc.Cmd = []string{"start", t}
		if t == "web" {
			proc.Ports = []ct.Port{{
				Port:  8080,
				Proto: "tcp",
				Service: &host.Service{
					Name:   app.Name + "-web",
					Create: true,
					Check:  &host.HealthCheck{Type: "tcp"},
				},
			}}
		}
		procs[t] = proc
	}
	release.Processes = procs
	if release.Env == nil {
		release.Env = make(map[string]string)
	}
	release.Env["SLUG_URL"] = slugURL

	if err := client.CreateRelease(release); err != nil {
		log.Fatalln("Error creating release:", err)
	}
	if err := client.DeployAppRelease(app.Name, release.ID); err != nil {
		log.Fatalln("Error deploying app release:", err)
	}

	fmt.Println("=====> Application deployed")

	if needsDefaultScale(app.ID, prevRelease.ID, procs, client) {
		formation := &ct.Formation{
			AppID:     app.ID,
			ReleaseID: release.ID,
			Processes: map[string]int{"web": 1},
		}

		watcher, err := client.WatchJobEvents(app.ID, release.ID)
		if err != nil {
			log.Fatalln("Error streaming job events", err)
			return
		}
		defer watcher.Close()

		if err := client.PutFormation(formation); err != nil {
			log.Fatalln("Error putting formation:", err)
		}
		fmt.Println("=====> Waiting for web job to start...")

		err = watcher.WaitFor(ct.JobEvents{"web": {"up": 1}}, scaleTimeout, func(e *ct.JobEvent) error {
			switch e.State {
			case "up":
				fmt.Println("=====> Default web formation scaled to 1")
			case "down", "crashed":
				return fmt.Errorf("Failed to scale web process type")
			}
			return nil
		})
		if err != nil {
			log.Fatalln(err.Error())
		}
	}
}

// needsDefaultScale indicates whether a release needs a default scale based on
// whether it has a web process type and either has no previous release or no
// previous scale.
func needsDefaultScale(appID, prevReleaseID string, procs map[string]ct.ProcessType, client *controller.Client) bool {
	if _, ok := procs["web"]; !ok {
		return false
	}
	if prevReleaseID == "" {
		return true
	}
	_, err := client.GetFormation(appID, prevReleaseID)
	return err == controller.ErrNotFound
}

func appendEnvDir(stdin io.Reader, pipe io.WriteCloser, env map[string]string) {
	defer pipe.Close()
	tr := tar.NewReader(stdin)
	tw := tar.NewWriter(pipe)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			// end of tar archive
			break
		}
		if err != nil {
			log.Fatalln(err)
		}
		hdr.Name = path.Join("app", hdr.Name)
		if err := tw.WriteHeader(hdr); err != nil {
			log.Fatalln(err)
		}
		if _, err := io.Copy(tw, tr); err != nil {
			log.Fatalln(err)
		}
	}
	// append env dir
	for key, value := range env {
		hdr := &tar.Header{
			Name:    path.Join("env", key),
			Mode:    0644,
			ModTime: time.Now(),
			Size:    int64(len(value)),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			log.Fatalln(err)
		}
		if _, err := tw.Write([]byte(value)); err != nil {
			log.Fatalln(err)
		}
	}
	hdr := &tar.Header{
		Name:    ".ENV_DIR_bdca46b87df0537eaefe79bb632d37709ff1df18",
		Mode:    0400,
		ModTime: time.Now(),
		Size:    0,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		log.Fatalln(err)
	}
}
