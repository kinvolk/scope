package docker

import (
	"math/rand"
	"strconv"

	docker_client "github.com/fsouza/go-dockerclient"

	log "github.com/Sirupsen/logrus"

	"github.com/weaveworks/scope/common/xfer"
	"github.com/weaveworks/scope/probe/controls"
	"github.com/weaveworks/scope/report"
)

// Control IDs used by the docker integration.
const (
	StopContainer    = "docker_stop_container"
	StartContainer   = "docker_start_container"
	RestartContainer = "docker_restart_container"
	PauseContainer   = "docker_pause_container"
	UnpauseContainer = "docker_unpause_container"
	RemoveContainer  = "docker_remove_container"
	AttachContainer  = "docker_attach_container"
	ExecContainer    = "docker_exec_container"
	DebugContainer   = "docker_debug_container"

	waitTime = 10
)

func (r *registry) stopContainer(containerID string, _ xfer.Request) xfer.Response {
	log.Infof("Stopping container %s", containerID)
	return xfer.ResponseError(r.client.StopContainer(containerID, waitTime))
}

func (r *registry) startContainer(containerID string, _ xfer.Request) xfer.Response {
	log.Infof("Starting container %s", containerID)
	return xfer.ResponseError(r.client.StartContainer(containerID, nil))
}

func (r *registry) restartContainer(containerID string, _ xfer.Request) xfer.Response {
	log.Infof("Restarting container %s", containerID)
	return xfer.ResponseError(r.client.RestartContainer(containerID, waitTime))
}

func (r *registry) pauseContainer(containerID string, _ xfer.Request) xfer.Response {
	log.Infof("Pausing container %s", containerID)
	return xfer.ResponseError(r.client.PauseContainer(containerID))
}

func (r *registry) unpauseContainer(containerID string, _ xfer.Request) xfer.Response {
	log.Infof("Unpausing container %s", containerID)
	return xfer.ResponseError(r.client.UnpauseContainer(containerID))
}

func (r *registry) removeContainer(containerID string, req xfer.Request) xfer.Response {
	log.Infof("Removing container %s", containerID)
	if err := r.client.RemoveContainer(docker_client.RemoveContainerOptions{
		ID: containerID,
	}); err != nil {
		return xfer.ResponseError(err)
	}
	return xfer.Response{
		RemovedNode: req.NodeID,
	}
}

func (r *registry) attachContainer(containerID string, req xfer.Request) xfer.Response {
	c, ok := r.GetContainer(containerID)
	if !ok {
		return xfer.ResponseErrorf("Not found: %s", containerID)
	}

	hasTTY := c.HasTTY()
	id, pipe, err := controls.NewPipe(r.pipes, req.AppID)
	if err != nil {
		return xfer.ResponseError(err)
	}
	local, _ := pipe.Ends()
	cw, err := r.client.AttachToContainerNonBlocking(docker_client.AttachToContainerOptions{
		Container:    containerID,
		RawTerminal:  hasTTY,
		Stream:       true,
		Stdin:        true,
		Stdout:       true,
		Stderr:       true,
		InputStream:  local,
		OutputStream: local,
		ErrorStream:  local,
	})
	if err != nil {
		return xfer.ResponseError(err)
	}
	pipe.OnClose(func() {
		if err := cw.Close(); err != nil {
			log.Errorf("Error closing attachment to container %s: %v", containerID, err)
			return
		}
	})
	go func() {
		if err := cw.Wait(); err != nil {
			log.Errorf("Error waiting on attachment to container %s: %v", containerID, err)
		}
		pipe.Close()
	}()
	return xfer.Response{
		Pipe:   id,
		RawTTY: hasTTY,
	}
}

func (r *registry) debugContainer(containerID string, req xfer.Request) xfer.Response {
	_, ok := r.GetContainer(containerID)
	if !ok {
		return xfer.ResponseErrorf("Not found: %s", containerID)
	}

	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	randomString := make([]byte, 8)
	for i := 0; i < 8; i++ {
		randomString[i] = chars[rand.Intn(len(chars))]
	}

	// find the list of processes
	top, err := r.client.TopContainer(containerID, "")
	if err != nil {
		return xfer.ResponseError(err)
	}
	// heuristic: take the last process (likely the one that the user wants to debug)
	lastProcess := 0
	for _, proc := range top.Processes {
		p, err := strconv.Atoi(proc[1])
		if err == nil {
			lastProcess = p
		}
		log.Infof("Process %v", proc[1])
	}

	cDbg, err := r.client.CreateContainer(docker_client.CreateContainerOptions{
		Name: "debugger_" + containerID + "_" + string(randomString),
		Config: &docker_client.Config{
				OpenStdin:    true,
				AttachStdin:  true,
				AttachStderr: true,
				AttachStdout: true,
				Image:        "albanc/toolbox",
				Cmd:          []string{
					"/usr/bin/gdb",
					"-p",
					strconv.Itoa(lastProcess),
				},
				Tty:          true,
			},
	})
	if err != nil {
		return xfer.ResponseError(err)
	}

	err = r.client.StartContainer(cDbg.Name, &docker_client.HostConfig{
		Privileged: true,
		PidMode: "host",
	})
	if err != nil {
		return xfer.ResponseError(err)
	}

	id, pipe, err := controls.NewPipe(r.pipes, req.AppID)
	if err != nil {
		return xfer.ResponseError(err)
	}
	local, _ := pipe.Ends()
	cw, err := r.client.AttachToContainerNonBlocking(docker_client.AttachToContainerOptions{
		Container:    cDbg.Name,
		RawTerminal:  true,
		Stream:       true,
		Stdin:        true,
		Stdout:       true,
		Stderr:       true,
		InputStream:  local,
		OutputStream: local,
		ErrorStream:  local,
	})
	if err != nil {
		return xfer.ResponseError(err)
	}
	pipe.OnClose(func() {
		if err := cw.Close(); err != nil {
			log.Errorf("Error closing attachment to container %s: %v", cDbg.Name, err)
			return
		}
		if err := r.client.StopContainer(cDbg.Name, 1); err != nil {
			log.Errorf("Error stopping container %s: %v", cDbg.Name, err)
			return
		}
	})
	go func() {
		if err := cw.Wait(); err != nil {
			log.Errorf("Error waiting on attachment to container %s: %v", cDbg.Name, err)
		}
		pipe.Close()
	}()
	return xfer.Response{
		Pipe:   id,
		RawTTY: true,
	}
}

func (r *registry) execContainer(containerID string, req xfer.Request) xfer.Response {
	exec, err := r.client.CreateExec(docker_client.CreateExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          []string{"/bin/sh", "-l", "-c", "TERM=xterm exec $( (type getent > /dev/null 2>&1  && getent passwd root | cut -d: -f7 2>/dev/null) || echo /bin/sh)"},
		Container:    containerID,
	})
	if err != nil {
		return xfer.ResponseError(err)
	}

	id, pipe, err := controls.NewPipe(r.pipes, req.AppID)
	if err != nil {
		return xfer.ResponseError(err)
	}
	local, _ := pipe.Ends()
	cw, err := r.client.StartExecNonBlocking(exec.ID, docker_client.StartExecOptions{
		Tty:          true,
		RawTerminal:  true,
		InputStream:  local,
		OutputStream: local,
		ErrorStream:  local,
	})
	if err != nil {
		return xfer.ResponseError(err)
	}
	pipe.OnClose(func() {
		if err := cw.Close(); err != nil {
			log.Errorf("Error closing exec in container %s: %v", containerID, err)
			return
		}
	})
	go func() {
		if err := cw.Wait(); err != nil {
			log.Errorf("Error waiting on exec in container %s: %v", containerID, err)
		}
		pipe.Close()
	}()
	return xfer.Response{
		Pipe:   id,
		RawTTY: true,
	}
}

func captureContainerID(f func(string, xfer.Request) xfer.Response) func(xfer.Request) xfer.Response {
	return func(req xfer.Request) xfer.Response {
		containerID, ok := report.ParseContainerNodeID(req.NodeID)
		if !ok {
			return xfer.ResponseErrorf("Invalid ID: %s", req.NodeID)
		}
		return f(containerID, req)
	}
}

func (r *registry) registerControls() {
	controls := map[string]xfer.ControlHandlerFunc{
		StopContainer:    captureContainerID(r.stopContainer),
		StartContainer:   captureContainerID(r.startContainer),
		RestartContainer: captureContainerID(r.restartContainer),
		PauseContainer:   captureContainerID(r.pauseContainer),
		UnpauseContainer: captureContainerID(r.unpauseContainer),
		RemoveContainer:  captureContainerID(r.removeContainer),
		AttachContainer:  captureContainerID(r.attachContainer),
		ExecContainer:    captureContainerID(r.execContainer),
		DebugContainer:   captureContainerID(r.debugContainer),
	}
	r.handlerRegistry.Batch(nil, controls)
}

func (r *registry) deregisterControls() {
	controls := []string{
		StopContainer,
		StartContainer,
		RestartContainer,
		PauseContainer,
		UnpauseContainer,
		RemoveContainer,
		AttachContainer,
		ExecContainer,
		DebugContainer,
	}
	r.handlerRegistry.Batch(controls, nil)
}
