package endpoint

func findBpfObjectFile() (string, error) {
	return "/usr/libexec/scope/ebpf/tcptracer-ebpf.o", nil
}
