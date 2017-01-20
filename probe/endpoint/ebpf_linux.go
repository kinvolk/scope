package endpoint

func findBpfObjectFile() (string, error) {
	return "/usr/libexec/scope/ebpf/ebpf.o", nil
}
