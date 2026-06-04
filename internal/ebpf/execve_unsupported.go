//go:build !linux || (!amd64 && !arm64)

package ebpf

import (
	"context"
	"errors"

	"runtime-guard/internal/events"
)

type ExecveCollector struct{}
type ConnectCollector struct{}
type FileWriteCollector struct{}
type ChmodCollector struct{}

func NewExecveCollector() (*ExecveCollector, error) {
	return nil, errors.New("live execve collection currently requires Linux amd64 or arm64")
}

func NewExecveCollectorWithConfig(RuntimeConfig) (*ExecveCollector, error) {
	return nil, errors.New("live execve collection currently requires Linux amd64 or arm64")
}

func (*ExecveCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live execve collection currently requires Linux amd64 or arm64")
}

func NewConnectCollector() (*ConnectCollector, error) {
	return nil, errors.New("live connect collection currently requires Linux amd64 or arm64")
}

func NewConnectCollectorWithConfig(RuntimeConfig) (*ConnectCollector, error) {
	return nil, errors.New("live connect collection currently requires Linux amd64 or arm64")
}

func (*ConnectCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live connect collection currently requires Linux amd64 or arm64")
}

func NewFileWriteCollector() (*FileWriteCollector, error) {
	return nil, errors.New("live file write collection currently requires Linux amd64 or arm64")
}

func NewFileWriteCollectorWithConfig(RuntimeConfig) (*FileWriteCollector, error) {
	return nil, errors.New("live file write collection currently requires Linux amd64 or arm64")
}

func (*FileWriteCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live file write collection currently requires Linux amd64 or arm64")
}

func NewChmodCollector() (*ChmodCollector, error) {
	return nil, errors.New("live chmod collection currently requires Linux amd64 or arm64")
}

func NewChmodCollectorWithConfig(RuntimeConfig) (*ChmodCollector, error) {
	return nil, errors.New("live chmod collection currently requires Linux amd64 or arm64")
}

func (*ChmodCollector) Run(context.Context, chan<- events.Event) error {
	return errors.New("live chmod collection currently requires Linux amd64 or arm64")
}

func NewRuntimeCollector() (Collector, error) {
	return nil, errors.New("live collection currently requires Linux amd64 or arm64")
}

func NewRuntimeCollectorWithConfig(config RuntimeConfig) (Collector, error) {
	if _, err := checkedRuntimeConfig(config); err != nil {
		return nil, err
	}
	if _, err := checkedCollectorNames(config.Collectors); err != nil {
		return nil, err
	}
	return nil, errors.New("live collection currently requires Linux amd64 or arm64")
}
