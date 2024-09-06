# Control another process

[![pkg.go.dev](https://pkg.go.dev/badge/gitlab.com/tozd/go/pcontrol)](https://pkg.go.dev/gitlab.com/tozd/go/pcontrol)
[![Go Report Card](https://goreportcard.com/badge/gitlab.com/tozd/go/pcontrol)](https://goreportcard.com/report/gitlab.com/tozd/go/pcontrol)
[![pipeline status](https://gitlab.com/tozd/go/pcontrol/badges/main/pipeline.svg?ignore_skipped=true)](https://gitlab.com/tozd/go/pcontrol/-/pipelines)
[![coverage report](https://gitlab.com/tozd/go/pcontrol/badges/main/coverage.svg)](https://gitlab.com/tozd/go/pcontrol/-/graphs/main/charts)

A Go package that allows you to attach to a running process and call system calls from inside the attached process.

It works on Linux and internally uses ptrace.

It was made for use in [dinit](https://gitlab.com/tozd/dinit) to change stdout and stderr of running processes,
but maybe it comes handy to somebody else as well.

## Installation

This is a Go package. You can add it to your project using `go get`:

```sh
go get gitlab.com/tozd/go/pcontrol
```

It requires Go 1.23 or newer.

## Usage

See full package documentation with examples on [pkg.go.dev](https://pkg.go.dev/gitlab.com/tozd/go/pcontrol#section-documentation).

## GitHub mirror

There is also a [read-only GitHub mirror available](https://github.com/tozd/go-pcontrol),
if you need to fork the project there.
