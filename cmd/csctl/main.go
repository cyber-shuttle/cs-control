package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cyber-shuttle/cs-control/internal/control"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "csctl:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	global := flag.NewFlagSet("csctl", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	global.Usage = printUsage
	stateDir := global.String("state-dir", defaultStateDir(), "local non-secret state directory")
	sshBin := global.String("ssh-bin", envOr("CSCTL_SSH_BIN", "ssh"), "ssh executable")
	timeout := global.Duration("timeout", 20*time.Second, "timeout for each SSH command")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = global.Args()
	if len(args) == 0 {
		return usageError()
	}
	service := control.Service{
		Runner: control.Runner{SSHBin: *sshBin, Timeout: *timeout},
		Store:  control.Store{Dir: *stateDir},
	}
	switch args[0] {
	case "resource":
		return runResource(ctx, service, args[1:])
	case "runtime":
		return runRuntime(ctx, service, args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return usageError()
	}
}

func runResource(ctx context.Context, service control.Service, args []string) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(os.Stderr, "Usage: csctl resource discover --ssh ALIAS [--json]")
		return nil
	}
	if len(args) == 0 || args[0] != "discover" {
		return errors.New("usage: csctl resource discover --ssh ALIAS [--json]")
	}
	flags := flag.NewFlagSet("resource discover", flag.ContinueOnError)
	ssh := flags.String("ssh", "", "SSH config alias")
	jsonOutput := flags.Bool("json", false, "print JSON")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *ssh == "" {
		return errors.New("usage: csctl resource discover --ssh ALIAS [--json]")
	}
	resource, err := service.Runner.Discover(ctx, *ssh)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return printJSON(resource)
	}
	fmt.Printf("Host: %s\nHome: %s\nAccounts:\n", resource.Host, resource.HomeDir)
	for _, account := range resource.Accounts {
		fmt.Printf("  %s\n", account)
	}
	fmt.Println("Partitions:")
	for _, partition := range resource.Partitions {
		fmt.Printf("  %s: %d CPUs, %s memory", partition.Name, partition.CPUCount, partition.Memory)
		for _, gres := range partition.GRES {
			fmt.Printf(", %s=%d", gres.Name, gres.Count)
		}
		fmt.Println()
	}
	return nil
}

func runRuntime(ctx context.Context, service control.Service, args []string) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		fmt.Fprintln(os.Stderr, "Usage: csctl runtime create|list|get|stop")
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: csctl runtime create|list|get|stop")
	}
	switch args[0] {
	case "create":
		flags := flag.NewFlagSet("runtime create", flag.ContinueOnError)
		request := control.CreateRequest{}
		flags.StringVar(&request.ID, "id", "", "runtime ID (generated when omitted)")
		flags.StringVar(&request.SSH, "ssh", "", "SSH config alias")
		flags.StringVar(&request.Partition, "partition", "", "SLURM partition")
		flags.StringVar(&request.Account, "account", "", "SLURM account")
		flags.IntVar(&request.CPUs, "cpus", 1, "CPU count")
		flags.IntVar(&request.MemoryMB, "memory-mb", 1024, "memory in MiB")
		flags.StringVar(&request.Walltime, "walltime", "01:00:00", "SLURM [days-]HH:MM:SS")
		flags.StringVar(&request.Linkspan, "linkspan", "", "absolute remote Linkspan path")
		flags.StringVar(&request.Workflow, "workflow", "", "absolute remote workflow path")
		flags.StringVar(&request.RemoteRoot, "remote-root", "", "absolute remote runtime root")
		jsonOutput := flags.Bool("json", false, "print JSON")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("runtime create does not accept positional arguments")
		}
		runtime, err := service.Create(ctx, request)
		if err != nil {
			return err
		}
		return printRuntime(runtime, *jsonOutput)
	case "list":
		flags := flag.NewFlagSet("runtime list", flag.ContinueOnError)
		jsonOutput := flags.Bool("json", false, "print JSON")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("runtime list does not accept positional arguments")
		}
		runtimes, err := service.List(ctx)
		if err != nil {
			return err
		}
		if *jsonOutput {
			return printJSON(runtimes)
		}
		for _, runtime := range runtimes {
			fmt.Printf("%s\t%s\t%s\t%s\n", runtime.ID, runtime.State, runtime.SSH, runtime.JobID)
		}
		return nil
	case "get", "stop":
		flags := flag.NewFlagSet("runtime "+args[0], flag.ContinueOnError)
		jsonOutput := flags.Bool("json", false, "print JSON")
		if err := flags.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil
			}
			return err
		}
		if flags.NArg() != 1 {
			return fmt.Errorf("usage: csctl runtime %s [--json] ID", args[0])
		}
		var runtime *control.Runtime
		var err error
		if args[0] == "get" {
			runtime, err = service.Get(ctx, flags.Arg(0))
		} else {
			runtime, err = service.Stop(ctx, flags.Arg(0))
		}
		if err != nil {
			return err
		}
		return printRuntime(runtime, *jsonOutput)
	default:
		return errors.New("usage: csctl runtime create|list|get|stop")
	}
}

func printRuntime(runtime *control.Runtime, jsonOutput bool) error {
	if jsonOutput {
		return printJSON(runtime)
	}
	fmt.Printf("%s\t%s\t%s\t%s\n", runtime.ID, runtime.State, runtime.SSH, runtime.JobID)
	return nil
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".cs-control"
	}
	return filepath.Join(home, ".cybershuttle", "control")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func usageError() error {
	printUsage()
	return errors.New("invalid command")
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  csctl [--state-dir DIR] resource discover --ssh ALIAS [--json]
  csctl [--state-dir DIR] runtime create --ssh ALIAS --partition NAME --linkspan PATH --workflow PATH [options]
  csctl [--state-dir DIR] runtime list [--json]
  csctl [--state-dir DIR] runtime get [--json] ID
  csctl [--state-dir DIR] runtime stop [--json] ID`)
}
