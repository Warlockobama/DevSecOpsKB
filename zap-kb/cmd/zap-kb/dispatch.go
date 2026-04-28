package main

type subcommandHandler func([]string)

var subcommands = map[string]subcommandHandler{
	"config":  runConfigCommand,
	"expired": runExpiredCommand,
	"merge":   runMergeCommand,
	"onboard": runOnboardCommand,
	"pull":    runPullCommand,
	"report":  runReportCommand,
}

func lookupSubcommand(args []string) (subcommandHandler, []string, bool) {
	if len(args) == 0 {
		return nil, nil, false
	}
	handler, ok := subcommands[args[0]]
	if !ok {
		return nil, nil, false
	}
	return handler, args[1:], true
}
