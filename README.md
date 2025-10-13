# RecordIt

A utility tool to record certain file before runs a command.

The recoreded files are stored in a directory `.recordit`(changeable) under
    1. current git repository root
    2. current working directory

All the files related to one session will be stored in a sub-directory named by timestamp by default, or you can give it a name and optional message.

## Recording

This tool will save all the files that either

1. are tracked by git
2. are specified by `--record` argument(s)

## Executiion

This tool will execute the command and

1. console mode: redirect the stdin, stdout, stderr of the command to the current terminal
2. tui mode: split the stdin, stdout, stderr of the command into 3 panes in a tui.