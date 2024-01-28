package commandrun

deny[msg] {
    input.exitcode != 0
    msg := "exitcode not 0"
}
