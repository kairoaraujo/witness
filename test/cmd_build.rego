package commandrun

deny[msg] {
    input.cmd != ["python3", "-m", "build", "--sdist", "--wheel", "--outdir", "dist/", "."]
    msg := "build command doesn't match"
}
