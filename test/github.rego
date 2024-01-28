package github

deny[msg] {
    input.projecturl != "https://github.com/in-toto/demo-package"
    msg := "projecturl is not 'https://github.com/kairoaraujo/demo-package'"
}