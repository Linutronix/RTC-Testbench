# Contributing to Linux RealTime Communication Testbench

The Linux RealTime Communication Testbench encourages contributions in form of feedback, bug
reports and/or code contributions.

## Github Workflow

The Linux RealTime Communication Testbench follows the Github development model using pull
request. To contribute code to the project use the following workflow:

1. Fork the repo and create your branch from `main`
2. Develop and test your changes
3. Adhere to the coding style
4. Update the documentation if necessary
5. Issue the pull request

Issues can be reported by using Github issues. Make sure to provide the steps
and necessary information how to reproduce the issue. This includes:

- Hardware and NIC(s) being used
- Configuration files(s) being used

## Email Workflow

In addition, contributions are accepted via email as well:

1. Clone the repo and create your branch from `main`
2. Develop and test your changes
3. Adhere to the coding style
4. Update the documentation if necessary
5. Send the patches via Email To: Kurt Kanzenbach <kurt@linutronix.de> and Cc:
   rt-users <linux-rt-users@vger.kernel.org>

## Commit message rules

For individual commits the Linux RealTime Communication Testbench follows the Linux kernel way of
writing and signing commit messages.

Describe your changes:

https://www.kernel.org/doc/html/latest/process/submitting-patches.html#describe-your-changes

Sign your work:

https://www.kernel.org/doc/html/latest/process/submitting-patches.html#sign-your-work-the-developer-s-certificate-of-origin

## Code Style

The coding style is the Linux kernel one. If unsure about it, run
`clang-format` on the C files. The Perl scripts in `scripts/` follow the same
style via `perltidy` (config in `.perltidyrc`); run `perltidy -b <file>.pl` to
format them.

In addition, the reverse xmas tree variable ordering is used:

https://docs.kernel.org/process/maintainer-netdev.html#local-variable-ordering-reverse-xmas-tree-rcs

## License

By contributing, you agree that your changes will be licensed under
BSD-2-Clause.
