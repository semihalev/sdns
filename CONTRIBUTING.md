# Contributing to SDNS

First and foremost, thank you for considering contributing to SDNS! It's people like you that make SDNS such a great tool.

## Getting Started

*   Make sure you have a [GitHub account](https://github.com/signup/free).
*   Fork the repository on GitHub.
*   Decide if you want to work on an existing issue or if you want to propose a new feature or bug fix.

## Making Changes

1.  Create a new branch in your fork from the main branch. Name your branch something descriptive.
2.  Make the changes in your fork.
3.  If you're adding a feature or fixing a bug, please add or modify existing tests if applicable.
4.  Run all tests to ensure your changes don't negatively impact existing code.
5.  Commit your changes to your branch. Keep commit messages clear and concise, stating what you did and why.

## Conventions

*   Format with `gofmt -w .`, then run `golangci-lint run`, `make test` and `go test -count=1 -run 'Alloc|ServeRawHitClasses' ./...` (the allocation pins, which do not run under `-race`). All of them should be clean before you open a pull request.
*   Tests use plain `testing` idioms. Do not add an assertion library.
*   Tests must not need the live network. Run them against loopback fixtures, such as a loopback authority, instead of resolving real names.

The full build and test guide, with the reasoning behind each convention, is at [sdns.dev/docs/development/building](https://sdns.dev/docs/development/building/).

## Submitting Changes

1.  Push your changes to your fork on GitHub.
2.  Open a pull request against the main branch of the original repository.
3.  Please ensure your pull request description clearly describes the problem and solution and relates to any issues it addresses.

## Additional Resources

*   [Issue tracker](https://github.com/semihalev/sdns/issues)
*   [General GitHub documentation](https://docs.github.com/)
*   [GitHub pull request documentation](https://docs.github.com/en/github/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-pull-requests)
