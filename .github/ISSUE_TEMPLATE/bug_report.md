name: "Bug Report"
description: Create a new issue for a bug.
title: "[BUG] - <title>"
labels: [
  "bug"
]
assignees:
  - semihalev
body:
  - type: textarea
    id: description
    attributes:
      label: "Description"
      description: Please enter an explicit description of your issue
      placeholder: Short and explicit description of your incident...
    validations:
      required: true
  - type: textarea
    id: reprod
    attributes:
      label: "Reproduction steps"
      description: Please enter an explicit description of your issue
      value: |
        1. Go to '...'
        2. Click on '....'
        3. Scroll down to '....'
        4. See error
      render: bash
    validations:
      required: true
  - type: textarea
    id: sdns-version
    attributes:
      label: sdns version
      description: "`sdns --version` output"
      render: bash
    validations:
      required: true
  - type: textarea
    id: screenshot
    attributes:
      label: "Screenshots"
      description: If applicable, add screenshots to help explain your problem.
      value: |
        ![DESCRIPTION](LINK.png)
      render: bash
    validations:
      required: false
  - type: textarea
    id: logs
    attributes:
      label: "Logs"
      description: Please copy and paste any relevant log output. This will be automatically formatted into code, so no need for backticks.
      render: bash
    validations:
      required: false
  - type: dropdown
    id: os
    attributes:
      label: "OS"
      description: What is the impacted environment ?
      multiple: true
      options:
        - Windows
        - Linux
        - MacOS
        - FreeBSD
        - Other
  - type: textarea
    id: ctx
    attributes:
      label: Additional context
      description: Anything else you would like to add
    validations:
      required: false
    validations:
      required: false
