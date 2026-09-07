# Triage labels

Use exactly one terminal triage state when a ticket needs routing:

- `needs-triage`: the issue has not been classified.
- `needs-info`: progress requires information from the reporter or operator.
- `ready-for-agent`: autonomous work may begin.
- `ready-for-human`: human judgment or action is the next step.
- `wontfix`: the issue will not be pursued.

Wayfinder maps use `wayfinder:map`. Their tickets use the matching
`wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or
`wayfinder:task` label.
