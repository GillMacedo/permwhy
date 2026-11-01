# Architecture

    settings files --> load_rules --> rules
    command --> split_command --> subcommands --> explain --> decision per subcommand
    rules --> lint --> findings

- **`split_command`** walks the text once, tracking quotes. It splits on the documented separators and collects commands nested in subshells, substitutions and control-flow bodies.
- **`strip_wrappers`** removes the wrappers the docs list, and leading environment-variable assignments. For allow rules only known-safe variables are stripped; for deny and ask rules any assignment is.
- **`explain`** checks deny, then ask, then allow. Deny and ask look at each subcommand with any leading assignment stripped; allow looks at it with only known-safe ones stripped. Nested commands can trigger deny and ask but don't need an allow.
- **`lint`** checks each rule against patterns the docs warn about.
- **The skill** tells Claude to run the script instead of reasoning through the rules.

Key choice: a single standard-library script, so installing the plugin needs no setup. See `decisions/`.
