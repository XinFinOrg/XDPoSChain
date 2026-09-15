# How to set up the development environment

## pre-commit

### Install pre-commit

Install pre-commit via `pipx`:

```bash
# Install pre-commit
pipx install pre-commit

# Verify installed version
pre-commit --version
```

### Upgrade pre-commit

If pre-commit was installed via `pipx`, upgrade it with:

```bash
# Upgrade pre-commit
pipx upgrade pre-commit

# Verify installed version
pre-commit --version
```

### Install Git hooks

Install Git hook scripts:

```bash
# Install the pre-commit hook
pre-commit install

# Install the commit-msg hook
pre-commit install --hook-type commit-msg

# Validate pre-commit configuration
pre-commit validate-config

# Verify commit-msg hook (this does not create a commit)
tmp_commit_msg="$(mktemp)"
printf "chore(docs): test commit message\n" > "${tmp_commit_msg}"
pre-commit run conventional-pre-commit --hook-stage commit-msg --commit-msg-filename "${tmp_commit_msg}"
rm -f "${tmp_commit_msg}"
```

Note:

- commit messages must follow Conventional Commits.
  - Format: `<type>(<scope>): <description>`
  - Example: `feat(core): add new validation check`
- The above commands avoid scanning the whole repository. If you want to run hooks against the whole repository, use:

```bash
pre-commit run --all-files
```

This command only runs hooks in the `pre-commit` stage and may modify many files.

### Upgrade hook versions

Update hook versions in `.pre-commit-config.yaml`:

```bash
pre-commit autoupdate
```

After updating, prepare environments, run checks, and review changes before committing:

```bash
pre-commit install-hooks
pre-commit validate-config
tmp_commit_msg="$(mktemp)"
printf "chore(docs): test commit message\n" > "${tmp_commit_msg}"
pre-commit run conventional-pre-commit --hook-stage commit-msg --commit-msg-filename "${tmp_commit_msg}"
rm -f "${tmp_commit_msg}"
git diff .pre-commit-config.yaml
```

### Uninstall Git hooks

Uninstall Git hook scripts:

```bash
# Uninstall the commit-msg hook
pre-commit uninstall --hook-type commit-msg

# Uninstall the pre-commit hook
pre-commit uninstall
```

### Uninstall pre-commit

Uninstall pre-commit with:

```bash
pipx uninstall pre-commit
```
