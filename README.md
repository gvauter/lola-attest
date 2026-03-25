# lola-attest

A standalone CLI tool that reads a [Lola](https://github.com/RedHatProductSecurity/lola) module directory and produces an [in-toto](https://in-toto.io/) attestation. Pair with [AMPEL](https://github.com/carabiner-dev/ampel) to enforce supply chain governance policies on AI skill modules using CEL expressions.

## Use Case: AI Skills Supply Chain Governance

AI skills distributed through Lola are executable instructions — they tell AI assistants to run commands, access files, and configure MCP servers. `lola-attest` enables organizations to enforce governance over what skills are allowed to do by scanning module structure against CEL-based policies.

## Installation

```bash
go install github.com/gvauter/lola-attest@latest
go install github.com/carabiner-dev/ampel/cmd/ampel@latest
```

## Usage

### Generate an attestation

```bash
lola-attest ./module/ > module.intoto.json
```

This reads the module directory and outputs an in-toto Statement v1 JSON document with the module's structure (skills, commands, agents, MCP config) as the predicate.

### Evaluate against policies

```bash
ampel verify -a module.intoto.json -p policies/
```

AMPEL evaluates CEL expressions in each policy file against the attestation predicate. Non-zero exit code means one or more policies failed.

### CI usage

Add the included GitHub Actions workflow to any repo containing Lola modules. See `.github/workflows/lola-policy-check.yml`.

## Attestation Format

The attestation predicate (`https://lola.dev/module-structure/v1`) contains:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Module directory name |
| `has_readme` | bool | Whether README.md exists |
| `has_agents_md` | bool | Whether AGENTS.md exists |
| `skills` | array | Skills with frontmatter, lexicon status, content length |
| `commands` | array | Commands with frontmatter and content |
| `agents` | array | Agents with frontmatter and content |
| `mcp` | object | MCP server configurations with extracted image refs |

## Included Policies

| Policy | Check |
|--------|-------|
| `LOLA.C01.TR01` | All skills must have a `description` in SKILL.md frontmatter |
| `LOLA.C02.TR01` | MCP server container images must not use `:latest` tag |
| `LOLA.C03.TR01` | Commands must not reference `--no-verify`, `--force`, or `--no-gpg-sign` |

Policies use the same AMPEL JSON format and CEL expression language used by [complyctl's ampel-plugin](https://github.com/complytime/complyctl/tree/main/cmd/ampel-plugin) for branch protection scanning.

## Writing Custom Policies

Create a JSON file in the `policies/` directory following the AMPEL policy format:

```json
{
  "id": "MY-ORG.C01.TR01",
  "meta": {
    "description": "Human-readable description of what this policy checks"
  },
  "tenets": [
    {
      "id": "01",
      "code": "predicates[0].has_readme == true",
      "predicates": {
        "types": ["https://lola.dev/module-structure/v1"]
      },
      "assessment": { "message": "Check passed" },
      "error": { "message": "Check failed", "guidance": "How to fix it" }
    }
  ]
}
```

The `code` field is a [CEL expression](https://cel.dev/) evaluated against the attestation predicate. Use `predicates[0]` to access the module structure fields.

## License

Apache-2.0
