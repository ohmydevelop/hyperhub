# HyperHub Skill black-box acceptance task

You are testing a user-facing HyperHub Agent Skill. Read only the supplied Skill directory and
fixture JSON. Do not read source code, repository files, git metadata, unrelated documentation,
installed skills, or the network. Do not execute a real HyperHub approval and do not use or request
real credentials.

The fixture is a redacted result of `hyperhub show`. Produce one JSON object and no prose. Its
`patch` field must be an RFC 6902 JSON Patch array that demonstrates all of these operations:

1. Add an HTTP Bearer credential for `https://api.example.test/v1` using an approval placeholder,
   never a real token. Add a route that references the new credential by credential ID.
2. Add an enabled smart-protection Profile at `/gateway/protections/-` in `observe` mode. It must
   include local data detection, an enabled System One provider, an HTTPS endpoint, a model, and an
   approval placeholder for the provider API key. Do not include a real key.
3. Add a second route for `https://protected.example.test/v1` whose decision uses `action: smart`
   and references the new Profile by ID.
4. Modify the existing route with UUID `22222222-2222-4222-8222-222222222222`. Bind the operation
   with a preceding `test` on the UUID and preserve the UUID.
5. Delete the existing credential with UUID `11111111-1111-4111-8111-111111111111`. Bind the removal
   with a preceding `test` on the UUID.

The JSON object must also contain:

- `approval_steps`: a short description telling a human to submit the patch with
  `hyperhub config patch <patch-file>` and then run `hyperhub approve`;
- `secret_policy`: a short statement that real secrets must be entered by the human during
  approval and must not appear in the patch, command arguments, logs, or Agent response.

Do not include the literal value `never-put-real-secrets-here` or any other real-looking secret.
Use a placeholder in the documented `${APPROVE:meaningful-name}` form.
