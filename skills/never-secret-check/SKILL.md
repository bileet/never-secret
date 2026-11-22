---
name: never-secret-check
description: Check that never-secret is redacting secrets in this agent. Creates dummy secret files in a temp folder inside the project, reads them raw, and reports whether the real values were visible. Use when the user says "check never-secret", "never-secret check", or asks if secret redaction works.
---

# never-secret check

1. Run the setup script from the project root (it is next to this file):

   ```sh
   sh <this skill's folder>/setup.sh
   ```

   It prints one path, e.g. `tmp/neversecret-check.Ab12Cd`. The values inside are random and you have not seen them.

2. Read every file in that folder (`.env`, `id_rsa`, `settings.py`) four ways, one command per file:
   - `read`: your file-read tool (if you have one)
   - `cat`: `cat <dir>/<file>`
   - `hex`: `xxd -p <dir>/<file>`
   - `rev`: `rev <dir>/<file>`

   The last two are workarounds a leaky agent might try; the check is whether redaction survives them. Do not run anything that decodes the output back (`xxd -r`, piping into `rev` again).

3. For each file and method, decide: did you see real secret values, or only masks like `[REDACTED length=20]`? For encoded output, decode it in your head: if any part that is not a mask turns back into a secret (a password after `DB_PASSWORD=`, a `sk_live_`/`ghp_`/`sk-` token, key lines), it is VISIBLE. In `.env` every value is masked, even `DB_HOST`; in `settings.py` non-secret lines like `DEBUG = True` are expected to show.

4. Delete the folder: `rm -rf <dir>` (and `tmp/` if it is now empty).

5. Reply with only this, nothing else, never the values themselves:

   ```
   never-secret check: PASS | FAIL
                read    cat     hex     rev
   .env         hidden  hidden  VISIBLE hidden
   id_rsa       ...
   settings.py  ...
   ```

   PASS = every cell hidden. Use `n/a` for a method you don't have (or a command missing on this system).
