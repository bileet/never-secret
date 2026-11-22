"""Self-check for the shared redaction engine (core/redact.py): python3 tests/test_redact.py"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core")
)
import base64
import html
import json
import re
import tempfile
import urllib.parse

from formats import known_redactor, redact_kv, redact_pgpass
from masking import ANY_MASK, mask
from patterns import apply_patterns
from redact import command_files, deep_redact
from values import known_values, mask_values, secret_key, secret_values, with_encodings


def test():
    cases = {
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS_SECRET_ACCESS_KEY=[REDACTED length=40]",
        "key AKIAIOSFODNN7EXAMPLE here": "key [REDACTED length=20] here",
        "postgres://bob:s3cr3t@db:5432/x": "postgres://bob:[REDACTED length=6]@db:5432/x",
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----": "[REDACTED length=65]",
        "token=ghp_" + "a" * 36: "token=[REDACTED length=40]",
        "PATH=/usr/bin  name=bob": "PATH=/usr/bin  name=bob",
        "hello world": "hello world",
        "x=AP6xxxxxxxxxx": "x=[REDACTED length=13]",
        'x = "AKCp8xxxxxxxx"': 'x = "[REDACTED length=13]"',
        "hook https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX": "hook [REDACTED length=77]",
        "Authorization: Bearer abc123def456ghi789jkl0": "Authorization: Bearer [REDACTED length=22]",
        "api.telegram.org/bot110201543:AAHdqTcvCH1vGWJxfSe1ofSAs0K5PALDsaw/getMe": "api.telegram.org/bot[REDACTED length=45]/getMe",
        "//registry.npmjs.org/:_authToken="
        + "743b"
        + "294a-cd03-11ec-9d64-0242ac120002": "//registry.npmjs.org/:_authToken=[REDACTED length=36]",
    }

    for src, want in cases.items():
        got = apply_patterns(src)
        assert got == want, f"{src!r} -> {got!r}, want {want!r}"

    # positive hits only: ordinary code that merely names secrets is never touched
    for line in (
        'token = request.headers.get("Authorization")',
        'password = os.environ["DB_PASSWORD"]',
        "const apiKey = process.env.OPENAI_API_KEY;",
        "secret_key = settings.SECRET_KEY",
        "password=${DB_PASSWORD}",
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN}",
        "auth_token: {{ .Values.token }}",
        "def check_password(password: str) -> bool:",
        "self.access_token = access_token",
        "password_hash = bcrypt.hashpw(password, salt)",
        "tokenizer = AutoTokenizer.from_pretrained(model_name)",
        'author = "jane"',
        "commit 8b1118b376c313ed420e5133ba91307817ed52c2",
        "id: 123e4567-e89b-12d3-a456-426614174000",
        '"https://url:8000";@something else',
        "see https://user@github.com/org/repo",
        "Bearer token expired, please re-login",
        "APACHEKAFKA and APPLICATION_ID",
    ):
        assert apply_patterns(line) == line, line
    basic = base64.b64encode(b"bob:hunter22").decode()
    assert (
        apply_patterns(f"Authorization: Basic {basic}\n")
        == f"Authorization: Basic {mask(basic)}\n"
    )

    for line in (
        "Basic auth is used here",
        "Basic Information",
        "Basic " + base64.b64encode(b"no-colon-here").decode(),
        "Basic " + base64.b64encode(b"\x00\x01:\xff\xfe").decode(),
    ):
        assert apply_patterns(line) == line, line
    assert (
        secret_key("DB_PASS")
        and secret_key("apiKey")
        and secret_key("_authToken")
        and secret_key("STRIPE_KEY")
    )
    assert not any(
        map(
            secret_key,
            ("author", "tokenizer", "REDDIT_USERNAME", "KEY_PREFIX", "DB_HOST", None),
        )
    )
    env = '# db\nDB_HOST=localhost\nexport PORT=5432\nEMPTY=\nQ=""\nKEY="-----BEGIN\nabc\n-----END"\nDB_PASS=hunter22\n'
    want = (
        "# db\nDB_HOST=[REDACTED length=9]\nexport PORT=[REDACTED length=4]\nEMPTY=[EMPTY]\nQ=[EMPTY]\n"
        "KEY=[REDACTED length=23]\nDB_PASS=[REDACTED length=8]\n"
    )
    got = apply_patterns(
        redact_kv(env)
    )  # same path as a known-file Read: no double masking
    assert got == want, repr(got)

    m = mask
    formats = {  # path -> (file text, expected)
        ".npmrc": (
            "//registry.npmjs.org/:_authToken=abc123\n",
            f"//registry.npmjs.org/:_authToken={m('abc123')}\n",
        ),
        "credentials": (
            "[default]\naws_access_key_id = AKIA1\n",
            f"[default]\naws_access_key_id = {m('AKIA1')}\n",
        ),
        "prod.tfvars": ('db_password = "pw12"\n', f"db_password = {m('pw12')}\n"),
        "id_ed25519": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nxyz\n",
            m("-----BEGIN OPENSSH PRIVATE KEY-----\nxyz") + "\n",
        ),
        ".pgpass": ("# c\ndb:5432:*:bob:pa:ss\n", f"# c\ndb:5432:*:bob:{m('pa:ss')}\n"),
        ".netrc": (
            "machine x login bob password hunter2\n",
            f"machine x login bob password {m('hunter2')}\n",
        ),
        "app-secrets.yaml": (
            'db:\n  user: bob\n  pass: ""\n  key: |\n    line1\n    line2\nother: 1\n',
            f"db:\n  user: {m('bob')}\n  pass: [EMPTY]\n  key: |\n    {m('line1')}\n    {m('line2')}\nother: {m('1')}\n",
        ),
        "credentials.json": (
            '{"type": "sa", "private_key": "k\\\\n", "n": 1}',
            f'{{"type": "{m("sa")}", "private_key": "{m("k" + chr(92) * 2 + "n")}", "n": 1}}',
        ),
    }

    for path, (src, want) in formats.items():
        got = known_redactor(path)(src)
        assert got == want, f"{path}: {got!r}, want {want!r}"
    assert (
        known_redactor("/a/.env.local")
        and known_redactor(".env")
        and not known_redactor("env.py")
    )
    assert not known_redactor(".env.example") and not known_redactor("/x/.env.sample")
    assert not known_redactor("id_rsa.pub") and not known_redactor("README.md")
    assert command_files("source .env && cat ~/.pgpass | grep x", None)[0] == [
        redact_kv,
        redact_pgpass,
    ]

    # output from known files the command never named (grep -r ., head *)
    grep = "./.env.local:1:DB_HOST=db.internal\n.env.local:2:DB_PASS=s3cret\nsrc/app.py:3:x = 1\n./id_rsa-4-abc\n"
    want = (
        f"./.env.local:1:DB_HOST={m('db.internal')}\n.env.local:2:DB_PASS={m('s3cret')}\n"
        f"src/app.py:3:x = 1\n./id_rsa-4-{m('abc')}\n"
    )
    assert deep_redact(grep) == want, repr(deep_redact(grep))
    head = "==> .env <==\nA=1\n\n==> notes.txt <==\nB=2\n"
    assert (
        deep_redact(head) == f"==> .env <==\nA={m('1')}\n\n==> notes.txt <==\nB=2\n"
    ), repr(deep_redact(head))

    # value masking: any print format leaks nothing
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "node_modules"))

        with open(os.path.join(d, ".env"), "w") as f:
            f.write(
                'DB_PASS=s3cretXY\nDB_HOST=db.internal\nPORT=5432\nDEBUG=true\nPRIVATE_KEY="l1-abcd\nl2-efgh"\n'
                "NODE_ENV=test\nREDDIT_USERNAME=throwaway_dev42\n"
            )

        with open(os.path.join(d, "node_modules", ".env"), "w") as f:
            f.write("IGNORED=pruned-dir\n")

        with open(os.path.join(d, "creds-secret.json"), "w") as f:
            f.write('{"private_key": "aaaa\\nbbbb", "client_email": "bot@example.com"}')
        vals = secret_values(d)
        assert {
            "s3cretXY",
            "l1-abcd",
            "l2-efgh",
            "aaaa\nbbbb",
            "aaaa",
            "bbbb",
        } <= vals, vals
        # plain config isn't hunted elsewhere (reading .env itself still hides it: redact_kv above)
        assert (
            not {
                "5432",
                "true",
                "pruned-dir",
                "db.internal",
                "test",
                "throwaway_dev42",
                "bot@example.com",
            }
            & vals
        ), vals
        out = "{ DB_PASS: 's3cretXY', host: 'db.internal', port: 5432 }\nl2-efgh\n[REDACTED length=4]\nu/throwaway_dev42: tests pass\n"
        got = deep_redact(out, vals=vals)
        assert got == (
            f"{{ DB_PASS: '{m('s3cretXY')}', host: 'db.internal', port: 5432 }}\n{m('l2-efgh')}\n"
            "[REDACTED length=4]\nu/throwaway_dev42: tests pass\n"
        ), repr(got)
        # the file's own read still hunts every value of it
        assert {"db.internal", "throwaway_dev42"} <= known_values(
            os.path.join(d, ".env")
        ), "read path"

    # whole words only: a value never masks inside a longer word, but still does next to punctuation
    vals = with_encodings({"hunter22"})
    assert mask_values("hunter222 xhunter22", vals) == "hunter222 xhunter22"
    assert mask_values("pw=hunter22;", vals) == f"pw={m('hunter22')};"

    # encoded forms: none of the secret's bytes survive, at any base64 alignment
    secret = 'p@ss"w/rd&<x>Long'
    vals = with_encodings({secret})

    for prefix in ("", "u:", "us:", "use:"):
        blob = base64.b64encode((prefix + secret + ":more-data").encode()).decode()
        got = mask_values(blob, vals)
        assert "[REDACTED" in got, (prefix, got)
        kept = re.sub(ANY_MASK, "", got)
        assert len(kept) <= 12 + len(base64.b64encode(b":more-data")), (
            prefix,
            got,
        )  # only edges remain

    for enc in (
        urllib.parse.quote(secret, safe=""),
        json.dumps(secret)[1:-1],
        html.escape(secret),
        secret.replace('"', '\\"'),
        secret[::-1],
    ):
        assert mask_values(f"x={enc};", vals) == f"x={m(enc)};", enc
    h = secret.encode().hex()

    for dump in (
        h,
        h.upper(),
        h[:8] + "\n" + h[8:],
        " ".join(h[i : i + 2] for i in range(0, len(h), 2)),
    ):
        got = mask_values(
            "00 " + dump + " ff", vals
        )  # xxd -p, xxd -u, wrapped mid-value, od -tx1
        assert got.startswith("00 [REDACTED") and got.endswith("] ff"), (dump, got)
    assert (
        mask_values("hello 68656c6c6f", vals) == "hello 68656c6c6f"
    )  # other hex left alone

    # a file the command names: its detected secrets are masked in any encoding
    with tempfile.TemporaryDirectory() as d:
        tok = "ghp_" + "c" * 36

        with open(os.path.join(d, "app.py"), "w") as f:
            f.write(f'DEBUG = True\nTOKEN = "{tok}"\n')
        vals = command_files("xxd -p app.py | head", d)[1]
        assert tok in vals and tok[::-1] in vals and tok.encode().hex() in vals, vals
        assert "DEBUG" not in vals and command_files("ls -la", d)[1] == set()
        assert m(tok) in mask_values(f'"{tok}" = NEKOT'[::-1], vals)

    print("ok")


if __name__ == "__main__":
    test()
