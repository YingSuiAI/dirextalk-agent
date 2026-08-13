# Real persistent Worker acceptance

`real-worker-driver.sh` is the reusable destructive acceptance driver for the
current Message Server + Agent stack. It uses only owner-facing Product actions
for credential, conversation, confirmation, Worker, and record mutations. AWS
CLI is used with one explicit profile only to resolve credentials in memory and
to independently read back the exact caller account, EC2 instance, key pair,
and security group identities.

The driver refuses to start when the account already has a retained Worker or
more than one AWS credential. It creates and later deletes a credential only
when none existed. An existing credential must already be verified at its
current revision, match the explicit AWS profile account, and use the requested
region. It never prints or writes credential values.

## Required environment

- `DIREXTALK_ACCEPTANCE_HTTP_BASE`: Message Server origin, for example
  `https://s2.example.test`.
- `DIREXTALK_ACCEPTANCE_OWNER_ACCESS_TOKEN`, or
  `DIREXTALK_ACCEPTANCE_SESSION_FILE` containing `access_token`.
- `DIREXTALK_ACCEPTANCE_AWS_PROFILE`: exact AWS CLI profile. The driver never
  uses the implicit default profile.
- `DIREXTALK_ACCEPTANCE_RECEIPT`: absolute final receipt path. Set by
  `run-current-stack.sh`.
- `DIREXTALK_ACCEPTANCE_RUN_DIR`: absolute protected evidence directory. Set by
  `run-current-stack.sh`.

Optional:

- `DIREXTALK_ACCEPTANCE_AWS_REGION` (default `ap-east-1`).
- `DIREXTALK_ACCEPTANCE_MODEL_PROFILE_ID` when a particular compatible
  `openai_compatible` conversation profile should be used. Without it the
  stable first compatible profile ID is selected.
- `DIREXTALK_ACCEPTANCE_REAL_WORKER_TIMEOUT_SECONDS` (60..7200, default 1200).

Run it through the complete acceptance batch:

```bash
scripts/acceptance/run-current-stack.sh \
  --real-worker-driver "$PWD/scripts/acceptance/real-worker-driver.sh"
```

The two actual tasks use the official durable `agent.chat.stream` WebSocket
route. All other calls use `POST /_p2p/query`. The first task must expose and
receive the exact priced confirmation, return a verified artifact containing a
new marker, and leave one idle Worker with live server load. The second task
must automatically reuse that exact Worker with a zero-priced plan and no
pending creation confirmation. The driver then destroys only that exact Worker
through `agent.workers.destroy` and independently waits for exact EC2, key pair,
and security group absence.

No receipt is written until every check and owned-record cleanup succeeds. On
failure the driver attempts cleanup only for the conversation, credential, and
exact eight-field Worker identity it created. If a confirmed AWS mutation has
not yielded a public exact Worker identity, it preserves records and fails
rather than guessing or deleting by name. This path does not call S3, request an
EIP, use KMS, or choose a custom AMI.
