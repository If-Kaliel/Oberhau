# Local Qwen drafts

Ollama defaults to `http://127.0.0.1:11434` and `qwen3.5:4b`. Settings accepts only loopback HTTP
origins without credentials, paths, queries or fragments. There is no cloud endpoint, paid account,
redirect or proxy support. Actual qwen3.5:4b inference was verified on the local RTX 4060, including
a Portuguese report with recorded evidence unchanged. Timing varies with model loading/workload.

Start the installed Ollama application yourself. Diagnostics checks its model list. Acquiring a
missing model is a separate free download, never triggered silently. Oberhau does not install
startup services or automatically start Ollama.

Generate with Qwen is manual. A thread lock and Windows named mutex serialize Oberhau generations
across local Windows processes; other Ollama clients are outside this coordination. Queue waits
are bounded and cancellable. POSIX uses only the process-local lock. Requests use temperature 0,
`think=false`, a strict Pydantic JSON schema, at most 6,000 UTF-8 bytes of redacted evidence,
8,192 context tokens and 1,200 generated tokens. JSON fields remain structurally valid when reduced.
`keep_alive=0` requests unloading after generation. This is a bounded context policy; model-aware
token accounting, full chunking and per-sentence evidence citations remain pending.

The client follows the official [Ollama chat API](https://docs.ollama.com/api/chat). Connectivity,
timeouts, incomplete output and invalid schemas use deterministic report fallback. HTTP body reads
poll cancellation/deadlines, including Connection: close responses. Cancellation closes the client;
server-side generation shutdown depends on Ollama's behavior. Generated commands never execute.

Only selected evidence fields, reviewed notes, explicit advisory IDs, source integrity, bounded
Python slices and recorded validation facts are sent after redaction. Scanner strings/comments
remain untrusted data. New CVE/GHSA identifiers and URLs absent from explicit evidence are rejected;
source comments alone cannot authorize those claims. These checks constrain selected claims, not
all factual accuracy. AI prose remains provisional and requires human review. It never changes
authorization, source/test records, finding status, rewards or submissions.
