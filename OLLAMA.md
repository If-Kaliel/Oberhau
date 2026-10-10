# Local Qwen drafts

Ollama defaults to `http://127.0.0.1:11434` and `qwen3.5:4b`. Settings accepts only loopback HTTP
origins without credentials, paths, queries or fragments. There is no cloud endpoint, paid account,
network redirect or proxy support. The initial environment has an Ollama executable, but its API
was not responding during verification; real model inference has not yet been verified.

Start the already installed Ollama application yourself. If the model is installed, diagnostics
will show it. Acquiring a missing model is a separate free download and is never triggered silently.
The program does not install startup services or start Ollama for you.

Generate with Qwen is manual. Requests are serialized within the Oberhau process, low-temperature,
bounded to 12,000 input characters / 8,192 context tokens / 1,200 generated tokens, with a strict
Pydantic JSON schema. `keep_alive=0` requests unloading after each generation. This is a bounded
context policy rather than model-aware token accounting; full chunking/token estimation is pending.

The client follows the official [Ollama chat API](https://docs.ollama.com/api/chat). Timeout,
connectivity failures and malformed/schema-invalid responses use deterministic reporting fallback.
Cancellation closes the client connection via a watchdog; server-side generation shutdown depends
on Ollama's connection handling. The app never executes generated commands.

Only selected title, location, status, explanation, excerpt and notes are sent, after redaction.
Source comments and scanner strings are untrusted evidence. The schema has no authorization,
execution, reward or confirmation fields. Reports place AI prose under provisional explanation;
stored source/test facts always come from deterministic records. AI prose can still be wrong and
must be reviewed; prompt text is not a guarantee against hallucination.
