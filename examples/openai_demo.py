"""Concrete demo: an agent calls OpenAI without ever holding the API key.

    python examples/openai_demo.py

The agent requests an embedding. A human approves it (with TOTP). The vault
leases the OpenAI key into a buffer, makes the call internally, and returns
only the embedding result — the agent never sees `sk-...`.

Runs offline (stubbed transport). The comment in `embed` marks where a live
run would call api.openai.com.
"""

from _demo_lib import Scenario, run


def embed(key_buf: bytearray) -> str:
    # key_buf is the live OpenAI key, only inside the vault boundary.
    # A live run would do, e.g.:
    #     headers = {"Authorization": "Bearer " + key_buf.decode()}
    #     r = httpx.post("https://api.openai.com/v1/embeddings",
    #                    headers=headers, json={"model": "text-embedding-3-small",
    #                                           "input": "rgt-vault"})
    #     return f"embedding dim={len(r.json()['data'][0]['embedding'])}"
    auth_header = "Bearer " + key_buf.decode()
    assert auth_header.startswith("Bearer sk-")  # proves the real key was used
    return "embedding vector returned (dim=1536)"


SCENARIO = Scenario(
    service="OpenAI",
    agent="research-agent",
    secret_title="OpenAI Production Key",
    secret_value="sk-demo000111222333444555666777888999",
    note="prod key, embeddings + chat",
    capability="openai_embeddings",
    purpose="Embed a document for semantic search",
    request_fields={"Model": "text-embedding-3-small", "Input": "1 document"},
    use_secret=embed,
)


if __name__ == "__main__":
    raise SystemExit(run(SCENARIO))
