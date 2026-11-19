RESEARCH EXTENSION - START HERE

This is a separate copy. Your original vulnerable and stable apps are unchanged.

1) Open CMD in this folder.
2) Activate the Python environment that already runs your stable app.
3) Run: python -m unittest -v test_security_core.py
4) If tests pass, run: streamlit run app.py
5) Login: userA/userA or userB/userB.

Research features: explicit document-level allow-list policy; chunk owner/document/chunk metadata; independent fail-closed verification before context reaches the LLM; policy hash included in the index cache key; JSONL retrieval audit with candidate IDs, allowed/blocked counts and latency.

To grant access: stop Streamlit and add e.g. userB/Python.pdf to userA's allowed_documents in policy.json. Restart. To revoke, remove it and restart.

The unit tests do not download models. They validate policy, grants, revocation, provenance checks and policy cache invalidation. End-to-end tests and literature comparison are still required before claiming research novelty. Demo credentials are not production authentication.
