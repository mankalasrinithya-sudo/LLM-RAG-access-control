"""Document-level policy, provenance verification and audit helpers."""
import hashlib, json
from pathlib import Path
from typing import Iterable

def default_policy(data_dir: Path, users: list[str]) -> dict:
    return {"users": {u: {"allowed_documents": sorted(f"{u}/{p.name}" for p in (data_dir/u).glob("*.pdf"))} for u in users}}

def load_policy(policy_path: Path, data_dir: Path, users: list[str]) -> dict:
    if not policy_path.exists():
        policy=default_policy(data_dir, users)
        policy_path.write_text(json.dumps(policy,indent=2),encoding="utf-8")
        return policy
    policy=json.loads(policy_path.read_text(encoding="utf-8"))
    if not isinstance(policy.get("users"),dict): raise ValueError("policy.json must contain a users object")
    for u in users:
        policy["users"].setdefault(u,{"allowed_documents":[]})
        a=policy["users"][u].get("allowed_documents",[])
        if not isinstance(a,list) or not all(isinstance(x,str) for x in a): raise ValueError(f"Invalid ACL for {u}")
    return policy

def list_authorized_documents(user: str, data_dir: Path, policy: dict):
    allowed=set(policy["users"].get(user,{}).get("allowed_documents",[])); files=[]; ids=set()
    for folder in data_dir.iterdir():
        if folder.is_dir():
            for p in folder.glob("*.pdf"):
                did=f"{folder.name}/{p.name}"
                if did in allowed: files.append(p); ids.add(did)
    return sorted(files),ids

def verify_authorized_chunks(chunks: Iterable, user: str, allowed_doc_ids: set[str]):
    accepted=[]; blocked=[]
    for chunk in chunks:
        m=getattr(chunk,"metadata",{}) or {}; did=m.get("doc_id"); owner=m.get("owner")
        if not did or not owner or did.split("/",1)[0] != owner or did not in allowed_doc_ids: blocked.append(chunk)
        else: accepted.append(chunk)
    return accepted,blocked

def policy_signature(policy: dict) -> str:
    return hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def append_audit_event(path: Path,event: dict):
    with path.open("a",encoding="utf-8") as f: f.write(json.dumps(event,ensure_ascii=False)+"\n")

def calculate_metrics(events: list[dict]) -> dict:
    lat=[float(e["latency_seconds"]) for e in events if e.get("latency_seconds") is not None]
    return {"total_queries":len(events),"cross_user_attempts":sum(bool(e.get("cross_user_test")) for e in events),"unauthorized_chunks_blocked":sum(int(e.get("blocked_chunk_count",0)) for e in events),"mean_latency_seconds":round(sum(lat)/len(lat),4) if lat else None}
