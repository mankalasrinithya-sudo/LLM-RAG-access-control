import tempfile, unittest
from pathlib import Path
from types import SimpleNamespace
from security_core import default_policy,list_authorized_documents,verify_authorized_chunks,policy_signature

class ACLTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
  for u,n in [("userA","A.pdf"),("userB","B.pdf")]:
   (self.root/u).mkdir(); (self.root/u/n).write_bytes(b"pdf")
  self.policy=default_policy(self.root,["userA","userB"])
 def tearDown(self): self.tmp.cleanup()
 def chunk(self,owner,did): return SimpleNamespace(metadata={"owner":owner,"doc_id":did,"chunk_id":"c1"},page_content="test")
 def test_own_document_allowed(self):
  fs,ids=list_authorized_documents("userA",self.root,self.policy); self.assertEqual([p.name for p in fs],["A.pdf"]); self.assertEqual(ids,{"userA/A.pdf"})
 def test_cross_user_denied(self):
  _,ids=list_authorized_documents("userA",self.root,self.policy); ok,no=verify_authorized_chunks([self.chunk("userB","userB/B.pdf")],"userA",ids); self.assertEqual(ok,[]); self.assertEqual(len(no),1)
 def test_explicit_grant_allowed(self):
  self.policy["users"]["userA"]["allowed_documents"].append("userB/B.pdf"); fs,ids=list_authorized_documents("userA",self.root,self.policy); ok,no=verify_authorized_chunks([self.chunk("userB","userB/B.pdf")],"userA",ids); self.assertEqual(len(ok),1); self.assertEqual(no,[])
 def test_revocation_takes_effect(self):
  a=self.policy["users"]["userA"]["allowed_documents"]; a.append("userB/B.pdf"); self.assertIn("userB/B.pdf",list_authorized_documents("userA",self.root,self.policy)[1]); a.remove("userB/B.pdf"); self.assertNotIn("userB/B.pdf",list_authorized_documents("userA",self.root,self.policy)[1])
 def test_bad_provenance_fails_closed(self):
  _,ids=list_authorized_documents("userA",self.root,self.policy); ok,no=verify_authorized_chunks([self.chunk("userA","userB/B.pdf")],"userA",ids); self.assertEqual(ok,[]); self.assertEqual(len(no),1)
 def test_policy_change_changes_hash(self):
  h=policy_signature(self.policy); self.policy["users"]["userA"]["allowed_documents"].append("userB/B.pdf"); self.assertNotEqual(h,policy_signature(self.policy))
if __name__=="__main__": unittest.main(verbosity=2)
