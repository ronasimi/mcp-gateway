import importlib.util, os, pathlib, tempfile, unittest
spec=importlib.util.spec_from_file_location('worker',pathlib.Path(__file__).resolve().parents[1]/'scripts/office-documents.py')
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
class Documents(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.old=os.environ.get('MCP_WORKSPACE');os.environ['MCP_WORKSPACE']=self.tmp.name
 def tearDown(self):
  self.tmp.cleanup()
  if self.old is None:os.environ.pop('MCP_WORKSPACE',None)
  else:os.environ['MCP_WORKSPACE']=self.old
 def call(self,action,**args):return w.main({'action':action,'arguments':args})
 def test_pdf_create_read_select_rotate(self):
  self.call('pdf_write',output='in.pdf',text='First page\fSecond page')
  r=self.call('pdf_read',path='in.pdf',start=2,count=1);self.assertEqual(r['page_count'],2);self.assertIn('Second page',r['pages'][0]['text'])
  self.call('pdf_write',mode='assemble',sources=[{'path':'in.pdf','pages':[2,1,2],'rotate':90}],output='out.pdf')
  r=self.call('pdf_read',path='out.pdf');self.assertEqual(r['page_count'],3);self.assertIn('Second page',r['pages'][0]['text'])
  try:from pypdf import PdfReader
  except ImportError:from PyPDF2 import PdfReader
  self.assertEqual(PdfReader(str(self.root/'out.pdf')).pages[0].get('/Rotate'),90)
 def test_preserve_original_and_existing_output(self):
  self.call('pdf_write',output='in.pdf',text='Original');before=(self.root/'in.pdf').read_bytes()
  with self.assertRaises(ValueError):self.call('pdf_write',output='in.pdf',text='Replace')
  with self.assertRaises(ValueError):self.call('pdf_write',mode='assemble',sources=[{'path':'in.pdf'}],output='in.pdf',overwrite=True)
  self.assertEqual((self.root/'in.pdf').read_bytes(),before)
 def test_invalid_page_leaves_no_output(self):
  self.call('pdf_write',output='in.pdf',text='Original')
  with self.assertRaises(ValueError):self.call('pdf_write',mode='assemble',sources=[{'path':'in.pdf','pages':[99]}],output='out.pdf')
  self.assertFalse((self.root/'out.pdf').exists());self.assertEqual(len(list(self.root.iterdir())),1)
 def test_confined_paths(self):
  for name in ['../outside','/etc/passwd']:
   with self.assertRaises(ValueError):w.confined(self.root,name)
  (self.root/'link').symlink_to('/tmp',target_is_directory=True)
  with self.assertRaises(ValueError):w.confined(self.root,'link/escape.pdf')
 def test_pdf_truncation_is_explicit(self):
  self.call('pdf_write',output='in.pdf',text='Long paragraph '*100)
  result=self.call('pdf_read',path='in.pdf',max_chars=100)
  self.assertTrue(result['truncated']);self.assertEqual(len(result['pages'][0]['text']),100)
if __name__=='__main__':unittest.main()
