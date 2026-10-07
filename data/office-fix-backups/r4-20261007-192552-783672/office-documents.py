#!/usr/bin/python3
"""Isolated LibreOffice/PDF worker. Requests and responses are JSON over stdio."""
import json, os, sys, tempfile, subprocess, time, uuid, pathlib, shutil

OFFICE={'.doc':'MS Word 97','.docx':'Office Open XML Text','.odt':'writer8',
        '.xls':'MS Excel 97','.xlsx':'Calc MS Excel 2007 XML','.ods':'calc8',
        '.ppt':'MS PowerPoint 97','.pptx':'Impress MS PowerPoint 2007 XML','.odp':'impress8'}
FAMILIES={'.doc':'text','.docx':'text','.odt':'text','.xls':'sheet','.xlsx':'sheet','.ods':'sheet','.ppt':'slides','.pptx':'slides','.odp':'slides'}

def bounded(value, default, minimum, maximum):
    value=default if value is None else value
    if type(value) is not int or not minimum<=value<=maximum: raise ValueError('integer outside supported bounds')
    return value

def confined(root, name, exists=False):
    if not isinstance(name,str) or not name or '\0' in name: raise ValueError('workspace-relative path required')
    p=pathlib.Path(name)
    if p.is_absolute() or '..' in p.parts: raise ValueError('absolute paths and traversal are rejected')
    p=(root/p).resolve()
    if not p.is_relative_to(root): raise ValueError('symlink escapes workspace')
    if exists and not p.is_file(): raise ValueError('input file not found')
    return p

def publish(temp, output, overwrite):
    # Atomic and no-clobber by default, including concurrent requests.
    if overwrite: os.replace(temp,output)
    else: os.link(temp,output); os.unlink(temp)
    os.chmod(output,0o640)

def props(**values):
    import uno
    out=[]
    for k,v in values.items():
        p=uno.createUnoStruct('com.sun.star.beans.PropertyValue');p.Name=k;p.Value=v;out.append(p)
    return tuple(out)

class Office:
    def __enter__(self):
        import uno
        self.uno=uno;self.tmp=tempfile.mkdtemp(prefix='mcp-office-');self.doc=None
        pipe='mcp_'+uuid.uuid4().hex
        self.proc=subprocess.Popen(['libreoffice','--headless','--nologo','--nodefault','--nofirststartwizard','--norestore',
            '-env:UserInstallation='+pathlib.Path(self.tmp).as_uri(), '--accept=pipe,name='+pipe+';urp;StarOffice.ComponentContext'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        local=uno.getComponentContext();resolver=local.ServiceManager.createInstanceWithContext('com.sun.star.bridge.UnoUrlResolver',local)
        deadline=time.monotonic()+20
        try:
            while True:
                try: ctx=resolver.resolve('uno:pipe,name='+pipe+';urp;StarOffice.ComponentContext');break
                except Exception:
                    if self.proc.poll() is not None or time.monotonic()>deadline:raise RuntimeError('LibreOffice failed to start')
                    time.sleep(.1)
            self.desktop=ctx.ServiceManager.createInstanceWithContext('com.sun.star.frame.Desktop',ctx)
            return self
        except BaseException:self.__exit__(None,None,None);raise
    def load(self,source,readonly=True):
        url=str(source) if str(source).startswith('private:factory/') else pathlib.Path(source).as_uri()
        self.doc=self.desktop.loadComponentFromURL(url,'_blank',0,props(Hidden=True,ReadOnly=readonly,MacroExecutionMode=0,UpdateDocMode=0))
        if self.doc is None:raise ValueError('LibreOffice could not open document (encrypted or unsupported file)')
        return self.doc
    def __exit__(self,*args):
        try:
            if self.doc:self.doc.dispose()
        finally:
            self.proc.terminate()
            try:self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait()
            shutil.rmtree(self.tmp,ignore_errors=True)

def family(doc):
    for service,name in [('com.sun.star.text.TextDocument','text'),('com.sun.star.sheet.SpreadsheetDocument','sheet'),('com.sun.star.presentation.PresentationDocument','slides')]:
        if doc.supportsService(service):return name
    raise ValueError('unsupported Office document type')

def texts(shape):
    if hasattr(shape,'getString'):yield shape.getString()
    if hasattr(shape,'getCount') and hasattr(shape,'getByIndex'):
        for i in range(shape.getCount()):yield from texts(shape.getByIndex(i))

def sheet(doc,name):
    sheets=doc.getSheets()
    if name is None:return sheets.getByIndex(0)
    if not sheets.hasByName(name):raise ValueError('sheet not found: '+name)
    return sheets.getByName(name)

def office_read(doc,a):
    kind=family(doc);limit=bounded(a.get('max_chars'),30000,100,50000)
    if kind=='text':
        text=doc.getText().getString();return {'kind':kind,'text':text[:limit],'truncated':len(text)>limit,'note':'Main document text; use PDF rendering for layout, headers, footers and embedded objects.'}
    if kind=='sheet':
        s=sheet(doc,a.get('sheet'));area=s.getCellRangeByName(a.get('range','A1:T50'));addr=area.getRangeAddress()
        rows=addr.EndRow-addr.StartRow+1;cols=addr.EndColumn-addr.StartColumn+1
        if rows>200 or cols>50:raise ValueError('read range exceeds 200 rows or 50 columns')
        values=[];formulas=[];remaining=limit;truncated=False
        for r in range(rows):
            row=[];formula=[]
            for c in range(cols):
                cell=area.getCellByPosition(c,r);t=cell.getString();f=cell.getFormula() if cell.getType().value=='FORMULA' else None
                if len(t)+len(f or '')>remaining:truncated=True;break
                row.append(t);formula.append(f);remaining-=len(t)+len(f or '')
            if truncated:break
            values.append(row);formulas.append(formula)
        return {'kind':kind,'sheets':list(doc.getSheets().getElementNames()),'sheet':s.getName(),'range':a.get('range','A1:T50'),'display_values':values,'formulas':formulas,'truncated':truncated,'note':'Only requested range returned; formulas are not refreshed from external links.'}
    pages=doc.getDrawPages();start=bounded(a.get('start'),1,1,max(1,pages.getCount()));count=bounded(a.get('count'),10,1,30);result=[];remaining=limit
    for i in range(start-1,min(start-1+count,pages.getCount())):
        t='\n'.join(texts(pages.getByIndex(i)));result.append({'slide':i+1,'text':t[:remaining]});remaining-=min(len(t),remaining)
        if remaining==0:break
    return {'kind':kind,'slide_count':pages.getCount(),'slides':result,'next_slide':start+len(result) if start+len(result)<=pages.getCount() else None,'truncated':remaining==0,'note':'Shape text only; charts, images and notes require visual review.'}

from office_replaceable import replace_document_text

def office_edit(doc,a):
    kind=family(doc);changes=0
    replacements=a.get('replacements',[]);cells=a.get('cells',[])
    if not replacements and not cells:raise ValueError('provide replacements or cells')
    if len(replacements)>100 or len(cells)>1000:raise ValueError('too many edits')
    if kind=='sheet' and replacements:raise ValueError('spreadsheet edits use cells, not replacements')
    if kind!='sheet' and cells:raise ValueError('cells apply only to spreadsheets')
    for item in replacements:
        if not isinstance(item.get('find'),str) or not item['find'] or not isinstance(item.get('replace'),str):raise ValueError('nonempty find and string replace required')
        found=doc.findAll(descriptor).getCount()
        expected=item.get('expected_count')
        if expected is not None and (type(expected) is not int or expected<0 or found!=expected):raise ValueError('replacement count mismatch; no output saved')
        if not found:raise ValueError('replacement text not found; no output saved')
        changes+=replace_document_text(doc, item['find'], item['replace'])
    for item in cells:
        import re
        if not re.fullmatch(r'[A-Za-z]{1,3}[1-9][0-9]{0,6}',item.get('cell','')):raise ValueError('single A1 cell address required')
        cell=sheet(doc,item.get('sheet')).getCellRangeByName(item['cell'])
        if ('formula' in item)==('value' in item):raise ValueError('provide exactly one of value or formula')
        if 'formula' in item:
            f=item['formula']
            if not isinstance(f,str) or not f.startswith('='):raise ValueError('formula must start with =')
            cell.setFormula(f)
        else:
            v=item['value']
            if v is None:cell.setString('')
            elif type(v) in (float,int):cell.setValue(v)
            elif isinstance(v,str):cell.setString(v)
            else:raise ValueError('cell value must be text, number or null')
        changes+=1
    return changes

def pdf_read(source,a):
    try:from pypdf import PdfReader
    except ImportError:from PyPDF2 import PdfReader
    r=PdfReader(str(source));start=bounded(a.get('start'),1,1,max(1,len(r.pages)));count=bounded(a.get('count'),10,1,50);limit=bounded(a.get('max_chars'),30000,100,50000);pages=[];truncated=False
    for i in range(start-1,min(start-1+count,len(r.pages))):
        t=r.pages[i].extract_text() or '';pages.append({'page':i+1,'text':t[:limit]});truncated=len(t)>limit;limit-=min(len(t),limit)
        if not limit:break
    return {'page_count':len(r.pages),'pages':pages,'truncated':truncated,'next_page':start+len(pages) if start+len(pages)<=len(r.pages) else None,'note':'Text extraction only; scanned pages require OCR. No OCR performed.'}

def pdf_write(temp,a,root):
    if a.get('mode','create')=='create':
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,PageBreak
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from xml.sax.saxutils import escape
        text=a.get('text')
        if not isinstance(text,str) or not text or len(text)>200000:raise ValueError('provide 1–200000 characters of text')
        font='/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
        pdfmetrics.registerFont(TTFont('Document',font));style=getSampleStyleSheet()['Normal'];style.fontName='Document';style.fontSize=11;style.leading=15
        flow=[]
        for index,page in enumerate(text.split('\f')):
            if index:flow.append(PageBreak())
            for paragraph in page.split('\n\n'):flow.extend([Paragraph(escape(paragraph).replace('\n','<br/>'),style),Spacer(1,8)])
        SimpleDocTemplate(str(temp),title=a.get('title','')).build(flow)
        return
    if a['mode']!='assemble':raise ValueError('mode must be create or assemble')
    try:from pypdf import PdfReader,PdfWriter
    except ImportError:from PyPDF2 import PdfReader,PdfWriter
    sources=a.get('sources',[])
    if not sources or len(sources)>30:raise ValueError('provide 1–30 PDF sources')
    writer=PdfWriter();total=0
    for item in sources:
        r=PdfReader(str(confined(root,item['path'],True)));indices=item.get('pages',list(range(1,len(r.pages)+1)));angle=item.get('rotate',0)
        if angle not in (0,90,180,270):raise ValueError('rotation must be 0, 90, 180 or 270')
        for n in indices:
            if type(n) is not int or n<1 or n>len(r.pages):raise ValueError('invalid 1-based PDF page')
            total+=1
            if total>1000:raise ValueError('output exceeds 1000 pages')
            import copy
            page=copy.copy(r.pages[n-1])
            if angle:page.rotate(angle)
            writer.add_page(page)
    if not total:raise ValueError('no pages selected')
    with open(temp,'wb') as out:writer.write(out)

def main(request):
    root=pathlib.Path(os.environ.get('MCP_WORKSPACE','/workspace')).resolve();action=request['action'];a=request['arguments']
    source=confined(root,a['path'],True) if 'path' in a else None
    if action=='pdf_read':return pdf_read(source,a)
    output=confined(root,a['output']) if 'output' in a else None
    if output:
        if output.exists() and not a.get('overwrite',False):raise ValueError('output exists; choose another path or set overwrite=true')
        if source==output or any(confined(root,item['path'],True)==output for item in a.get('sources',[])):raise ValueError('use a separate output copy')
        output.parent.mkdir(parents=True,exist_ok=True)
    temp=None
    try:
        if output:
            fd,name=tempfile.mkstemp(suffix=output.suffix,dir=output.parent);os.close(fd);temp=pathlib.Path(name)
        if action=='pdf_write':
            if output.suffix.lower()!='.pdf':raise ValueError('PDF output must end in .pdf')
            pdf_write(temp,a,root);result={}
        else:
            if source.suffix.lower() not in OFFICE:raise ValueError('supported inputs: DOC/DOCX/ODT, XLS/XLSX/ODS, PPT/PPTX/ODP')
            with Office() as office:
                doc=office.load(source,action=='office_read')
                if action=='office_read':return office_read(doc,a)
                if action not in ('office_edit','office_export'):raise ValueError('unknown action')
                kind=family(doc);ext=output.suffix.lower()
                if ext=='.pdf' and action=='office_export':filter_name={'text':'writer_pdf_Export','sheet':'calc_pdf_Export','slides':'impress_pdf_Export'}[kind]
                else:
                    if FAMILIES.get(ext)!=kind:raise ValueError('output must belong to the same Office family, or PDF for export')
                    filter_name=OFFICE[ext]
                result={'changes':office_edit(doc,a)} if action=='office_edit' else {}
                doc.storeToURL(temp.as_uri(),props(FilterName=filter_name,Overwrite=True))
                result['warning']='LibreOffice may alter complex formatting or unsupported features. Review the output; macros are disabled and external links are not refreshed.'
        publish(temp,output,a.get('overwrite',False));temp=None
        return {'ok':True,'output':str(output.relative_to(root)),**result}
    finally:
        if temp and temp.exists():temp.unlink()

if __name__=='__main__':
    try:print(json.dumps(main(json.load(sys.stdin)),ensure_ascii=False))
    except Exception as e:print(json.dumps({'error':str(e)}));sys.exit(1)
