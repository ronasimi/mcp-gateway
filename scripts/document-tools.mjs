import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const str=description=>({type:'string',description});
const integer=(description,minimum,maximum)=>({type:'integer',description,minimum,maximum});
const object=(properties,required=[])=>({type:'object',properties,required,additionalProperties:false});
const tool=(name,description,properties,required)=>({name,description,inputSchema:object(properties,required)});
const path=str('Workspace-relative input file.');
const output=str('Workspace-relative output copy; original input is preserved.');
const overwrite={type:'boolean',description:'Replace an existing output file; default false. Input and output must differ.'};
const max_chars=integer('Maximum returned text characters; default 30000. Narrow range/pages when truncated.',100,50000);
export const DOCUMENT_TOOLS=[
 tool('pdf_read','Read PDF text by page with bounded pagination. Scanned images require separate OCR; this tool does not perform OCR.',{path,start:integer('First page, 1-based; default 1.',1,100000),count:integer('Pages to read; default 10.',1,50),max_chars},['path']),
 tool('pdf_write','Create a PDF from plain text, or assemble PDFs by merging, selecting, reordering and rotating pages. Does not rewrite existing PDF text.',{output,overwrite,mode:{type:'string',enum:['create','assemble'],description:'create (default): text to PDF; assemble: source pages to PDF.'},text:{...str('Plain text for create; blank lines separate paragraphs, form feed separates pages. Maximum 200000 characters.'),maxLength:200000},title:str('Optional title for a new PDF.'),sources:{description:'PDF inputs with optional page selections and rotations.',type:'array',minItems:1,maxItems:30,items:object({path,pages:{type:'array',minItems:1,maxItems:1000,items:integer('1-based page number.',1,100000),description:'Ordered page selection; omitted means all pages.'},rotate:{type:'integer',enum:[0,90,180,270],description:'Clockwise rotation; default 0.'}},['path'])}},['output']),
 tool('office_read','Read Microsoft Office or OpenDocument files: DOC/DOCX/ODT text, XLS/XLSX/ODS cell ranges and formulas, PPT/PPTX/ODP slide text. Uses LibreOffice; macros disabled.',{path,max_chars,sheet:str('Spreadsheet sheet name; default first sheet.'),range:str('Spreadsheet A1 range; default A1:T50, maximum 200 rows by 50 columns.'),start:integer('First slide, 1-based; default 1.',1,100000),count:integer('Slides to read; default 10.',1,30)},['path']),
 tool('office_edit','Edit an Office/OpenDocument copy: literal text replacements in Writer/presentations, or explicit spreadsheet cell values/formulas. Retains supported formatting through LibreOffice; review complex layouts.',{path,output,overwrite,replacements:{description:'Ordered literal text replacements; each must match.',type:'array',minItems:1,maxItems:100,items:object({find:str('Nonempty case-sensitive literal text.'),replace:str('Replacement text.'),expected_count:integer('Optional exact number of matches; mismatch cancels output.',0,100000)},['find','replace'])},cells:{description:'Explicit spreadsheet cell edits; supply value or formula per cell.',type:'array',minItems:1,maxItems:1000,items:object({sheet:str('Sheet name; default first sheet.'),cell:str('Single A1 cell address.'),value:{type:['string','number','null'],description:'Literal value; strings beginning with = remain text. Null clears the cell.'},formula:str('Formula starting with =; supply instead of value.')},['cell'])}},['path','output']),
 tool('office_export','Export an Office/OpenDocument file to PDF or another format in the same document family using LibreOffice. Supports DOC/DOCX/ODT, XLS/XLSX/ODS and PPT/PPTX/ODP.',{path,output,overwrite},['path','output'])
];
let active=0;
export function callDocumentTool(name,args,workspace){
 if(active>=2)return Promise.reject(Error('Document workers busy; retry after current document operations finish'));
 active++;
 const action={pdf_read:'pdf_read',pdf_write:'pdf_write',office_read:'office_read',office_edit:'office_edit',office_export:'office_export'}[name];
 return new Promise((resolve,reject)=>{
  const child=spawn('/usr/bin/python3',[fileURLToPath(new URL('./office-documents.py',import.meta.url))],{env:{...process.env,MCP_WORKSPACE:workspace},detached:true,stdio:['pipe','pipe','pipe']});
  let stdout='',stderr='',bytes=0,done=false;
  const kill=()=>{try{process.kill(-child.pid,'SIGKILL');}catch{}};
  const finish=(err,value)=>{if(done)return;done=true;active--;clearTimeout(timer);kill();err?reject(err):resolve(value);};
  const timer=setTimeout(()=>finish(Error('Document operation timed out after 120 seconds')),120000);
  child.on('error',e=>finish(e));child.stdin.on('error',()=>{});
  for(const [stream,isError] of [[child.stdout,false],[child.stderr,true]])stream.on('data',data=>{bytes+=data.length;if(bytes>8*1024*1024)return finish(Error('Document output exceeded limit'));if(isError)stderr+=data;else stdout+=data;});
  child.on('close',code=>{try{const r=JSON.parse(stdout);if(code||r.error)finish(Error(r.error||stderr||'Document operation failed'));else finish(null,r);}catch(e){finish(Error(stderr||e.message));}});
  child.stdin.end(JSON.stringify({action,arguments:args}));
 });
}
