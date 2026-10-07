import test from 'node:test';
import assert from 'node:assert/strict';
import {DOCUMENT_TOOLS} from '../scripts/document-tools.mjs';
import {validateArguments} from '../scripts/security-runtime.mjs';
const schema=name=>DOCUMENT_TOOLS.find(t=>t.name===name).inputSchema;
test('Office cell values accept numbers, text and null but reject objects and booleans',()=>{
 for(const value of [3,'=literal',null])validateArguments(schema('office_edit'),{path:'in.xlsx',output:'out.xlsx',cells:[{cell:'A1',value}]});
 for(const value of [{},true])assert.throws(()=>validateArguments(schema('office_edit'),{path:'in.xlsx',output:'out.xlsx',cells:[{cell:'A1',value}]}));
});
test('document schemas bound page counts and reject guessed arguments',()=>{
 assert.throws(()=>validateArguments(schema('pdf_read'),{path:'a.pdf',count:51}));
 assert.throws(()=>validateArguments(schema('office_read'),{path:'a.docx',unknown:true}));
 validateArguments(schema('pdf_write'),{output:'a.pdf',text:'a'.repeat(200000)});
 assert.throws(()=>validateArguments(schema('pdf_write'),{output:'a.pdf',text:'a'.repeat(200001)}));
});
