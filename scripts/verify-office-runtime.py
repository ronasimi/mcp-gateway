#!/usr/bin/python3
"""Build-time integration gate for the actual LibreOffice/PDF dependencies."""
import importlib.util, pathlib, tempfile, os
spec=importlib.util.spec_from_file_location('worker',pathlib.Path(__file__).with_name('office-documents.py'))
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
with tempfile.TemporaryDirectory() as tmp:
    root=pathlib.Path(tmp);os.environ['MCP_WORKSPACE']=tmp
    for ext in ['.doc','.docx','.odt','.xls','.xlsx','.ods','.ppt','.pptx','.odp']:
        kind=w.FAMILIES[ext];source=root/('input'+ext)
        with w.Office() as office:
            doc=office.load({'text':'private:factory/swriter','sheet':'private:factory/scalc','slides':'private:factory/simpress'}[kind],False)
            if kind=='text':doc.getText().setString('Original text')
            elif kind=='sheet':doc.getSheets().getByIndex(0).getCellRangeByName('A1').setValue(5)
            else:
                pages=doc.getDrawPages()
                if not pages.getCount():pages.insertNewByIndex(0)
                shape=doc.createInstance('com.sun.star.drawing.TextShape');pages.getByIndex(0).add(shape);shape.setString('Original text')
            doc.storeToURL(source.as_uri(),w.props(FilterName=w.OFFICE[ext],Overwrite=True))
        edit={'path':source.name,'output':'edited'+ext}
        if kind=='sheet':edit['cells']=[{'cell':'A1','value':7},{'cell':'B1','formula':'=A1*2'},{'cell':'C1','value':'=literal'}]
        else:edit['replacements']=[{'find':'Original','replace':'Updated','expected_count':1}]
        w.main({'action':'office_edit','arguments':edit})
        result=w.main({'action':'office_read','arguments':{'path':edit['output']}})
        if kind=='text':assert 'Updated' in result['text'],result
        elif kind=='slides':assert 'Updated' in str(result['slides']),result
        else:
            assert result['display_values'][0][:3]==['7','14','=literal'],result
        w.main({'action':'office_export','arguments':{'path':edit['output'],'output':ext[1:]+'.pdf'}})
        assert w.main({'action':'pdf_read','arguments':{'path':ext[1:]+'.pdf'}})['page_count']>0
    w.main({'action':'pdf_write','arguments':{'output':'created.pdf','text':'First page\fSecond page'}})
    w.main({'action':'pdf_write','arguments':{'mode':'assemble','sources':[{'path':'created.pdf','pages':[2,1],'rotate':90}],'output':'assembled.pdf'}})
    assert w.main({'action':'pdf_read','arguments':{'path':'assembled.pdf'}})['page_count']==2
print('Office runtime verified: nine input/edit formats, PDF exports, PDF creation and assembly')
