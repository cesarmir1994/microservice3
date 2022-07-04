path = '/usr/local/lib/python3.6/dist-packages/docx2txt/docx2txt.py'
with open(path,'r') as f:
    script = f.readlines()
 
with open(path,'w') as f:
    for i,line in enumerate(script):
        if i == 86:
            line = "    doc_xml = [re.findall('(word\/document.*)',fn)[0] for fn in filelist if len(re.findall('(word\/document.*)',fn)) > 0][0]\n"
        f.write(line)
