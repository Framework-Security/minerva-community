import pdfkit
import shutil
from datetime import datetime
import fnmatch
import fileinput
import matplotlib.pyplot as plt

scopeflag = 0
vulnflag = 0
vpageflag = []

def parseGen(toRead):
    with open(toRead,"r") as file:
        data = file.read().replace("\n","")
    sections = data.split('}')
    sections = list(filter(None, sections))
    toRet = []
    for section in sections:
        section = section.split("{")
        for subsect in section:
            if "ptype=" in subsect or "full-title=" in subsect:
                section = subsect.split(";")
        if len(section) == 2:
            section[1].replace(";","")
        section = list(filter(None, section))
        toRet.append(section)
    return toRet

def add(conf, db):
    toRet = [0,0,0,0,0,0]
    for i in range(2, len(conf)):
        toRet[0] += int(getC(conf[0][i]))
        current = "short-title="+getT(conf[0][i])
        ranking = getC(db[grabIdx(db, current)[0]][2])
        if ranking == "Critical":
            toRet[1] += int(getC(conf[0][i]))
        elif ranking == "High":
            toRet[2] += int(getC(conf[0][i]))
        elif ranking == "Medium":
            toRet[3] += int(getC(conf[0][i]))
        elif ranking == "Low":
            toRet[4] += int(getC(conf[0][i]))
        elif ranking == "Information":
            toRet[5] += int(getC(conf[0][i]))
        else:
            print("user error, check config & db")
    return toRet

def genVPage(fName, ranking, impact, remediation, details, banner, num):
    global vpageflag
    if banner in details:
        vpageflag[num] += details.count(banner)
    start = '''
    <div style = "display:block; clear:both; page-break-after:always;"></div>
    <img src="''' + banner + '''">
    <div class="sHeader"><strong>''' + fName + '''</strong></div>
    <div class="sib"><span class="''' + ranking[0].lower() + '''">Severity - ''' + ranking + '''</span></div>
    <br>
    <div class="sib">Details</div>
    <div class="sText">''' + details + '''</div>
    <br>
    <div class="sib">Impact</div>
    <div class="sText">''' + impact + '''</div>
    <br>
    <div class="sib">Remediation</div>
    <div class="sText">''' + remediation + '''</div>
    '''

    return start

def genVTable(conf, db, total):
    global vulnflag
    resultList = []
    resultDict = {}
    for item in conf[0][2:]:
        itemList = item.split('=')
        name = itemList[0]
        print(itemList)
        value = int(itemList[1])
        if name in resultDict:
            resultDict[name] += value
        else:
            resultDict[name] = value
    for name, value in resultDict.items():
        resultList.append(f"{name}={value}")

    start = '''
    <table>
    <tr>
    <th>Vulnerability</th>
    <th>Severity</th>
    <th>Occurrences</th>
    </tr>
    '''
    for val in resultList:
        vName = getC(db[grabIdx(db, "short-title="+getT(val))[0]][1])
        sName = getC(db[grabIdx(db, "short-title="+getT(val))[0]][2])
        oName = getC(val)
        start += '''
    <tr>
	<td>''' + vName + '''</td>
	<td>''' + sName + '''</td>
	<td>''' + oName + '''</td>
	</tr>
        '''
    start += '''
    </table>
    </div>
    '''
    start += '<br><div class="sText"> Total = ' + str(total) + '</div>'
    return start

def genSTable(config):
    global scopeflag
    docount=18
    isdocount=0
    start = '''
    <table>
    <tr>
    <th>IP/Hostname</th>
    <th>Special Notes</th>
    </tr>
    '''
    c = 1
    config[1] = config[1][1].split(";")
    config[1] = list(filter(None, config[1]))
    for val in config[1][1:]:
        if c >= docount:
            if not isdocount:
                docount += 16
                isdocount = 1
            start += '''
            </table>
            </div>
            <div style = "display:block; clear:both; page-break-after:always;"></div>
            <img src="the_rest_of_the_path/resources/banner.png">
            <div class="sHeader"><strong>Scope Cont.</strong></div>
            <div class="scopeTable">
            <table>
            <tr>
            <th>IP/Hostname</th>
            <th>Special Notes</th>
            </tr>
            '''
            c = 1
            scopeflag += 1
        name = val.rsplit("=",1)[0]
        notes = val.rsplit("=",1)[1]
        if notes:
            print("Remember to modify the Statement of Limitations!")
        start += '''
        <tr>
        <td>''' + name + '''</td>
        <td>''' + notes + '''</td>
        '''
        c += 1
    start += '''
    </table>
    </div>'''
    return start

def genToc(config, db):
    global scopeflag
    global vulnflag
    count = 3
    c = 1
    tocset = 0
    offset = scopeflag + vulnflag + 37
    if len(config[0][2:]) < offset:
        tocset = 0
    else:
        tocset += offset//len(config[0][2:]) + (offset % len(config[0][2:]) > 0)
        offset += tocset

    l = ['Executive Summary', 'Disclaimer, Statement of Limitations, Testing Narrative & Project Team', 'Objectives & Scope', 'Assessment Methodology', 'Vulnerability Ranking Chart, CVE & CWE', 'Vulnerability Listings']
    start = '''
    <div class="sText">
    '''
    for i in range(len(l)):
        if tocset:
            count += 1
            tocset -= 1
            i-=1
            continue
        start += l[i] + '<div class="num">' + str(count) + '</div><br>\n'
        if scopeflag and l[i] == 'Objectives & Scope':
            count+=scopeflag
        if vulnflag and l[i] == 'Vulnerability Listings':
            count += vulnflag
        count += 1

    icount = count
    vulnc = 0
    for title in config[0][2:]:
        if c >= offset:
            offset+=icount
            start += '''
                </div>
                </div>
                <div style = "display:block; clear:both; page-break-after:always;"></div>
                <img src="the_rest_of_the_path/resources/banner.png">
                <div class="sHeader"><strong>Table of Contents Cont.</strong></div>
                <div class="tocTable">
                <div class="sText">
            '''
            c = 1
        ct = getC(db[grabIdx(db, "short-title="+getT(title))[0]][1])
        start += ct + '<div class="num">' + str(count) + '</div><br>\n'
        if vpageflag[vulnc]:
            count += vpageflag[vulnc]
        count += 1
        vulnc += 1
        c += 1
    start += 'Appendix <div class="num">' + str(count) + '</div><br>\n'

    start += '''
    </div>'''

    return start


def appendix(config, banner, pType):
    apiT = {"Fill in" : "your toolset"}
    web = {"Fill in" : "your toolset"}
    network = {"Fill in" : "your toolset"}
    mobile = {"Fill in" : "your toolset"}
    sca = {"Fill in" : "your toolset"}
    prev = 0
    start = '''
    <div style = "display:block; clear:both; page-break-after:always;"></div>
    <img src="''' + banner + '''">
    <div class="sHeader"><strong>Appendix</strong></div>
    
    '''
    if "api" in pType.lower():
        start += '''<div class="sib"><strong>API Testing Tools</strong></div>
        <div class="sText">
        '''
        for key, value in apiT.items():
            start += '<div class="apxT">'+key+"</div>"+value+"<br>"
        start += "</div><br>"
        prev += 1
    if "web" in pType.lower():
        if prev:
            start += '''
            <div style = "display:block; clear:both; page-break-after:always;"></div>
            <img src="''' + banner + '''">
            <div class="sHeader"><strong>Appendix</strong></div>
            '''
        start += '''<div class="sib"><strong>Web Testing Tools</strong></div>
        <div class="sText">
        '''
        for key, value in web.items():
            start += '<div class="apxT">'+key+"</div>"+value
        start += "</div>"
        prev += 1
    if "mobile" in pType.lower() or "ios" in pType.lower() or "android" in pType.lower():
        if prev:
            start += '''
            <div style = "display:block; clear:both; page-break-after:always;"></div>
            <img src="''' + banner + '''">
            <div class="sHeader"><strong>Appendix</strong></div>
            '''
        start += '''<div class="sib"><strong>Mobile Testing Tools</strong></div>
        <div class="sText">
        '''
        for key, value in mobile.items():
            start += '<div class="apxT">'+key+"</div>"+value+"<br>"
        start += "</div>"
    if "network" in pType.lower():
        if prev:
            start += '''
            <div style = "display:block; clear:both; page-break-after:always;"></div>
            <img src="''' + banner + '''">
            <div class="sHeader"><strong>Appendix</strong></div>
            '''
        start += '''<div class="sib"><strong>Network Testing Tools</strong></div>
        <div class="sText">
        '''
        for key, value in network.items():
            start += '<div class="apxT">'+key+"</div>"+value+"<br>"
        start += "</div><br>"
        prev += 1
    if "source code" in pType.lower():
        if prev:
            start += '''
            <div style = "display:block; clear:both; page-break-after:always;"></div>
            <img src="''' + banner + '''">
            <div class="sHeader"><strong>Appendix</strong></div>
            '''
        start += '''<div class="sib"><strong>Source Code Analysis Tooling</strong></div>
        <div class="sText">
        '''
        for key, value in sca.items():
            start += '<div class="apxT">'+key+"</div>"+value+"<br>"
        start += "</div><br>"
        prev += 1

    return start

def genDonut(ladd):
    olad = ladd[1:]
    ocolor = ["red","orange","yellow","green","blue"]
    oname = ["Critical","High","Medium","Low","Information"]
    color = []
    name = []
    lad = []
    for i in range(len(olad)):
        if olad[i]:
            name.append(oname[i]+" - "+str(olad[i]))
            lad.append(olad[i])
            color.append(ocolor[i])
    plt.rcParams["font.family"] = "Helvetica"
    plt.pie(lad, labels=name, colors=color, wedgeprops={'linewidth' : 3, 'edgecolor' : 'white', 'width':1})

    center=plt.Circle( (0,0), 0.7, color='white')
    p=plt.gcf()
    p.gca().add_artist(center)
    plt.savefig("resources/currplot.png", dpi=500)


def getT(ss):
    return ss.split("=", 1)[0]

def getC(ss):
    return ss.split("=", 1)[1]

def grabIdx(search, value):
    return next((i, j) for i, lst in enumerate(search)
        for j, x in enumerate(lst) if x == value)


config = parseGen("config.txt")
db = parseGen("makeshift-db.txt")

ladd = add(config, db)
genDonut(ladd)

vpageflag = [0] * len(config[2:])

client = getC(config[0][0])
pType = getC(config[0][1])
if "api" in pType.lower():
    print("Modify the methodology, its an API!")
bannerLink = "the_rest_of_the_path/resources/banner.png"

date = datetime.today().strftime('%B %d, %Y')
template = "report.html"
bTemplate = "basic-template.html"
shutil.copyfile(bTemplate,template)

with open(template, 'r') as file:
    data = file.read()

data = data.replace("[pentest type]",pType)
data = data.replace("[client]",client)
data = data.replace("[date]",date)
data = data.replace("[crits]",str(ladd[1]))
data = data.replace("[total]",str(ladd[0]))
data = data.replace("[fname]", config[1][1].split(";")[0])

with open(template, 'w') as file:
    file.write(data)

vTable = genVTable(config, db, ladd[0])
for line in fileinput.FileInput(template, inplace=True):
    if '<div class="vulnTable">' in line:
        line += vTable
    print(line, end="")

sTable = genSTable(config)
for line in fileinput.FileInput(template, inplace=True):
    if '<div class="scopeTable">' in line:
        line += sTable
    print(line, end="")

with open(template, "a") as file:
    for i in range(2, len(config)):
        current = "short-title="+getT(config[i][0])
        odb = db[grabIdx(db, current)[0]]
        file.write(genVPage(getC(odb[1]), getC(odb[2]), getC(odb[3]), getC(odb[4]), getC(config[i][1]), bannerLink, i-2))
    
with open(template, "a") as file:
    file.write(appendix(config, bannerLink, pType))
    file.write("\n</body>\n</html>")

makeToc = genToc(config, db)
for line in fileinput.FileInput(template, inplace=True):
    if '<div class="tocTable">' in line:
        line += makeToc
    print(line, end="")


options = {
    'page-size': 'Letter',
    'margin-top': '0.20in',
    'margin-right': '0.20in',
    'margin-bottom': '0.20in',
    'margin-left': '0.20in',
    'encoding': "UTF-8",
    "enable-local-file-access":"",
    "footer-html":"resources/paging.html"
    }

pdfkit.from_file('report.html', 'out.pdf', options=options, css="resources/styles.css")
