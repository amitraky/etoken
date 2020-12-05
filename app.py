import os
from flask import Flask, jsonify, flash, request, redirect, url_for,send_from_directory
from werkzeug.utils import secure_filename
import PyKCS11 as PK11
import sys
import datetime
from endesive import pdf, hsm
import os
import requests
from os.path import join, dirname, realpath
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
cors = CORS(app, resources={r"*": {"origins": "*"}})

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOADS_PATH = join(dirname(realpath(__file__)), 'uploads/')
app.config['UPLOAD_FOLDER'] = UPLOADS_PATH
if sys.platform == 'win32':
    dllpath = r'c:\windows\system32\SignatureP11.dll'
else:
    dllpath = '/usr/lib/WatchData/ProxKey/lib/libwdpkcs_SignatureP11.so'



def back_send_to_client(fileUrl,fileName):
    print("calling cb....")
    url = 'http://localhost/api/save_sigend_certificate_cb?file_name='+fileName
    res = requests.post(url, files={'ComplainFileName': open(fileUrl, 'rb'), 'file_name': fileName})
    return "OK"
   
    
    

    
class Singers(hsm.HSM):
    def __init__(self,lib):
        hsm.HSM.__init__(self,lib)
        
class Signer(Singers):   
    def __init__(self,password):
        Singers.__init__(self,dllpath)    
        self.password = password#password
        slot = self.pkcs11.getSlotList(tokenPresent=True)
        token = self.pkcs11.getTokenInfo(slot[0])
        dico = token.to_dict()       
        #self.lable = 'VIVEK GUPTA' #dico.get('label')
        lable =  dico.get('label').replace('\x00','')
        self.lable = str(lable)
        
    def certificate(self):           
        self.login(self.lable, self.password)        
        
        keyid = [0x5e, 0x9a, 0x33, 0x44, 0x8b, 0xc3, 0xa1, 0x35, 0x33,
                 0xc7, 0xc2, 0x02, 0xf6, 0x9b, 0xde, 0x55, 0xfe, 0x83, 0x7b, 0xde]
        # keyid = [0x3f, 0xa6, 0x63, 0xdb, 0x75, 0x97, 0x5d, 0xa6, 0xb0, 0x32, 0xef, 0x2d, 0xdc, 0xc4, 0x8d, 0xe8]
        keyid = bytes(keyid)
        try:
            pk11objects = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                # PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                # PK11.CKA_ISSUER,
                # PK11.CKA_CERTIFICATE_CATEGORY,
                # PK11.CKA_END_DATE,
                PK11.CKA_ID,
            ]
        
            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(
                        pk11object, all_attributes)
                except PK11.PyKCS11Error as e:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                
                cert = bytes(attrDict[PK11.CKA_VALUE])
                # if keyid == bytes(attrDict[PK11.CKA_ID]):
                return bytes(attrDict[PK11.CKA_ID]), cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        self.login(self.lable, self.password)
        try:
            privKey = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY)])[0]
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            return bytes(sig)
        finally:
            self.logout()


def main(filename,signature,password):    

    dates = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = dates.strftime('%Y%m%d%H%M%S+00\'00\'')
    displayDate = dates.strftime('%Y-%m-%d %H:%M:%S %Z%z')
    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "contact": "contac@gmail.com",
        "location": 'India',
        "signingdate": date.encode(),
        "reason": 'Sample sign',
        "signature":signature+displayDate,
        "signaturebox": (10, 0, 200, 100)
    }    
        
    fname = os.path.join(app.config['UPLOAD_FOLDER'],filename)
    datau = open(fname, 'rb').read()   
    try:
        clshsm = Signer(password)
        datas = pdf.cms.sign(datau, dct,
                         None, None,
                         [],
                         'sha256',
                         clshsm,
                         )
    except Exception as e:
        raise ValueError("Please insert DSC or "+str(e))          
        
        
    fname = fname.replace('.pdf', '-signed.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)
        
    return  back_send_to_client(fname,filename)   



    


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        
        if 'file' not in request.files:
            flash('No file part')
            return jsonify({'status': 0, 'filename': 'file is required'})
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            try:
                main(filename,'amit prajapt','12345678')
                message = 'upload success'
            except Exception as e:
                message = 'Error Uploading '+str(e)
            return jsonify({'status': 0, 'filename': message,'location':'http://127.0.0.1:5000/signed/'+filename.replace('.pdf', '-signed.pdf')})

    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''



@app.route('/api/upload', methods=['POST'])
def upload():
        # check if the post request has the file part
    print("Req.............")  
    fileUrl = request.form["url"]
    password = request.form["password"]
    signature = request.form["signature"]
    
    if fileUrl == '':
        return jsonify({'status': 0, 'filename': 'file is required'}) 
    
    pdfUrl = "http://localhost/certificate/"+fileUrl
    r = requests.get(pdfUrl)
    with open(os.path.join(app.config['UPLOAD_FOLDER'],fileUrl),'wb') as f:
        f.write(r.content)  
    filename = fileUrl
    try:
        print("reqeust sending for signeingngn")
        contents = main(filename,signature,password)   
        response = jsonify({'status': 0, "message":"Success",'filename': filename,"data":contents})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response         
        
    except Exception as e:
        message = str(e)
        response = jsonify({'status': 1,"message":message,'filename': filename,"data":""})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response 
    
        
        
    
    
        
        
@app.route('/api/set', methods=['GET'])
def get_tasks():
    print("calling cb....")
    fileName = 'pdfsnsdf.pdf'
    fileUrl = UPLOADS_PATH = join(dirname(realpath(__file__)), 'uploads/')+fileName
    url = 'http://localhost/api/save_sigend_certificate_cb?file_name='+fileName
    res = requests.post(url, files={'ComplainFileName': open(fileUrl, 'rb'), 'file_name': fileName})
    return jsonify({'Error': res.text,"fileUrl":fileUrl})



@app.route('/signed/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

if __name__ == '__main__':
    app.run(debug=True)
