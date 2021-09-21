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
import string
import re
from asn1crypto import x509
from gui import Management

app = Flask(__name__)
CORS(app)
cors = CORS(app, resources={r"*": {"origins": "*"}})
ob = Management()
data = ob.main()
print(data)
lib = PK11.lib(os.environ['PKCS11_MODULE'])
print(lib)


env = 'dev'
host = 'http://localhost:8000'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOADS_PATH = join(dirname(realpath(__file__)), 'uploads/')
app.config['UPLOAD_FOLDER'] = UPLOADS_PATH

dllpath = data['pathFile'] #proxy

def log(data):
    print(data)
    sys.stdout.flush()

def back_send_to_client(fileUrl,fileName):
    log("calling cb....")
    url = host+'/api/save_sigend_certificate_cb?file_name='+fileName
    res = requests.post(url, files={'ComplainFileName': open(fileUrl, 'rb'), 'file_name': fileName})
    log("Happy bye")
    return "OK"
   
class Singers(hsm.HSM):
    def __init__(self,lib):

        hsm.HSM.__init__(self,lib)
            
class Signer(Singers):   
    def __init__(self,password):
        Singers.__init__(self,dllpath)    
        self.password = password
        slot = self.pkcs11.getSlotList(tokenPresent=True)
        token = self.pkcs11.getTokenInfo(slot[0])
        log(token)
        dico = token.to_dict()      
        lable = str(dico.get('label'))        
        lable = lable.replace('\x00', '')
        lable = lable.strip()
        self.lable = str(lable)
        self.name = ''
        self.certificate()
        
    def certificate(self): 
        log(self.lable)          
        self.login(self.lable, self.password)       
        
        keyid = [0x5e, 0x9a, 0x33, 0x44, 0x8b, 0xc3, 0xa1, 0x35, 0x33,
                 0xc7, 0xc2, 0x02, 0xf6, 0x9b, 0xde, 0x55, 0xfe, 0x83, 0x7b, 0xde]
        # keyid = [0x3f, 0xa6, 0x63, 0xdb, 0x75, 0x97, 0x5d, 0xa6, 0xb0, 0x32, 0xef, 0x2d, 0xdc, 0xc4, 0x8d, 0xe8]
        keyid = bytes(keyid)

        try:            
            pk11objects = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                PK11.CKA_SUBJECT,
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
                cka_value, cka_id = self.session.getAttributeValue(pk11object, [PK11.CKA_VALUE, PK11.CKA_ID])
                subject = bytes(attrDict[PK11.CKA_SUBJECT])                 

                cert_der = bytes(cka_value)
                cert = x509.Certificate.load(cert_der)
                # subject = cert.subject
                # issuer = cert.issuer
                
                printable =  dict(cert['tbs_certificate']['subject'].native)
                owner_full_name = printable['common_name']
                self.name = owner_full_name
                cert = bytes(attrDict[PK11.CKA_VALUE])
                # if keyid == bytes(attrDict[PK11.CKA_ID]):
                return bytes(attrDict[PK11.CKA_ID]), cert
        except PK11.PyKCS11Error as e:
          print("Sorry ! Error")

        finally:            
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):
        log("Signing try ... ")
        self.login(self.lable, self.password)

        try:
            privKey = self.session.findObjects(
                [(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY)])[0]
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None))
            log("Singed success")
            return bytes(sig)
        finally:
            self.logout()
    
    def getSubject(self):
        print("OK")
        return self.name         


def main(filename,signature,password):    


    dates = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = dates.strftime('%Y%m%d%H%M%S+00\'00\'')
    displayDate = dates.strftime('%Y-%m-%d %H:%M:%S %Z%z')
    pdDate = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z%z'))
    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "contact": "contac@gmail.com",
        "location": 'India',
        "sigandcertify": True,
        "signingdate": date.encode(),
        "reason": 'Issue Certificate',
        "signature":signature + pdDate,
        "signaturebox": (10, 10, 90, 40),
        'text': {
            'fontsize': 8,
        }
    }

    fname = os.path.join(app.config['UPLOAD_FOLDER'],filename)
    datau = open(fname, 'rb').read()   
    try:
        clshsm = Signer(password)
        log("Name of Certificate "+clshsm.getSubject())
        dct['signature'] = dct['signature'].replace("$name",clshsm.getSubject())

        datas = pdf.cms.sign(datau, dct,
                         None, None,
                         [],
                         'sha256',
                         clshsm,
                         )
        log("Prepared pdf")                 
    except Exception as e:
        log(str(e))
        raise ValueError("Please insert DSC or "+str(e))          
        
        
    fname = fname.replace('.pdf', '-signed.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)
    log("Signed document ready !")    
    return  back_send_to_client(fname,filename)   


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        
        if 'file' not in request.files:
            log('No file part')
            return jsonify({'status': 0, 'filename': 'file is required'})
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            log('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            try:
                main(filename,'$name','12345678')
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
    
    setyear = datetime.datetime.now()
    pdfUrl = "http://localhost:8000/certificate"+str(setyear.year)+"/"+fileUrl
    print(pdfUrl)
    

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
        
        

if __name__ == '__main__':
    app.run(debug=True)