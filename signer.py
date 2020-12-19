import sys
import datetime
from endesive import pdf, hsm

import os
import sys

dllpath = 'c:\windows\system32\SignatureP11.dll'
import OpenSSL
import PyKCS11 as PK11
import binascii
from Crypto.Cipher import AES
import string
import re


class Signer(hsm.HSM):
    def __init__(self,dll):
        self.name = ''
        super().__init__(dll)
        self.certificate()
        
    def certificate(self):
        print("singer *******************")
       # print(self.pkcs11.getSlotList(tokenPresent=True))
        #print(self.pkcs11.getTokenInfo(57348))
        #print(self.pkcs11.getTokenInfo(16385))
#        print(self.pkcs11.getTokenInfo(2))
    
        #self.login("WD PROXKey","12345678")
        self.login("VIVEK GUPTA","12345678")
        
        # slots = self.pkcs11.getSlotList(tokenPresent=True)
        # for s in slots:
        #     t = self.pkcs11.getTokenInfo(s)
        #     session = self.pkcs11.openSession(s)
        #     objects = self.session.findObjects([(PK11.CKA_LABEL, "00000103000003A1")])
        #     print ("Found %d objects: %s" % (len(objects), [x.value() for x in objects]))
        keyid = [0x5e, 0x9a, 0x33, 0x44, 0x8b, 0xc3, 0xa1, 0x35, 0x33, 0xc7, 0xc2, 0x02, 0xf6, 0x9b, 0xde, 0x55, 0xfe, 0x83, 0x7b, 0xde]
        #keyid = [0x3f, 0xa6, 0x63, 0xdb, 0x75, 0x97, 0x5d, 0xa6, 0xb0, 0x32, 0xef, 0x2d, 0xdc, 0xc4, 0x8d, 0xe8]
        keyid = bytes(keyid)
        try:
            pk11objects = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_CERTIFICATE)])
            all_attributes = [
                PK11.CKA_SUBJECT,
                PK11.CKA_VALUE,
                #PK11.CKA_ISSUER,
                #PK11.CKA_CERTIFICATE_CATEGORY,
                #PK11.CKA_END_DATE,
                PK11.CKA_ID,
            ]
            
            for pk11object in pk11objects:
                try:
                    attributes = self.session.getAttributeValue(pk11object, all_attributes)
                except PK11.PyKCS11Error as e:
                    continue

                attrDict = dict(list(zip(all_attributes, attributes)))
                
                print(str(bytearray(attrDict[PK11.CKA_SUBJECT],'windows-1252')))
                print("ssssssssss")
                
                dataRead = dict()
                cert = bytes(attrDict[PK11.CKA_VALUE])
                subject = bytes(attrDict[PK11.CKA_SUBJECT])
                #value = bytes(attrDict[PK11.CKA_VALUE])
                #dataRead['x'] = subject.decode('utf-8')
                #cipher_encrypt = AES.new(subject, AES.MODE_CBC,iv)
                st = str(subject.decode('windows-1252'))
                printable = set(string.printable)
                x = re.sub(r'[^\x00-\x7f]',r'', st)   
                
                end_string = ''.join(i for i in x if i in printable)
                owner_name = end_string.split('0U')[-1];
                self.name = owner_name
                #print(owner_name)

                
                
                # if attrDict[PK11.CKA_CERTIFICATE_CATEGORY] == (0x2, 0x0, 0x0, 0x0):
                #     continue

                # x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1,str(bytearray(attrDict[PK11.CKA_VALUE])))

                
                # dataRead['subject'] = subject.decode("windows-1252").strip()
                # dataRead['value'] = value.decode("windows-1252").strip()
               # end = bytes(attrDict[PK11.CKA_END_DATE])
               
                
               
                #if keyid == bytes(attrDict[PK11.CKA_ID]):
                return bytes(attrDict[PK11.CKA_ID]), cert
        finally:
            self.logout()
        return None, None

    def sign(self, keyid, data, mech):      
        self.login("VIVEK GUPTA","12345678")
        
        try:
            privKey = self.session.findObjects([(PK11.CKA_CLASS, PK11.CKO_PRIVATE_KEY)])[0]          
            mech = getattr(PK11, 'CKM_%s_RSA_PKCS' % mech.upper())
            sig = self.session.sign(privKey, data, PK11.Mechanism(mech, None)) 
            return bytes(sig)
        
        finally:
            self.logout()
     
    def getSubject(self):
        print("OK")
        return self.name        

def main():
   
    dates = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
    date = dates.strftime('%Y%m%d%H%M%S+00\'00\'')
    displayDate = dates.strftime('%Y-%m-%d %H:%M:%S %Z%z')
    dct = {
        "sigflags": 3,
        "sigpage": 0,
        "sigbutton": True,
        "contact": "x@c.com",
        "location": 'India',
        "sigandcertify":True,
        "signingdate": date.encode(),
        "reason": 'Sample sign',
        "signature": 'Digitally Signed by:$name \n Reason:Sample sign \n Location:India \n Date: '+displayDate,
        "signature_img":'ok.jpg',
        "signaturebox": (10, 0, 200, 100)
    }
    clshsm = Signer(dllpath)
    fname = 'sample.pdf'
    datau = open(fname, 'rb').read()
    dct['signature'] = dct['signature'].replace("$name",clshsm.getSubject())
    
    #print(dct['signature'])
    datas = pdf.cms.sign(datau, dct,
        None, None,
        [],
        'sha256',
        clshsm
    )
    print("Signed Success")
    fname = fname.replace('.pdf', '-signed.pdf')
    with open(fname, 'wb') as fp:
        fp.write(datau)
        fp.write(datas)


main()




