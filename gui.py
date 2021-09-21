import os
from tkinter import *
from tkinter import filedialog,ttk
import json
import sys
app = Tk()
class Management:

    def tokenDLLconfiration(self):
        data = self.getTokenDetails()
        tokenTypeList = ['--Choose USB Token Type--',"EPass","Watchdata PROXkey","Cryptocard"]
        tokenDir = ['']
        self.example = ttk.Combobox(app,values=tokenTypeList,width=50)
        #print(dict(example))
        self.example.grid(column=0, row=0, pady=5,padx=5)
        self.example.current(data['index'])
        self.example.bind("<<ComboboxSelected>>", self.selectTokenDrvier)

        # Part
        part_text = StringVar()
        self.part_entry = Entry(app, textvariable=part_text,width=53)
        self.part_entry.grid(row=1, column=0)
        self.part_entry.insert(0,data['pathFile'])
        # Customer

        add_btn = Button(app, text='Browse', width=12, command=self.UploadAction)
        add_btn.grid(row=1, column=2, pady=5)
        result = Button(app, text = "Submit",width=12,command=self.finalSubmit).grid(column=0,row = 3,padx=5)
        
        
        
        
    def UploadAction(self,event=None):
        filename =  filedialog.askopenfilename(initialdir = "C:\Windows\System32",title = "Select A  File",filetype = (("dll","*.dll"),("All Files","*.*")))
        self.part_text.set(filename)
        print('Selected:', filename)

    def finalSubmit(self):
        print("Submited success")
        app.destroy()
        
    

    def getTokenDetails(self):
        f = open('./token.json',)
        data =  json.load(f)
        f.close()
        return data

    def setTokenDetails(self,data):
        with open('./token.json', 'w') as json_file:
            json.dump(data, json_file)

    def selectTokenDrvier(self,event):
        sys.stdout.flush()

        isFile = None
        pathFile = ""
        index = ""
        tokenType = self.example.get()
        self.part_entry.delete(0,END)
        
        if(tokenType == 'EPass'):
            pathFile = 'c:\windows\system32\eps2003csp11.dll'
            isFile =  os.path.isfile(pathFile)
            index = 1   

        if(tokenType == 'Watchdata PROXkey'):
            pathFile = 'c:\windows\system32\SignatureP11.dll'
            isFile =  os.path.isfile(pathFile)
            index = 2      

        if(tokenType == 'Cryptocard'):
            pathFile = 'c:\windows\system32\libgtop11dotnet.dll'
            isFile =  os.path.isfile(pathFile)
            index = 3      
        
        if(isFile == True):
            self.part_entry.insert(0,pathFile)
        
        self.setTokenDetails({
            "token":tokenType,
            "pathFile":pathFile,
            "index":index
        })

    def close_win(self):
        print(self.password.get())
        app.destroy()

    def enterPassword(self):
        #Set the geometry of frame
        
        app.title('Enter Password')
        app.geometry('450x120')
        Label(app,text="Enter USB Token Password", font=('Helvetica',10)).pack(pady=10)

        #Create Entry Widget for password
        self.password= Entry(app,show="*",width=40)
        self.password.pack()

        #Create a button to close the window
        Button(app, text="Submit", font=('Helvetica bold',
        10),width=20,command=self.close_win).pack(pady=20)
        # Start program
        app.mainloop()

    def main(self):
        app.title('Configure your token details')
        app.geometry('450x120')
        self.tokenDLLconfiration()
        # Start program
        app.mainloop() 
        return self.getTokenDetails()

