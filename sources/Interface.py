from tkinter import *
from tkinter import ttk
import tkinter.font as TkFont
from tkinter.messagebox import *
from tkinter.filedialog import *

from PIL import ImageTk,Image
from CreateDB import CreateDB
from Extract import Extract
import os

PATH_TO_DB = "../SQLITEDB/CVEDB.db"
PATH_TO_RAW_DB = "../../RawDB/advisories/github-reviewed"


class Interface:
    def __init__(self):
            self.listCVESite = []
            self.db = CreateDB(PATH_TO_DB)
            self.site = {}
            self.nbCVE = 0

    def createDB(self):
        if os.path.exists(PATH_TO_DB):
                os.remove(PATH_TO_DB)
                print("The previous db was removed")
        self.db = CreateDB(PATH_TO_DB) #r"../SQLITEDB/CVEDB.db"
        self.db.getRawDB(PATH_TO_RAW_DB) # C:/Users/blood/source/repos/RawDB/advisory-database/advisories/github-reviewed
        self.db.addTabDB()

    def ExtractPackages(self,path):
        print(path)
        self.site = Extract(path)
        self.site.getPackages()
        print("Number of packages extracted from your website : "+ str(self.site.nbPackage))

    def getPath2(self,default_download_folder,root):
        """ get a path

            :param default_download_folder: path to the file package-lock.json
            :param root: tkinter root
        """
        folder_selected = askopenfilename(parent=root, initialdir=default_download_folder, title="Select your package-lock.json file")
        default_download_folder = folder_selected
        return

    def app(self):
        """ Main fonction off the tkinter app


        """
    
        root = Tk()

        root.title("WebNmap")
    
        root.option_add('*foreground', 'black')
        root.tk.call("source", "azure.tcl")
        root.tk.call("set_theme", "dark")
        root.minsize(700, 800)
        menubar = Menu(root)
        root.config(menu=menubar)
        menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="About",command=lambda :showinfo("About", "Version 0.1\n Author : Enzo Barrier"))
        font1 = TkFont.Font(family= "Lucida Handwriting",size=32)
        root.grid_columnconfigure(0, weight=1)
        Label(root, text = "WebNmap",font =font1,foreground="white").grid(column=0, row=0 )
        canvas = Canvas(root,width = 100, height = 100)      
        canvas.grid(column=0, row=1 )
        #img= (Image.open("visuels/logo.png"))     
        #resized_image= img.resize((100,100), Image.ANTIALIAS)
        #new_image= ImageTk.PhotoImage(resized_image)
        #canvas.create_image(50,00, anchor=N, image=new_image)  
        tabControl = ttk.Notebook(root, width=1500, height=700)
        tabControl.grid(row=3)
        s = ttk.Style(root)
        s.configure("TNotebook", tabposition='n')
        onglet1 = Frame(tabControl)
        onglet1_2 = Frame(tabControl)
        onglet2 = Frame(tabControl)
        onglet3 = Frame(tabControl)
        onglet4 = Frame(tabControl)
        tabControl.add(onglet1, text='CreateDB')
        tabControl.add(onglet1_2, text='Extract')
        tabControl.add(onglet2, text='Analyze')
        tabControl.add(onglet3, text='Extract')
        

        onglet1.grid_columnconfigure(0, weight=1)
        font2 = TkFont.Font(family= "Microsoft YaHei",size=20)
        font3 = TkFont.Font(family= "Microsoft YaHei",size=16)
        font4 = TkFont.Font(family= "Microsoft YaHei",size=8)
        ttk.Label(onglet1, text = "Create a DB based on Online Raw database Advisory Database ",font =font2,foreground="white").grid(column=0, row=0)
        link=ttk.Entry(onglet1, width=30, font=font3)
        link.grid(column=0, row=2)
        B1 = ttk.Button(onglet1, text ="Create Database", command = lambda: self.createDB())
        B1.grid(column=0, row=4)

        onglet1_2.grid_columnconfigure(0, weight=1)
        ttk.Label(onglet1_2, text = "Extract Package from your website",font =font2,foreground="white").grid(column=0, row=0)
        default_file = ""
        default_file = "../AppTest/"

        B30 = ttk.Button(onglet1_2, text ="Select your package-lock.json", command = lambda: self.getPath2(default_file,root))
        B30.grid(column=0, row=1)
        ttk.Label(onglet1_2, textvariable = default_file,font =font3,foreground="grey").grid(column=0, row=2)
        B50 = ttk.Button(onglet1_2, text ="Start", command = lambda: self.ExtractPackages(default_file))
        B50.grid(column=0, row=3, pady=20)


        
       
        root.bind("<Escape>",lambda :root.destroy())
        root.mainloop()
