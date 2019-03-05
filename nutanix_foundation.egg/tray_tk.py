# uncompyle6 version 3.2.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 3.6.5 (v3.6.5:f59c0932b4, Mar 28 2018, 17:00:18) [MSC v.1900 64 bit (AMD64)]
# Embedded file name: foundation/tray_tk.py
# Compiled at: 2019-02-15 12:42:10
import sys, webbrowser
from tkinter import *
from tkinter import ttk
import cherrypy
from foundation import folder_central as fc
from foundation import foundation_tools
from foundation.foundation_tools import subprocess

class FoundationControlPanel:

    def __init__(self, master, version):
        self.version = version
        self.master = master
        master.title('Foundation %s' % self.version)
        self._init_menu()
        port = cherrypy.server.socket_port
        self.url = 'http://localhost:%s/' % port
        Label(master, text='Foundation is running at').pack()
        link = Label(master, text=self.url, fg='blue', cursor='hand2')
        link.pack()
        link.bind('<Button-1>', lambda _: self.do_open(self.url))
        Button(master, text='Quit', command=master.quit).pack()

    def _init_menu(self):
        menu = Menu(self.master)
        self.master.config(menu=menu)
        filemenu = Menu(menu)
        menu.add_cascade(label='File', menu=filemenu)
        filemenu.add_separator()
        filemenu.add_command(label='Open AOS Folder', command=lambda : self.do_open_folder(fc.get_nos_folder()))
        filemenu.add_command(label='Open Hypervisor Folder', command=lambda : self.do_open_folder(fc.get_hypervisor_isos_folder('')))
        filemenu.add_command(label='Open Log Folder', command=lambda : self.do_open_folder(fc.get_log_folder()))
        filemenu.add_separator()
        filemenu.add_command(label='Exit', command=self.master.quit)

    def do_open(self, link):
        webbrowser.open_new_tab(link)

    def do_open_folder(self, path):
        openers = {'darwin': 'open', 
           'win32': 'explorer', 
           'linux2': 'xdg-open'}
        opener = openers.get(sys.platform, '')
        subprocess.call([opener, path])


def start():
    root = Tk()
    root.attributes('-topmost', True)
    root.minsize(200, 50)
    version = foundation_tools.read_foundation_version()
    gui = FoundationControlPanel(root, version)
    root.mainloop()