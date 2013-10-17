import wx
from threading import *
from socket import *

def serverThreadFun():
	serverSocket = socket(AF_INET,SOCK_STREAM)
        serverPort = int(frame.port.GetValue())
        serverSocket.bind(('',serverPort))
        serverSocket.listen(1)
	
	
	for i in range(10):
		if(frame.abort_thread==1):
			frame.abort_thread==0
			frame.working = 0
			self.SetStatusText("The server has been shutdown")
			return
		connectionSocket, addr = serverSocket.accept()
                sentence = connectionSocket.recv(2048)
		frame.DR.ChangeValue(sentence)
		drd = decryption(sentence)
		if (drd == "Authenticated!"):
			frame.lblAuth.SetLabel("Authenticated")
			connectionSocket.send("Authenticated")
		frame.DRD.ChangeValue(drd)
                connectionSocket.close()

def decryption(recString):
	k1 = int(frame.SSV1.GetValue())
	k2 = int(frame.SSV2.GetValue())
	serverRSA = RSA_module(k1,k2)
	decrypedString = ""
	temp =""
	for i in range(0,len(recString)):
		if(recString[i]=="."):
			decrypedString = decrypedString + serverRSA.rsaDecrypt(int(temp))
			temp =""
		elif(recString[i]=="!"):
			index = recString.index("$")
			authInt = int(recString[(i+1):index])
			if((authInt/k1)==k2):
				return "Authenticated!"
		else:
			temp = temp + recString[i]
	return decrypedString
class RSA_module(object):
	def __init__(self,p1,p2):
		self.p1 = p1;
		self.p2 = p2;
		self.e = 3;
		self.n = p1*p2;
		self.phi = (p1-1)*(p2-1);
		self.d = (2*(self.phi)+1)/3;
	
	
	def rsaEncrypt(self, m):
		m = ord(m)
		c = (m**self.e)%self.n
		return c
	
	def rsaDecrypt(self, c):
		m = (c**self.d)%self.n;
		m = chr(m);
		return m;



class MainWindow(wx.Frame):
	def __init__(self, parent, title):
		wx.Frame.__init__(self, parent, title=title,size=(220,500))

		self.CreateStatusBar() # A Statusbar in the bottom of the window

		# Setting up the menu.
		filemenu= wx.Menu()

		# wx.ID_ABOUT and wx.ID_EXIT are standard IDs provided by wxWidgets.
		menuToggle = filemenu.Append(wx.ID_ABOUT, "&Toggle"," Toggle Server/Client")
		filemenu.AppendSeparator()
		menuExit = filemenu.Append(wx.ID_EXIT,"E&xit"," Terminate the program")

		# Creating the menubar.
		menuBar = wx.MenuBar()
		menuBar.Append(filemenu,"&File") # Adding the "filemenu" to the MenuBar
		self.SetMenuBar(menuBar)  # Adding the MenuBar to the Frame content.

		self.Bind(wx.EVT_MENU, self.OnToggle, menuToggle)
		self.Bind(wx.EVT_MENU, self.OnExit, menuExit)
		self.clientServerToggle = 0 #Default to client
		self.mainSizer = wx.BoxSizer(wx.VERTICAL)
		self.panel = wx.Panel(self, wx.ID_ANY)

		 # create the labels
		
		lblPort = wx.StaticText(self.panel, label="Port:", size=(70,-1))
		lblIP = wx.StaticText(self.panel, label="Server IP:", size=(70,-1))
		lblSSV = wx.StaticText(self.panel, label="Secret Shared Value", size=(70,-1))
		lblDS = wx.StaticText(self.panel, label="Data to Send:", size=(70,-1))
		lblDR = wx.StaticText(self.panel, label="Data Recieved:", size=(70,-1))
		lblDRD = wx.StaticText(self.panel, label="Data Decrypted:", size=(70,-1))
		self.lblAuth = wx.StaticText(self.panel, label="UnAuthenticated", size=(120,-1))
        # create the text controls
	        self.port = wx.TextCtrl(self.panel)
		self.IP = wx.TextCtrl(self.panel, size=(120,-1))
		self.SSV1 = wx.TextCtrl(self.panel, size=(40,-1))
		self.SSV2 = wx.TextCtrl(self.panel, size=(40,-1))
		self.DS = wx.TextCtrl(self.panel)
		self.DR = wx.TextCtrl(self.panel, style=wx.TE_MULTILINE, size=(120, 40))
		self.DRD = wx.TextCtrl(self.panel, style=wx.TE_MULTILINE, size=(120, 40))
		
        # create some sizers
		modeTitleSizer = wx.BoxSizer(wx.HORIZONTAL)
        	lineOneSizer = wx.BoxSizer(wx.HORIZONTAL)
       		lineTwoSizer = wx.BoxSizer(wx.HORIZONTAL)
        	lineThreeSizer = wx.BoxSizer(wx.HORIZONTAL)
		lineFourSizer = wx.BoxSizer(wx.HORIZONTAL)
		lineFiveSizer = wx.BoxSizer(wx.HORIZONTAL)
		lineSixSizer = wx.BoxSizer(wx.HORIZONTAL)
		authButtonSizer = wx.BoxSizer(wx.HORIZONTAL)
		authSizer = wx.BoxSizer(wx.HORIZONTAL)
		buttonSizer = wx.BoxSizer(wx.HORIZONTAL)
	
	# create buttons
		self.toggleButton = wx.Button(self.panel, label="Client Mode", size=(120,-1))
		self.Bind(wx.EVT_BUTTON, self.OnToggle,self.toggleButton)
		self.authButton = wx.Button(self.panel, label="Authenticate",size=(120,-1))
		self.Bind(wx.EVT_BUTTON, self.OnClickAuth,self.authButton)		
		self.sendButton = wx.Button(self.panel, label="Send",size=(100,-1))
		self.Bind(wx.EVT_BUTTON, self.OnClick,self.sendButton)
	# add widgets to sizers
		modeTitleSizer.Add(self.toggleButton, 0, wx.ALL|wx.ALIGN_LEFT, 5)
		self.mainSizer.Add(modeTitleSizer)
        	lineOneSizer.Add(lblPort, 0, wx.ALL|wx.ALIGN_LEFT, 5)
        	lineOneSizer.Add(self.port, 0, wx.ALL, 5)
		self.mainSizer.Add(lineOneSizer)
        	lineTwoSizer.Add(lblIP, 0, wx.ALL|wx.ALIGN_LEFT, 5)
        	lineTwoSizer.Add(self.IP, 0, wx.ALL, 5)
		self.mainSizer.Add(lineTwoSizer)
        	lineThreeSizer.Add(lblSSV, 0, wx.ALL|wx.ALIGN_LEFT, 5)
		lineThreeSizer.Add(self.SSV1, 0, wx.ALL|wx.ALIGN_LEFT, 2)
		lineThreeSizer.Add(self.SSV2, 0, wx.ALL, 2)
		self.mainSizer.Add(lineThreeSizer)
		authButtonSizer.Add(self.authButton, 0, wx.ALIGN_LEFT|wx.ALL, 5)
		self.mainSizer.Add(authButtonSizer)
		authSizer.Add(self.lblAuth, 0, wx.ALIGN_LEFT|wx.ALL, 5)
		self.mainSizer.Add(authSizer)
		lineFourSizer.Add(lblDS, 0, wx.ALL|wx.ALIGN_LEFT, 5)
        	lineFourSizer.Add(self.DS, 0, wx.ALL, 5)
		self.mainSizer.Add(lineFourSizer)
		lineFiveSizer.Add(lblDR, 0, wx.ALL|wx.ALIGN_LEFT, 5)
        	lineFiveSizer.Add(self.DR, 0, wx.ALL, 5)		
		self.mainSizer.Add(lineFiveSizer)
		lineSixSizer.Add(lblDRD, 0, wx.ALL|wx.ALIGN_LEFT, 5)
		lineSixSizer.Add(self.DRD, 0, wx.ALL,5)
		self.mainSizer.Add(lineSixSizer)
		buttonSizer.Add(self.sendButton, 0, wx.ALIGN_CENTER|wx.ALL, 5)
		self.mainSizer.Add(buttonSizer)
		self.panel.SetSizer(self.mainSizer)		
		self.Show()
		

	def OnToggle(self,e):
		if(self.clientServerToggle==0):
			self.toggleButton.SetLabel("Server Mode")
			self.sendButton.SetLabel("Start/Stop")
			self.clientServerToggle=1
			self.working = 0
		else:
			self.toggleButton.SetLabel("Client Mode")
			self.sendButton.SetLabel("Send")
			self.clientServerToggle=0
	def OnExit(self,e):
		self.Close(True)
			
	def convertRSA(self):
		sentence = self.DS.GetValue()
		p1 = int(self.SSV1.GetValue())
		p2 = int(self.SSV2.GetValue())
		clientRSA = RSA_module(p1,p2)
		mymsg = []
		for i in range(0,len(sentence)):
			mymsg.append(str(clientRSA.rsaEncrypt(sentence[i])))
			mymsg.append(".")
		return mymsg
	def OnClickAuth(self,e):
		if(self.clientServerToggle==0):
			p1 = int(self.SSV1.GetValue())
			p2 = int(self.SSV2.GetValue())			
			clientRSA = RSA_module(p1,p2)
			serverName = self.IP.GetValue()
			serverPort = int(self.port.GetValue())
			clientSocket = socket(AF_INET, SOCK_STREAM)
			clientSocket.connect((serverName,serverPort))
			clientSocket.send("!"+str(clientRSA.n) + "$")
			authSentence = clientSocket.recv(1024)
			if(len(authSentence)>0):
				self.lblAuth.SetLabel("Authenticated")
			clientSocket.close()	
	def OnClick(self,e):
		if(self.clientServerToggle==0):
			serverName = self.IP.GetValue()
			serverPort = int(self.port.GetValue())
			encryptedMsg = self.convertRSA()
			
			clientSocket = socket(AF_INET, SOCK_STREAM)
			clientSocket.connect((serverName,serverPort))
			for i in range(0,len(encryptedMsg)):
				clientSocket.send(encryptedMsg[i])
			clientSocket.close()
			self.SetStatusText("Message Sent")

		else:
			if not self.working:
            			self.working = 1
				self.abort_thread = 0
				self.serverThread = Thread(target=serverThreadFun)
        			self.serverThread.start()
				self.SetStatusText("The server is ready to recieve")
        			e.Skip()
			else:
				self.abort_thread=1
	                        frame.working = 0
        	                self.SetStatusText("The server has been shutdown")

app = wx.App(False)
frame = MainWindow(None, "VPN - Group 2")
app.MainLoop()