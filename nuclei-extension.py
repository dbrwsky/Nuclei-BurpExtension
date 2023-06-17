try:
    from burp import IBurpExtender
    from burp import ITab
    from burp import IScanIssue
    from burp import IContextMenuFactory
    from burp import IExtensionStateListener
    from javax.swing import ( JScrollPane, JButton, JPanel, JTextField,
                              JLabel, SwingConstants, Box, JOptionPane,
                              JMenuItem, BoxLayout, JFileChooser, JTextPane, 
                              JTabbedPane )
    from javax.swing.border import EmptyBorder
    from java.awt import (Frame, Component, BorderLayout, FlowLayout, Dimension, Color)
    from java.net import URL
    from java.util import ArrayList
    
    from urlparse import urlparse 
    from threading import Thread
    import subprocess
    import sys
    import shlex
    import os
    import json
    
except ImportError as e:
    print (e)
    
VERSION = '0.4'

reload(sys)
sys.setdefaultencoding('utf-8')
 
class BurpExtender(IBurpExtender, ITab, IScanIssue, IExtensionStateListener):
    
    def __init__(self):
        self.cfgNucleiPath = ''
        self.cfgTemplatesPath = ''
        self.cfgCustomArgs = ''
        self.tabNo = 0


    def registerExtenderCallbacks(self, callbacks):
        print("Loading...")
        self._helpers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._callbacks.setExtensionName("Nuclei")
        self._callbacks.registerExtensionStateListener(self)       
        
        self.scannerMenu = ScannerMenu(self)
        self._callbacks.registerContextMenuFactory(self.scannerMenu)
        
        self._callbacks.addSuiteTab(self)
        self.isBurpPro = True if "Professional" in self._callbacks.getBurpVersion()[0] else False
        
        self.runningSubprocesses = set()
        print("Extension loaded")

    def getTabCaption(self):
        return "Nuclei"

    def getUiComponent(self):
        if self._callbacks.loadExtensionSetting("nucleiPath"):
            self.cfgNucleiPath = str(self._callbacks.loadExtensionSetting("nucleiPath"))
        if self._callbacks.loadExtensionSetting("templatesPath"):
            self.cfgTemplatesPath = str(self._callbacks.loadExtensionSetting("templatesPath"))
        if self._callbacks.loadExtensionSetting("customArgs"):    
            self.cfgCustomArgs = str(self._callbacks.loadExtensionSetting("customArgs"))
        
        self.mainPanel = JPanel(BorderLayout(5,5))
        self.mainPanel.setBorder(EmptyBorder(20, 20, 20, 20))
        
        self.actionPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.actionPanel.add(JLabel("Target:", SwingConstants.LEFT), BorderLayout.LINE_START)
        self.targetField = JTextField('',40)
        self.actionPanel.add(self.targetField)
        self.scanButton = JButton('Run Scanning',actionPerformed=self.startScan)
        self.actionPanel.add(self.scanButton)
        self.closeButton = JButton("Close All Tabs", actionPerformed=self.closeAllTabs)
        self.actionPanel.add(self.closeButton)
        
        self.configPanel = JPanel()
        self.configPanel.layout = BoxLayout(self.configPanel,BoxLayout.PAGE_AXIS)

        
        self.configPanel.add(Box.createRigidArea(Dimension(0, 10)))
        self.labelTest = JLabel("Path to nuclei binary:")
        self.labelTest.setAlignmentX(Component.LEFT_ALIGNMENT)
        self.configPanel.add(self.labelTest)
        
        self.nucleiPathPanel = JPanel()
        self.nucleiPathPanel.layout = BoxLayout(self.nucleiPathPanel,BoxLayout.X_AXIS)
        self.nucleiPathField = JTextField('' + self.cfgNucleiPath,30)
        self.nucleiPathButton = JButton('Browse...',actionPerformed=self.getFile)
        self.nucleiPathPanel.add(self.nucleiPathField)
        self.nucleiPathPanel.add(self.nucleiPathButton)
        self.configPanel.add(self.nucleiPathPanel)
        

        self.configPanel.add(Box.createRigidArea(Dimension(0, 10)))
        self.configPanel.add(JLabel("Path to nuclei templates folder:", SwingConstants.LEFT), BorderLayout.LINE_START)
        
        self.nucleiTemplatesPathPanel = JPanel()
        self.nucleiTemplatesPathPanel.layout = BoxLayout(self.nucleiTemplatesPathPanel,BoxLayout.X_AXIS)
        self.nucleiTemplatesPathField = JTextField('' + self.cfgTemplatesPath ,30)
        self.nucleiTemplatesPathButton = JButton('Browse...',actionPerformed=self.getFile)
        self.nucleiTemplatesPathPanel.add(self.nucleiTemplatesPathField)
        self.nucleiTemplatesPathPanel.add(self.nucleiTemplatesPathButton)
        self.configPanel.add(self.nucleiTemplatesPathPanel)
        
        self.configPanel.add(Box.createRigidArea(Dimension(0, 10)))
        self.configPanel.add(JLabel("Custom nuclei arguments:", SwingConstants.LEFT), BorderLayout.LINE_START)
        self.nucleiCustomArgsField = JTextField('' + self.cfgCustomArgs,30) #-etags fuzz,network -duc -ni -rl 10 -c 5 -proxy http://127.0.0.1:8080
        self.configPanel.add(self.nucleiCustomArgsField)
        self.configPanel.add(Box.createRigidArea(Dimension(0, 10)))
        
        self.mainPanel.add(self.actionPanel, BorderLayout.PAGE_START)
        
        self._bottomPanel = JPanel(BorderLayout(10, 10))
        self._bottomPanel.setBorder(EmptyBorder(10, 0, 0, 0))
            
        self.tabPane = JTabbedPane(JTabbedPane.TOP)

        self.panel2Tab = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        self.panel2Tab.add(self.configPanel, BorderLayout.PAGE_START)
        self.tabPane.addTab("Configuration", self.panel2Tab)     
        
        self._bottomPanel.add(self.tabPane, BorderLayout.CENTER)
        
        self.mainPanel.add(self._bottomPanel, BorderLayout.CENTER)
        
        self.Frames = Frame.getFrames()
        for frame in self.Frames:
            if frame.getName() == "suiteFrame" and  "Burp Suite" in frame.getTitle():
                self.parentFrame = frame
        
        return self.mainPanel
    
    def saveConfig(self):
        self._callbacks.saveExtensionSetting("nucleiPath",str(self.nucleiPathField.text))
        self._callbacks.saveExtensionSetting("templatesPath",str(self.nucleiTemplatesPathField.text))
        self._callbacks.saveExtensionSetting("customArgs",str(self.nucleiCustomArgsField.text))

    def extensionUnloaded(self):
        for p in self.runningSubprocesses:
            p.terminate()
            self.runningSubprocesses.remove(p)
        self.saveConfig()
        print("Extension was unloaded")
        
    def startScan(self, ev):
        host = self.targetField.text
        if(len(host) == 0):
            JOptionPane.showMessageDialog(self.parentFrame, "URL not specified!", "ERROR", JOptionPane.ERROR_MESSAGE) 
            return
        parsedURL = urlparse(host)
        if parsedURL.scheme == 'http':
            if not parsedURL.port: 
                httpService = self._helpers.buildHttpService(str(parsedURL.hostname), 80, False)
            else:    
                httpService = self._helpers.buildHttpService(str(parsedURL.hostname), parsedURL.port, False)    
        elif parsedURL.scheme == 'https':
            if not parsedURL.port:    
                httpService = self._helpers.buildHttpService(str(parsedURL.hostname), 443, True)
            else:
                httpService = self._helpers.buildHttpService(str(parsedURL.hostname), parsedURL.port, True)
        else:
            JOptionPane.showMessageDialog(self.parentFrame, "Invalid URL!", "ERROR", JOptionPane.ERROR_MESSAGE) 
            return
                
        self.scannerThread = Thread(target=self.scan, args=(host, httpService))
        self.scannerThread.start()

    
    def scan(self, url, httpService):
        text=''
        self.tabNo += 1
        scanResultsTextPane = JTextPane()
        scanResultsTextPane.setEditable(False)
        scanResultsTextPane.setContentType("text/html")
        self.scanResultsTab = JPanel(BorderLayout())
        self.scanResultsTab.add(JScrollPane(scanResultsTextPane), BorderLayout.CENTER)
        
        tabActionPanel = JPanel(FlowLayout(FlowLayout.LEADING, 10, 10))
        
        tabActionPanel.add(JLabel("Status: ", SwingConstants.LEFT))
        scanStatusLabel = JLabel("Ready to scan", SwingConstants.LEFT)
        tabActionPanel.add(scanStatusLabel)
        
        tabCloseButton = JButton("Close tab",actionPerformed=self.closeTab)
        tabCloseButton.setForeground(Color.RED)
        tabActionPanel.add(tabCloseButton, BorderLayout.LINE_START)
        
        killProcessButton = JButton("Kill nuclei process",actionPerformed=self.killNuclei)
        killProcessButton.setForeground(Color.RED)
        tabActionPanel.add(killProcessButton, BorderLayout.LINE_START)
        

        title = '['+ str (self.tabNo) +'] ' + url
        self.scanResultsTab.add(tabActionPanel, BorderLayout.PAGE_START)
        self.tabPane.addTab(title,self.scanResultsTab)
        
        cmd = "'" + self.nucleiPathField.text + "' -u " + url + " -t '" + self.nucleiTemplatesPathField.text + "' -j -nc " + self.nucleiCustomArgsField.text
        
        text += "Scanning of " + url + " started<br>" + cmd + "<br>"
        text += "-----------------------------------------------------------<br>"
        scanResultsTextPane.setText(text)

        
        parsedCmd = shlex.split(cmd, posix=True)
        try:
            p = subprocess.Popen(parsedCmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            scanStatusLabel.setText("Scan in progress")
            
            self.runningSubprocesses.add(p)

            killProcessButton.putClientProperty("pid", p.pid)
            killProcessButton.putClientProperty("proc", p)
            
            tabCloseButton.putClientProperty("pid", p.pid)
            tabCloseButton.putClientProperty("proc", p)
             
            for line in iter(p.stdout.readline, b''):
                vuln = line.rstrip()
                text += self.parseNucleiResults(vuln, httpService)
                scanResultsTextPane.setText(text)

            scanStatusLabel.setText("Scan completed")
            self.runningSubprocesses.remove(p)
            
        except Exception as e:
            text += "<p style=\"color:red\"><b> EXCEPTION OCCURED: " + str(e) + "</b></p>"
            scanStatusLabel.setText("ERROR")
            scanResultsTextPane.setText(text)
        
        killProcessButton.setEnabled(False)

    
    def parseNucleiResults(self, results, httpService):
        issues = results.splitlines()
        text = ''
        for issue in issues:
            try:
                finding = json.loads(issue)
                findingName = "[Nuclei] " + finding["info"]["name"]
                findingDesc = "<b>Template ID:</b> " + finding["template-id"] + "<br>"
                if "matcher-name" in finding:
                    findingName += " : " + finding["matcher-name"]
                findingDesc += "<b>Matched-at:</b> "+ finding["matched-at"] + "<br>"
                if "extracted-results" in finding:
                    for item in finding["extracted-results"]:
                        findingName += ": " + item
                        findingDesc += "<b>Extracted data:</b> " + item + "<br>"
                if "description" in finding["info"]:
                    findingDesc += "<b>Description:</b> <br>" + finding["info"]["description"] + "<br>"
                if finding["info"]["reference"]:
                    findingDesc += "<b>References:</b><br> "
                    for item in finding["info"]["reference"]:
                        findingDesc += item + "<br>"  
                if "curl-command" in finding:
                    findingDesc += "<br><b>CURL:</b><br>" + finding["curl-command"]
                findingSeverity = "Information"
                if (finding["info"]["severity"]).lower() == "high" or (finding["info"]["severity"]).lower() == "critical":
                    findingSeverity = "High"
                elif (finding["info"]["severity"]).lower() == "medium":
                    findingSeverity = "Medium"
                elif (finding["info"]["severity"]).lower() == "low" :
                    findingSeverity = "Low"
                text += '<b>[' + findingSeverity + '] ' + findingName + '<br><br></b>' + findingDesc + '<br>-----------<br>'
                if self.isBurpPro and (finding["type"] == "http" or finding["type"] == "headless"):
                    findingURL = URL(finding["matched-at"])
                    customIssue = CustomScanIssue(httpService, findingURL, findingName, findingDesc, findingSeverity)
                    self._callbacks.addScanIssue(customIssue)
            except Exception as e:
                print (e)
        return text

    def closeAllTabs(self, button):
        for p in self.runningSubprocesses:
            p.terminate()
            self.runningSubprocesses.remove(p)
            
        # Avoid to remove configuration tab
        while self.tabPane.getTabCount() > 1:
            self.tabPane.removeTabAt(self.tabPane.getTabCount()-1)
        self.tabNo = 0
        

    def closeTab(self, button):
        pid = button.getSource().getClientProperty("pid")
        proc = button.getSource().getClientProperty("proc")
        if proc and pid:
            poll = proc.poll()
            if poll is None:
                proc.terminate()
                
        tabid = self.tabPane.getSelectedIndex()
        self.tabPane.removeTabAt(tabid)
        if self.tabPane.getTabCount() == 1:
            self.tabNo = 0

    def killNuclei(self, button):
        proc = button.getSource().getClientProperty("proc")
        proc.terminate()

                
    def getFile(self, button):
        chooser = JFileChooser()
        if button.getSource() == self.nucleiPathButton:
            chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
            returnVal = chooser.showOpenDialog(self.parentFrame)
            if returnVal != chooser.CANCEL_OPTION:
                if (chooser.currentDirectory and chooser.selectedFile.name) is not None:
                    self._fileLocation = chooser.getCurrentDirectory().toString() + os.sep + chooser.getSelectedFile().getName()
                    self.nucleiPathField.setText(self._fileLocation)
                    self.saveConfig()
        if button.getSource() == self.nucleiTemplatesPathButton:
            chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES)
            returnVal = chooser.showOpenDialog(self.parentFrame)
            if returnVal != chooser.CANCEL_OPTION:
                if (chooser.currentDirectory) is not None:
                    self._fileLocation = chooser.getCurrentDirectory().toString() + os.sep + chooser.getSelectedFile().getName()
                    self.nucleiTemplatesPathField.setText(self._fileLocation)
                    self.saveConfig()  
                
class ScannerMenu(IContextMenuFactory):
    def __init__(self, scannerInstance):
        self.scannerInstance = scannerInstance

    def createMenuItems(self, contextMenuInvocation):
        self.contextMenuInvocation = contextMenuInvocation
        sendToNucleiScanner = JMenuItem( "Send URL to Nuclei Scanner", actionPerformed=self.getSentUrl)
        menuItems = ArrayList()
        menuItems.add(sendToNucleiScanner)
        return menuItems

    def getSentUrl(self, event):
        for selectedMessage in self.contextMenuInvocation.getSelectedMessages():
            if (selectedMessage.getHttpService() != None):
                try:
                    url = self.scannerInstance._helpers.analyzeRequest(
                        selectedMessage.getHttpService(),
                        selectedMessage.getRequest()).getUrl()
                    print ("URL: " + url.toString())
                    self.scannerInstance.targetField.setText(url.toString())
                except:
                    self.scannerInstance._callbacks.issueAlert(
                        "Cannot get URL from the currently selected message " +
                        str(sys.exc_info()[0]) + " " + str(sys.exc_info()[1]))
            else:
                self.scannerInstance._callbacks.issueAlert(
                    "The selected request is null.")


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, name, detail, severity="High", confidence="Firm"):
        self._httpService = httpService
        self._url = url
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._httpMessages = [] # Dummy array to fix issue with adding custom scan issue

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
