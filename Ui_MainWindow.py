from PyQt5 import QtWidgets, QtCore
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow
import sys
sys.path.append("C:/LearnPyhon/pythonPractice/Python_class/final_homework")
# 导入各个子界面的类
from ui_to_py import Ui_Gu_dian  # 古典加密
import ui_to_py.Ui_Base as Ui_Base  # Base家族
import ui_to_py.Ui_xian_dai as Ui_xian_dai  # 现代加密
import ui_to_py.Ui_RSA as Ui_RSA  # RSA专栏
import ui_to_py.Ui_file as Ui_File  # 文件加解密


class HelpWindow(QtWidgets.QMainWindow):
    def __init__(self, filename):
        super().__init__()
        self.setWindowTitle("帮助文档")
        self.resize(600, 400)
        
        # 创建文本编辑器用于显示文档内容
        self.helpTextEdit = QtWidgets.QTextEdit()
        self.helpTextEdit.setReadOnly(True)
        
        # 加载文本文件内容
        self.loadHelpFile(filename)
        
        # 设置文本编辑器为中心部件
        self.setCentralWidget(self.helpTextEdit)
    
    def loadHelpFile(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                content = file.read()
                self.helpTextEdit.setPlainText(content)
        except FileNotFoundError:
            self.helpTextEdit.setPlainText("找不到帮助文档文件。")

class Ui_MainWindow(QMainWindow):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        
        # Create QStackedWidget
        self.stackedWidget = QtWidgets.QStackedWidget(self.centralwidget)
        self.stackedWidget.setObjectName("stackedWidget")
        
        # 文件加解密
        self.pageFile = QtWidgets.QWidget()
        self.File_Ui = Ui_File.Ui_Form()
        self.File_Ui.setupUi(self.pageFile)
        self.stackedWidget.addWidget(self.pageFile)
        
        # 古典密码
        self.pageGuDian = QtWidgets.QWidget()
        self.GuDian_Ui = Ui_Gu_dian.Ui_Form()
        self.GuDian_Ui.setupUi(self.pageGuDian)
        self.stackedWidget.addWidget(self.pageGuDian)
        
        # 现代密码
        self.pageXianDai = QtWidgets.QWidget()
        self.Xiandai_Ui = Ui_xian_dai.Ui_Form()
        self.Xiandai_Ui.setupUi(self.pageXianDai)
        self.stackedWidget.addWidget(self.pageXianDai)
        
        # Base家族
        self.basePage = QtWidgets.QWidget()
        self.baseUi = Ui_Base.Ui_Form()
        self.baseUi.setupUi(self.basePage)
        self.stackedWidget.addWidget(self.basePage)
        
        # RSA专栏
        self.RSAPage = QtWidgets.QWidget()
        self.RSAUi = Ui_RSA.Ui_Form()
        self.RSAUi.setupUi(self.RSAPage)
        self.stackedWidget.addWidget(self.RSAPage)
        
        # Set layout for central widget
        self.central_layout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.central_layout.addWidget(self.stackedWidget)
        MainWindow.setCentralWidget(self.centralwidget)
        
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 26))
        self.menubar.setObjectName("menubar")
        
        self.menu = QtWidgets.QMenu(self.menubar)
        self.menu.setObjectName("menu")
        self.menu_2 = QtWidgets.QMenu(self.menubar)
        self.menu_2.setObjectName("menu_2")
        
        self.actionVersion = QtWidgets.QAction(MainWindow)
        self.actionVersion.setObjectName("actionVersion")
        self.actionHelptext = QtWidgets.QAction(MainWindow)
        self.actionHelptext.setObjectName("actionHelptext")
        self.actionWhat_s_this = QtWidgets.QAction(MainWindow)
        self.actionWhat_s_this.setObjectName("actionWhat_s_this")
        self.actionBase = QtWidgets.QAction(MainWindow)
        self.actionBase.setObjectName("actionBase")
        self.action = QtWidgets.QAction(MainWindow)
        self.action.setObjectName("action")
        self.action_2 = QtWidgets.QAction(MainWindow)
        self.action_2.setObjectName("action_2")
        self.action_3 = QtWidgets.QAction(MainWindow)
        self.action_3.setObjectName("action_3")
        self.action_4 = QtWidgets.QAction(MainWindow)
        self.action_4.setObjectName("action_4")
        self.actionRSA = QtWidgets.QAction(MainWindow)
        self.actionRSA.setObjectName("actionRSA")
        
        self.menu.addAction(self.actionVersion)
        self.menu.addAction(self.actionWhat_s_this)
        self.menu_2.addAction(self.actionHelptext)
        
        self.menubar.addAction(self.menu.menuAction())
        self.menubar.addAction(self.menu_2.menuAction())
        MainWindow.setMenuBar(self.menubar)
        
        self.toolBar = QtWidgets.QToolBar(MainWindow)
        self.toolBar.setObjectName("toolBar")
        MainWindow.addToolBar(QtCore.Qt.TopToolBarArea, self.toolBar)
        
        self.toolBar.addAction(self.action)
        self.toolBar.addAction(self.action_2)
        self.toolBar.addAction(self.action_3)
        self.toolBar.addAction(self.actionBase)
        self.toolBar.addAction(self.actionRSA)
        self.toolBar.addAction(self.action_4)
        
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
        # action分别连接到文件加解密、古典密码、现代密码、Base家族、RSA专栏
        self.action.triggered.connect(lambda: self.stackedWidget.setCurrentIndex(0))
        self.action_2.triggered.connect(lambda: self.stackedWidget.setCurrentIndex(1))
        self.action_3.triggered.connect(lambda: self.stackedWidget.setCurrentIndex(2))
        self.actionBase.triggered.connect(lambda: self.stackedWidget.setCurrentIndex(3))  # Index of basePage
        self.actionRSA.triggered.connect(lambda: self.stackedWidget.setCurrentIndex(4))
        self.actionHelptext.triggered.connect(self.showHelpDocument)
        
        # 初始化帮助文档窗口
        self.helpWindow = None

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Crypto Tool"))
        self.setWindowIcon(QIcon('C:/LearnPyhon/pythonPractice/Python_class/final_homework/logo/bitbug_favicon.ico'))
        self.menu.setTitle(_translate("MainWindow", "关于"))
        self.menu_2.setTitle(_translate("MainWindow", "帮助"))
        self.toolBar.setWindowTitle(_translate("MainWindow", "toolBar"))
        self.actionVersion.setText(_translate("MainWindow", "Version"))
        self.actionHelptext.setText(_translate("MainWindow", "Helptext"))
        self.actionWhat_s_this.setText(_translate("MainWindow", "What\'s this"))
        self.actionBase.setText(_translate("MainWindow", "Base家族"))
        self.action.setText(_translate("MainWindow", "文件加解密"))
        self.action_2.setText(_translate("MainWindow", "古典密码"))
        self.action_3.setText(_translate("MainWindow", "现代密码"))
        self.action_4.setText(_translate("MainWindow", "其他"))
        self.actionRSA.setText(_translate("MainWindow", "RSA专栏"))

    def showHelpDocument(self):
        if not self.helpWindow:
            # 在这里指定要加载的帮助文档文件路径
            filename = "C:\\LearnPyhon\\pythonPractice\\Python_class\\final_homework\\REDME.txt"  # 替换为实际的文件路径
            self.helpWindow = HelpWindow(filename)
        self.helpWindow.show()

