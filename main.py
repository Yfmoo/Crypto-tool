"""这是一款密码加解密集成工具，主要对古典、现代、文件进行加解密
   主要适用于在线下直接进行加解密
   适用于ctf赛事的密码方向
   攻防演练中没有网络的情况而准备   
"""


from PyQt5 import QtCore, QtGui, QtWidgets
import sys
import ui_to_py.Ui_MainWindow as Ui_MainWindow


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    my_Window = Ui_MainWindow.Ui_MainWindow()
    my_Window.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())