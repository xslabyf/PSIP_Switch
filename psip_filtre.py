# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'psip_filtre.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_SecondWindow(object):
    def __init__(self, switch):
        self.switch = switch
        self.interface = ""
        self.direction = ""
        self.permision = ""
        self.src_mac = ""
        self.dst_mac = ""
        self.src_ip = ""
        self.dst_ip = ""
        self.closeWindow = False

    def setupUi(self, SecondWindow):
        SecondWindow.setObjectName("SecondWindow")
        SecondWindow.resize(790, 220)
        self.centralwidget = QtWidgets.QWidget(SecondWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.textEdit_4 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_4.setEnabled(True)
        self.textEdit_4.setGeometry(QtCore.QRect(290, 90, 81, 21))
        self.textEdit_4.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_4.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_4.setUndoRedoEnabled(True)
        self.textEdit_4.setObjectName("textEdit_4")
        self.textEdit_5 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_5.setEnabled(True)
        self.textEdit_5.setGeometry(QtCore.QRect(380, 90, 81, 21))
        self.textEdit_5.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_5.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_5.setUndoRedoEnabled(True)
        self.textEdit_5.setObjectName("textEdit_5")
        self.textEdit_6 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_6.setEnabled(True)
        self.textEdit_6.setGeometry(QtCore.QRect(470, 90, 81, 21))
        self.textEdit_6.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_6.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_6.setUndoRedoEnabled(True)
        self.textEdit_6.setObjectName("textEdit_6")
        self.textEdit_7 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_7.setEnabled(True)
        self.textEdit_7.setGeometry(QtCore.QRect(560, 90, 81, 21))
        self.textEdit_7.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_7.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_7.setUndoRedoEnabled(True)
        self.textEdit_7.setObjectName("textEdit_7")
        self.textEdit_8 = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_8.setEnabled(True)
        self.textEdit_8.setGeometry(QtCore.QRect(650, 90, 81, 21))
        self.textEdit_8.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_8.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.textEdit_8.setUndoRedoEnabled(True)
        self.textEdit_8.setObjectName("textEdit_8")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(340, 10, 91, 16))
        font = QtGui.QFont()
        font.setPointSize(14)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(40, 60, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(130, 60, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(220, 60, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_4.setFont(font)
        self.label_4.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(298, 60, 60, 16))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_5.setFont(font)
        self.label_5.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_5.setAlignment(QtCore.Qt.AlignCenter)
        self.label_5.setObjectName("label_5")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(400, 60, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_6.setFont(font)
        self.label_6.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_6.setAlignment(QtCore.Qt.AlignCenter)
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(490, 60, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_7.setFont(font)
        self.label_7.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setGeometry(QtCore.QRect(580, 60, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_8.setFont(font)
        self.label_8.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_8.setAlignment(QtCore.Qt.AlignCenter)
        self.label_8.setObjectName("label_8")
        self.label_9 = QtWidgets.QLabel(self.centralwidget)
        self.label_9.setGeometry(QtCore.QRect(670, 60, 47, 13))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.label_9.setFont(font)
        self.label_9.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_9.setAlignment(QtCore.Qt.AlignCenter)
        self.label_9.setObjectName("label_9")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(650, 140, 75, 23))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.clicked.connect(self.addFilter)
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(20, 90, 81, 22))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("")
        self.comboBox.addItem("")
        self.comboBox.activated[str].connect(self.chooseInterface)
        self.comboBox_2 = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox_2.setGeometry(QtCore.QRect(110, 90, 81, 22))
        self.comboBox_2.setObjectName("comboBox_2")
        self.comboBox_2.addItem("")
        self.comboBox_2.addItem("")
        self.comboBox_2.activated[str].connect(self.chooseDirection)
        self.comboBox_3 = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox_3.setGeometry(QtCore.QRect(200, 90, 81, 22))
        self.comboBox_3.setObjectName("comboBox_3")
        self.comboBox_3.addItem("")
        self.comboBox_3.addItem("")
        self.comboBox_3.activated[str].connect(self.choosePermision)
        SecondWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(SecondWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 790, 21))
        self.menubar.setObjectName("menubar")
        SecondWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(SecondWindow)
        self.statusbar.setObjectName("statusbar")
        SecondWindow.setStatusBar(self.statusbar)

        self.retranslateUi(SecondWindow)
        QtCore.QMetaObject.connectSlotsByName(SecondWindow)

    def retranslateUi(self, SecondWindow):
        _translate = QtCore.QCoreApplication.translate
        SecondWindow.setWindowTitle(_translate("SecondWindow", "MainWindow"))
        self.label.setText(_translate("SecondWindow", "Add filter"))
        self.label_2.setText(_translate("SecondWindow", "I"))
        self.label_3.setText(_translate("SecondWindow", "I/O"))
        self.label_4.setText(_translate("SecondWindow", "A"))
        self.label_5.setText(_translate("SecondWindow", "Port/ping"))
        self.label_6.setText(_translate("SecondWindow", "S MAC"))
        self.label_7.setText(_translate("SecondWindow", "D MAC"))
        self.label_8.setText(_translate("SecondWindow", "S IP"))
        self.label_9.setText(_translate("SecondWindow", "D IP"))
        self.pushButton.setText(_translate("SecondWindow", "Add"))
        self.comboBox.setItemText(0, _translate("SecondWindow", "Interface 1"))
        self.comboBox.setItemText(1, _translate("SecondWindow", "Interface 2"))
        self.comboBox_2.setItemText(0, _translate("SecondWindow", "IN"))
        self.comboBox_2.setItemText(1, _translate("SecondWindow", "OUT"))
        self.comboBox_3.setItemText(0, _translate("SecondWindow", "Allow"))
        self.comboBox_3.setItemText(1, _translate("SecondWindow", "Deny"))


    def addFilter(self):
        zoz = []
        zoz.append(self.interface)
        zoz.append(self.direction)
        zoz.append(self.permision)
        zoz.append(self.textEdit_4.toPlainText())
        zoz.append(self.textEdit_5.toPlainText())
        zoz.append(self.textEdit_6.toPlainText())
        zoz.append(self.textEdit_7.toPlainText())
        zoz.append(self.textEdit_8.toPlainText())
        self.switch.filters.append(zoz)
        print(self.switch.filters)
        self.closeWindow = True


    def chooseInterface(self, index):
        self.interface = index

    def chooseDirection(self, index):
        self.direction = index

    def choosePermision(self, index):
        self.permision = index