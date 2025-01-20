# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'main_window2.ui'
##
## Created by: Qt User Interface Compiler version 6.7.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QDate, QDateTime, QLocale,
    QMetaObject, QObject, QPoint, QRect,
    QSize, QTime, QUrl, Qt)
from PySide6.QtGui import (QBrush, QColor, QConicalGradient, QCursor,
    QFont, QFontDatabase, QGradient, QIcon,
    QImage, QKeySequence, QLinearGradient, QPainter,
    QPalette, QPixmap, QRadialGradient, QTransform)
from PySide6.QtWidgets import (QApplication, QCheckBox, QFrame, QHBoxLayout,
    QLabel, QMainWindow, QPushButton, QSizePolicy,
    QStackedWidget, QTextBrowser, QTextEdit, QVBoxLayout,
    QWidget)
import gui.icons_rc

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.centralwidget.setStyleSheet(u"background-color: #333333;\n"
"padding: 0px; margin: 0px;")
        self.mainVerticalLayout = QVBoxLayout(self.centralwidget)
        self.mainVerticalLayout.setObjectName(u"mainVerticalLayout")
        self.navBar = QFrame(self.centralwidget)
        self.navBar.setObjectName(u"navBar")
        self.navBar.setStyleSheet(u"background-color: #1A1A1A; color: white; padding: 0px; min-width: 25px;")
        self.navBar.setFrameShape(QFrame.StyledPanel)
        self.navBar.setFrameShadow(QFrame.Raised)
        self.navBarLayout = QHBoxLayout(self.navBar)
        self.navBarLayout.setObjectName(u"navBarLayout")
        self.titleLabel = QLabel(self.navBar)
        self.titleLabel.setObjectName(u"titleLabel")
        self.titleLabel.setStyleSheet(u"font-size: 12px; font-weight: bold;\n"
"")

        self.navBarLayout.addWidget(self.titleLabel)


        self.mainVerticalLayout.addWidget(self.navBar)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.sectionColumn = QFrame(self.centralwidget)
        self.sectionColumn.setObjectName(u"sectionColumn")
        self.sectionColumn.setStyleSheet(u"background-color: #333333; min-width: 70px; padding: 0px; margin: 0px;")
        self.sectionColumn.setFrameShape(QFrame.NoFrame)
        self.sectionColumn.setFrameShadow(QFrame.Plain)
        self.verticalLayout_2 = QVBoxLayout(self.sectionColumn)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setObjectName(u"verticalLayout_2")
        self.verticalLayout_2.setAlignment(Qt.AlignTop)
        self.scanSection = QPushButton(self.sectionColumn)
        self.scanSection.setObjectName(u"scanSection")
        self.scanSection.setStyleSheet(u"\n"
"             QPushButton {\n"
"                 background-color: #333333; \n"
"                 color: white; \n"
"                 font-size: 16px; \n"
"                 font-weight: bold; \n"
"                 border: none;\n"
"                 text-align: bottom;\n"
"				 width: 50px;\n"
"				 height: 50px;\n"
"             }\n"
"             QPushButton:hover {\n"
"                 background-color: #1F1F1F;\n"
"             }\n"
"             QPushButton:icon {\n"
"                 text-align: top;\n"
"             }\n"
"            ")
        icon = QIcon()
        icon.addFile(u":/gui/glass.png", QSize(), QIcon.Normal, QIcon.Off)
        self.scanSection.setIcon(icon)
        self.scanSection.setIconSize(QSize(32, 32))
        # self.scanSection.setTextAlignment(Qt.AlignCenter)
        # self.scanSection.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)

        self.verticalLayout_2.addWidget(self.scanSection)

        self.firewallSection = QPushButton(self.sectionColumn)
        self.firewallSection.setObjectName(u"firewallSection")
        self.firewallSection.setStyleSheet(u"\n"
"             QPushButton {\n"
"                 background-color: #333333; \n"
"                 color: white; \n"
"                 font-size: 16px; \n"
"                 font-weight: bold; \n"
"                 border: none;\n"
"                 text-align: bottom;\n"
"				 width: 50px;\n"
"				 height: 50px;\n"
"             }\n"
"             QPushButton:hover {\n"
"                 background-color: #1F1F1F;\n"
"             }\n"
"             QPushButton:icon {\n"
"                 text-align: top;\n"
"             }\n"
"            ")
        icon1 = QIcon()
        icon1.addFile(u":/gui/wall.png", QSize(), QIcon.Normal, QIcon.Off)
        self.firewallSection.setIcon(icon1)
        self.firewallSection.setIconSize(QSize(32, 32))
        # self.firewallSection.setTextAlignment(Qt.AlignCenter)
        # self.firewallSection.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)

        self.verticalLayout_2.addWidget(self.firewallSection)

        self.statusSection = QPushButton(self.sectionColumn)
        self.statusSection.setObjectName(u"statusSection")
        self.statusSection.setStyleSheet(u"\n"
"             QPushButton {\n"
"                 background-color: #333333; \n"
"                 color: white; \n"
"                 font-size: 16px; \n"
"                 font-weight: bold; \n"
"                 border: none;\n"
"                 text-align: bottom;\n"
"				 width: 50px;\n"
"				 height: 50px;\n"
"             }\n"
"             QPushButton:hover {\n"
"                 background-color: #1F1F1F;\n"
"             }\n"
"             QPushButton:icon {\n"
"                 text-align: top;\n"
"             }\n"
"            ")
        icon2 = QIcon()
        icon2.addFile(u":/gui/tick.png", QSize(), QIcon.Normal, QIcon.Off)
        self.statusSection.setIcon(icon2)
        self.statusSection.setIconSize(QSize(32, 32))
        # self.statusSection.setTextAlignment(Qt.AlignCenter)
        # self.statusSection.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)

        self.verticalLayout_2.addWidget(self.statusSection)

        iconAboveText = '''
            QPushButton {
                text-align: center;
                padding: 10px;  /* Adjust padding as needed */
            }
            QPushButton::icon {
                margin-bottom: 5px;  /* Adjust margin between icon and text */
            }
        '''
        
        self.scanSection.setStyleSheet(iconAboveText)
        self.firewallSection.setStyleSheet(iconAboveText)
        self.statusSection.setStyleSheet(iconAboveText)

        self.horizontalLayout.addWidget(self.sectionColumn)

        self.stackedWidget = QStackedWidget(self.centralwidget)
        self.stackedWidget.setObjectName(u"stackedWidget")
        self.stackedWidget.setStyleSheet(u"padding: 0px; margin: 0px;")
        self.scan_page = QWidget()
        self.scan_page.setObjectName(u"scan_page")
        self.scan_page.setStyleSheet(u"padding: 0px; margin: 0px;")
        self.verticalLayout = QVBoxLayout(self.scan_page)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.scanButton = QPushButton(self.scan_page)
        self.scanButton.setObjectName(u"scanButton")
        self.scanButton.setStyleSheet(u"background-color: #1E90FF; color: white; font-size: 36px; font-weight: bold; padding: 30px; border-radius: 20px;")

        self.verticalLayout.addWidget(self.scanButton)

        self.resultTextArea = QTextEdit(self.scan_page)
        self.resultTextArea.setObjectName(u"resultTextArea")

        self.verticalLayout.addWidget(self.resultTextArea)

        self.stackedWidget.addWidget(self.scan_page)
        self.firewall_page = QWidget()
        self.firewall_page.setObjectName(u"firewall_page")
        self.firewall_page.setStyleSheet(u"padding: 0px; margin: 0px;")
        self.label = QLabel(self.firewall_page)
        self.label.setObjectName(u"label")
        self.label.setGeometry(QRect(20, 50, 61, 16))
        self.textBrowser = QTextBrowser(self.firewall_page)
        self.textBrowser.setObjectName(u"textBrowser")
        self.textBrowser.setGeometry(QRect(100, 40, 256, 31))
        self.stackedWidget.addWidget(self.firewall_page)
        self.status_page = QWidget()
        self.status_page.setObjectName(u"status_page")
        self.status_page.setStyleSheet(u"padding: 0px; margin: 0px;")
        self.checkBox = QCheckBox(self.status_page)
        self.checkBox.setObjectName(u"checkBox")
        self.checkBox.setGeometry(QRect(270, 270, 76, 20))
        self.stackedWidget.addWidget(self.status_page)

        self.horizontalLayout.addWidget(self.stackedWidget)


        self.mainVerticalLayout.addLayout(self.horizontalLayout)

        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)

        self.stackedWidget.setCurrentIndex(2)


        QMetaObject.connectSlotsByName(MainWindow)
    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"Antivirus Application", None))
        self.titleLabel.setText(QCoreApplication.translate("MainWindow", u"Porcupine", None))
        self.scanSection.setText(QCoreApplication.translate("MainWindow", u"Scan", None))
        self.firewallSection.setText(QCoreApplication.translate("MainWindow", u"Firewall", None))
        self.statusSection.setText(QCoreApplication.translate("MainWindow", u"Status", None))
        self.scanButton.setText(QCoreApplication.translate("MainWindow", u"Scan", None))
        self.label.setText(QCoreApplication.translate("MainWindow", u"Username", None))
        self.textBrowser.setHtml(QCoreApplication.translate("MainWindow", u"<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><meta charset=\"utf-8\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"hr { height: 1px; border-width: 0; }\n"
"li.unchecked::marker { content: \"\\2610\"; }\n"
"li.checked::marker { content: \"\\2612\"; }\n"
"</style></head><body style=\" font-family:'Segoe UI'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">\u0110\u1ed7 Trung HI\u1ebfu</p>\n"
"<p style=\"-qt-paragraph-type:empty; margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\"><br /></p></body></html>", None))
        self.checkBox.setText(QCoreApplication.translate("MainWindow", u"Use AI scan", None))
    # retranslateUi

