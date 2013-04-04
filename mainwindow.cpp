#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "NetworkDevice.h"
#include "mylog.h"

extern bool findDevices(QList<NetworkDevice>*);

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(&logger,SIGNAL(SIGNAL_debug(QString)),this,SLOT(SLOT_debug(QString)));
    loadDevice();
    ui->box_username->setText("1202121272");
    ui->box_password->setText("123458");
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::loadDevice()
{
    QList<NetworkDevice> deviceList;
    findDevices(&deviceList);
    ui->deviceComboBox->clear();
    for (int i=0;i<deviceList.count();i++)
    {
        ui->deviceComboBox->addItem(deviceList[i].description,QVariant(deviceList[i].name));
    }
}
void MainWindow::on_btnRefresh_clicked()
{
   loadDevice();
}

void MainWindow::on_btnStart_clicked()
{
    if (ui->box_username->text().isEmpty())
    {
        QMessageBox::warning(NULL,tr("Information"),tr("Please Input Username."),QMessageBox::Yes|QMessageBox::No,QMessageBox::Yes);
        ui->box_username->setFocus();
        return;
    }
    if (ui->box_password->text().isEmpty())
    {
        QMessageBox::warning(NULL,tr("Information"),tr("Please Input Password."),QMessageBox::Yes|QMessageBox::No,QMessageBox::Yes);
        ui->box_password->setFocus();
        return;
    }
    if (ui->deviceComboBox->count()==0)
    {
        QMessageBox::warning(NULL,tr("Information"),tr("Device Not Found!"),QMessageBox::Yes|QMessageBox::No,QMessageBox::Yes);
        return;
    }
    QString deviceName=ui->deviceComboBox->itemData(ui->deviceComboBox->currentIndex()).toString();

    myAuth.InitAuth(ui->box_username->text(),ui->box_password->text(),deviceName,this);
    myAuth.start();
}

void MainWindow::SLOT_changeBtnSlots(QString type)
{
    disconnect(ui->btnStart,SIGNAL(clicked()),0,0);
    if(!type.compare("Stop"))
    {
        connect(ui->btnStart,SIGNAL(clicked()),this,SLOT(on_btnStop_clicked()));
        ui->btnStart->setText("Stop");
    }
    else if (!type.compare("LogOff"))
    {
        connect(ui->btnStart,SIGNAL(clicked()),this,SLOT(on_btnLogOff_clicked()));
        ui->btnStart->setText("LogOff");
    }
    else if(!type.compare("Start"))
    {
        connect(ui->btnStart,SIGNAL(clicked()),this,SLOT(on_btnStart_clicked()));
        ui->btnStart->setText("Start");
    }
}


void MainWindow::SLOT_debug(QString msg)
{
    ui->textBrowser->append(msg);
}


void MainWindow::on_btnStop_clicked()
{
    myAuth.status=false;
}

void MainWindow::on_btnLogOff_clicked()
{
    myAuth.stopAuth();
}

void MainWindow::on_textBrowser_textChanged()
{
    int num=ui->spinBox->value();
    if (num==0) return ;
    if(ui->textBrowser->document()->blockCount()>num)
        ui->textBrowser->clear();
}
