#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "NetworkDevice.h"

extern bool findDevices(QList<NetworkDevice>*);

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    loadDevice();
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
        qDebug()<<deviceList[i].name<<endl;
        ui->deviceComboBox->addItem(deviceList[i].description,QVariant(deviceList[i].name));
    }
}

void MainWindow::on_pushButton_clicked()
{
    loadDevice();
}
