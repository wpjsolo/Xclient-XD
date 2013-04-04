#include "mainwindow.h"
#include "mylog.h"
#include <QApplication>
#include <QTextCodec>
#include <QObject>
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    QTextCodec::setCodecForLocale(QTextCodec::codecForName("GBK"));
    MainWindow w;
    w.show();
    return a.exec();
}
