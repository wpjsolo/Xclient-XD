#ifndef MYLOG_H
#define MYLOG_H
#include <QObject>
#include <QString>

class MyLog : public QObject
{
    Q_OBJECT

public:
    MyLog();
    void debug(QString msg);
    void info(QString msg);
    void error(QString msg);
signals:
    void SIGNAL_debug(QString msg);
};
static MyLog logger;
#endif // MYLOG_H
