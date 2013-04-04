#include "mylog.h"
#include "QDebug"

MyLog::MyLog()
{

}
void MyLog::debug(QString msg)
{
    emit this->SIGNAL_debug(msg);
}

void MyLog::info(QString msg)
{

}

void MyLog::error(QString msg)
{
    emit this->SIGNAL_debug(msg);
}
