#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include "auth.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void loadDevice();
    Auth myAuth;
public slots:
    void SLOT_debug(QString msg);
    void SLOT_changeBtnSlots(QString type);
private slots:
    void on_btnStart_clicked();
    void on_btnRefresh_clicked();
    void on_btnStop_clicked();
    void on_btnLogOff_clicked();

    void on_textBrowser_textChanged();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
