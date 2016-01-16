#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <memory>
#include "Generator.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private:
    Ui::MainWindow *ui;
    bool generatorStopped;
    std::unique_ptr<Generator> generator;
public slots:
    void onStartStopClicked();
    void onSetGeneratorIsRunning(bool isRunning);
};

#endif // MAINWINDOW_H
