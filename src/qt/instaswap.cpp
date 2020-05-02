#include "instaswap.h"
#include "forms/ui_instaswap.h"

#include "init.h"
#include "addressbookpage.h"
#include "optionsmodel.h"
#include "guiutil.h"
#include <qt/platformstyle.h>

#include <QLineEdit>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSettings>
#include <QNetworkAccessManager>
#include <QUrl>
#include <QUrlQuery>
#include <QNetworkReply>
#include "clientmodel.h"
#include "walletmodel.h"

#include <boost/algorithm/string.hpp>
using namespace std;

const char* InstaSwap::TransactionStateString[] = {
    "Awaiting Deposit", "Swaping", "Withdraw", "Completed", "Deposit Not Completed"
};

InstaSwap::InstaSwap(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::InstaSwap),
    clientModel(0),
    walletModel(0),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    if (!_platformStyle->getImagesOnButtons()) {
        ui->addressBookButton->setIcon(QIcon());
    } else {
        ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    }

    PURCHASECOIN = "SIN";
    ENDPOINT = QString::fromStdString(gArgs.GetArg("-instaswapurl", "https://instaswap.sinovate.io/instaswap_service.php"));

    setupSwapList();


    // normal sin address field
    GUIUtil::setupAddressWidget(ui->receivingAddressEdit, this);

    // managers and settings
    ConnectionManager = new QNetworkAccessManager(this);

    QSettings settings;

    /* wallet receive address? - or deterministic  +++
    QString username = settings.value("platformUsername").toString();
    QString useraddress = settings.value("platformUseraddress").toString();
    ui->usernameEdit->setText(username);
    ui->addressEdit->setText(useraddress);


    if (!username.isEmpty() && !useraddress.isEmpty())
    {
        on_userButton_clicked();        //autorefresh
    }
    */
}

InstaSwap::~InstaSwap()
{
    delete ui;
    delete ConnectionManager;
}

// overrride
void InstaSwap::showEvent( QShowEvent* event ) {
    QWidget::showEvent( event );
    //your code here
    populatePairsCombo();
}

void InstaSwap::setClientModel(ClientModel* model)
{
    this->clientModel = model;
    if (model) {
        // connect for change events...
        //connect(clientModel, SIGNAL(strMasternodesChanged(QString)), this, SLOT(updateNodeList()));
    }
}

void InstaSwap::showContextMenu(const QPoint &point)
{
    QTableWidgetItem *item = ui->swapsTable->itemAt(point);
    if(item)    swapListContextMenu->exec(QCursor::pos());
}

void InstaSwap::setWalletModel(WalletModel* model)
{
    this->walletModel = model;
}

void InstaSwap::setAddress(const QString& address)
{
    setAddress(address, ui->receivingAddressEdit);
}

void InstaSwap::setAddress(const QString& address, QLineEdit* addrEdit)
{
    addrEdit->setText(address);
    addrEdit->setFocus();
}

void InstaSwap::setupSwapList() {
    // Swap List table
    int columnTransactionIdWidth = 120;
    int columnStatusWidth = 130;
    int columnTimestampWidth = 120;
    int columnDepositAddressWidth = 160;
    int columnSendCoinWidth = 80;
    int columnSendAmounWidth = 100;
    int columnReceiveAddressWidth = 160;
    int columnReceiveCoinWidth = 140;
    int columnReceiveAmountWidth = 140;
    int columnRefundAddressWidth = 160;

    ui->swapsTable->setColumnWidth(0, columnTransactionIdWidth);
    ui->swapsTable->setColumnWidth(1, columnStatusWidth);
    ui->swapsTable->setColumnWidth(2, columnTimestampWidth);
    ui->swapsTable->setColumnWidth(3, columnDepositAddressWidth);
    ui->swapsTable->setColumnWidth(4, columnSendCoinWidth);
    ui->swapsTable->setColumnWidth(5, columnSendAmounWidth);
    ui->swapsTable->setColumnWidth(6, columnReceiveAddressWidth);
    ui->swapsTable->setColumnWidth(7, columnReceiveCoinWidth);
    ui->swapsTable->setColumnWidth(8, columnReceiveAmountWidth);
    ui->swapsTable->setColumnWidth(9, columnRefundAddressWidth);

    ui->swapsTable->setContextMenuPolicy(Qt::CustomContextMenu);

    QAction* copyTransactionIdAction = new QAction(tr("Copy &Transaction ID"), this);
    QAction* copyDepositAddressAction = new QAction(tr("Copy &Deposit Address"), this);

    swapListContextMenu = new QMenu();
    swapListContextMenu->addAction(copyTransactionIdAction);
    swapListContextMenu->addAction(copyDepositAddressAction);
    connect(ui->swapsTable, SIGNAL(customContextMenuRequested(const QPoint &)), this, SLOT(showContextMenu(const QPoint &)));
    connect(copyTransactionIdAction, SIGNAL(triggered()), this, SLOT(onCopyTransactionActionClicked()));
    connect(copyDepositAddressAction, SIGNAL(triggered()), this, SLOT(onCopyDepositActionClicked()));
}

void InstaSwap::populatePairsCombo()
{
    if (ui->allowedPairsCombo->count()>0)   return;

    QJsonDocument json = callAllowedPairs();

    if ( json.object()["apiInfo"]=="OK" && json.object().contains("response") && json.object()["response"].isArray() )
    {
        QJsonArray jArr = json.object()["response"].toArray();

        for(const QJsonValue & value : jArr) {
            QJsonObject obj = value.toObject();
            QString receiveCoin = obj["receiveCoin"].toString();
            if (receiveCoin==PURCHASECOIN) {       // only SIN purchases
                ui->allowedPairsCombo->addItem( obj["depositCoin"].toString() );
            }
        }
    }
}

QJsonDocument InstaSwap::callAllowedPairs( )
{
    QString Service = QString::fromStdString("InstaswapReportAllowedPairs");

    QUrl url( InstaSwap::ENDPOINT );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("s", Service);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);

    return json;
}

QJsonDocument InstaSwap::callListHistory( )
{
    QString Service = QString::fromStdString("InstaswapReportWalletHistory");
    QString walletAddress = ui->receivingAddressEdit->text();

    QUrl url( InstaSwap::ENDPOINT );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("s", Service);
    urlQuery.addQueryItem("wallet", walletAddress);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);

    return json;
}

QJsonDocument InstaSwap::callTicker( )
{
    QString Service = QString::fromStdString("InstaswapTickers");
    QString getCoin = QString::fromStdString("SIN");        // only SIN purchases at the moment
    QString giveCoin = ui->allowedPairsCombo->currentText();
    QString sendAmount = ui->depositAmountEdit->text();

    QUrl url( InstaSwap::ENDPOINT );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("s", Service);
    urlQuery.addQueryItem("getCoin", getCoin);
    urlQuery.addQueryItem("giveCoin", giveCoin);
    urlQuery.addQueryItem("sendAmount", sendAmount);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);

    return json;
}

QJsonDocument InstaSwap::callDoSwap( )
{
    QString Service = QString::fromStdString("InstaswapSwap");
    QString getCoin = QString::fromStdString("SIN");        // only SIN purchases at the moment
    QString giveCoin = ui->allowedPairsCombo->currentText();
    QString sendAmount = ui->depositAmountEdit->text();
    QString receiveWallet = ui->receivingAddressEdit->text();
    QString refundWallet = ui->refundAddressEdit->text();

    QUrl url( InstaSwap::ENDPOINT );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("s", Service);
    urlQuery.addQueryItem("getCoin", getCoin);
    urlQuery.addQueryItem("giveCoin", giveCoin);
    urlQuery.addQueryItem("sendAmount", sendAmount);
    urlQuery.addQueryItem("receiveWallet", receiveWallet);
    urlQuery.addQueryItem("refundWallet", refundWallet);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);

    return json;
}

void InstaSwap::updateSwapList()
{
    // clean
    ui->swapsTable->setRowCount(0);

    QJsonDocument json = callListHistory();

    if ( json.object()["apiInfo"]=="OK" && json.object().contains("response") && json.object()["response"].isArray() )
    {
        QJsonArray jArr = json.object()["response"].toArray();

        for(const QJsonValue & value : jArr) {
            QJsonObject obj = value.toObject();
            QString strTransactionId = obj["transactionId"].toString();
            QString strDepositCoin = obj["depositCoin"].toString();
            QString strDepositAmount = obj["depositAmount"].toString();
            QString strReceiveCoin = obj["receiveCoin"].toString();
            QString strReceiveAmount = obj["receivingAmount"].toString();
            QString strRefundAddress = obj["refundWallet"].toString();
            QString strReceiveAddress = obj["receiveWallet"].toString();
            QString strDepositAddress = obj["depositWallet"].toString();
            QString strTransactionState = obj["transactionState"].toString();
            QString strTimestamp = obj["timestamp"].toString();

            ui->swapsTable->insertRow(0);

            QTableWidgetItem* TransactionIdItem = new QTableWidgetItem(strTransactionId);
            QTableWidgetItem* DepositCoinItem = new QTableWidgetItem(strDepositCoin);
            //AmountItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            QTableWidgetItem* DepositAmountItem = new QTableWidgetItem(strDepositAmount);
            QTableWidgetItem* ReceiveCoinItem = new QTableWidgetItem(strReceiveCoin);
            QTableWidgetItem* ReceiveAmountItem = new QTableWidgetItem(strReceiveAmount);
            QTableWidgetItem* RefundAddressItem = new QTableWidgetItem(strRefundAddress);
            QTableWidgetItem* ReceiveAddressItem = new QTableWidgetItem(strReceiveAddress);
            QTableWidgetItem* DepositAddressItem = new QTableWidgetItem(strDepositAddress);
            QTableWidgetItem* TransactionStateItem = new QTableWidgetItem(strTransactionState);
            QTableWidgetItem* TimestampItem = new QTableWidgetItem(strTimestamp);

            ui->swapsTable->setItem(0, 0, TransactionIdItem);
            ui->swapsTable->setItem(0, 1, TransactionStateItem);
            ui->swapsTable->setItem(0, 2, TimestampItem);
            ui->swapsTable->setItem(0, 3, DepositAddressItem);
            ui->swapsTable->setItem(0, 4, DepositCoinItem);
            ui->swapsTable->setItem(0, 5, DepositAmountItem);
            ui->swapsTable->setItem(0, 6, ReceiveCoinItem);
            ui->swapsTable->setItem(0, 7, ReceiveAmountItem);
            ui->swapsTable->setItem(0, 8, ReceiveAddressItem);
            ui->swapsTable->setItem(0, 9, RefundAddressItem);
        }
    }
    else
    {
        QString error = QString("An error occurred while connecting to Instaswap");
        ui->errorLabel->setText( "ERROR: " + error );
    }

    return;
}

void InstaSwap::onCopyTransactionActionClicked()
{
    CopyListColumn( ui->swapsTable, 0 );
}

void InstaSwap::onCopyDepositActionClicked()
{
    CopyListColumn( ui->swapsTable, 3 );
}

void InstaSwap::CopyListColumn( QTableWidget *QTW, int nColumn )
{
    // Find column info
    QItemSelectionModel* selectionModel = QTW->selectionModel();
    QModelIndexList selected = selectionModel->selectedRows();

    if (selected.count() == 0) return;

    QModelIndex index = selected.at(0);
    int nSelectedRow = index.row();
    QString strData = QTW->item(nSelectedRow, nColumn)->text();

    GUIUtil::setClipboard( strData );
}

void InstaSwap::on_addressBookButton_clicked()
{
    if (walletModel) {
        AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, this);
        dlg.setModel(walletModel->getAddressTableModel());
        if (dlg.exec())
            setAddress(dlg.getReturnValue(), ui->receivingAddressEdit);
    }
}

void InstaSwap::on_depositAmountEdit_textChanged(const QString &arg1)
{
    bool isNumeric = false;
    double value = arg1.toDouble( &isNumeric );
    if ( isNumeric && value>0 ) {
        QJsonDocument json = callTicker();

        if ( json.object()["apiInfo"]=="OK" && json.object().contains("response") && json.object()["response"].isObject() )
        {
            QJsonObject response = json.object()["response"].toObject();
            QString value = response["getAmount"].toString();
            ui->receivingAmountLabel->setText( value + " " + PURCHASECOIN );
        }
    }
}

bool InstaSwap::validateBitcoinAddress(QString address) {

    return address.contains(QRegExp("^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$"));
}

void InstaSwap::on_receivingAddressEdit_textChanged(const QString &arg1)
{
    if ( walletModel->validateAddress(arg1) )    {
        updateSwapList();
    }
}

void InstaSwap::on_sendSwapButton_clicked()
{
    if (!validateBitcoinAddress( ui->refundAddressEdit->text() ))  {
        QString error = QString("Please enter a valid BTC refund address");
        ui->errorLabel->setText( "ERROR: " + error );
        return;
    }

    QJsonDocument json = callDoSwap();

    if ( json.object()["apiInfo"]=="OK" && json.object().contains("response") && json.object()["response"].isObject() )
    {
        QJsonObject response = json.object()["response"].toObject();
        QString value = response["depositWallet"].toString();
        ui->errorLabel->setText( "Success, deposit address copied to clipboard: " + value );
        GUIUtil::setClipboard( value );
        updateSwapList();
    }
    else
    {
        QString error = QString("An error occurred while sending swap to Instaswap");
        ui->errorLabel->setText( "ERROR: " + error );
    }
}

void InstaSwap::on_allowedPairsCombo_currentIndexChanged(const QString &arg1)
{
    on_depositAmountEdit_textChanged(ui->depositAmountEdit->text());
}
