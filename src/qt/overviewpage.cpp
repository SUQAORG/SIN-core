// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/overviewpage.h>
#include <qt/forms/ui_overviewpage.h>

#include <qt/sinunits.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactiontablemodel.h>
#include <qt/utilitydialog.h>
#include <qt/walletmodel.h>
#include <wallet/wallet.h>
#include <validation.h>
#include <interfaces/node.h>

#include <init.h>
#include <util/system.h>
#include <shutdown.h>
#include <instantx.h>
#include <masternode-sync.h>
#include <infinitynodeman.h>

#include <QAbstractItemDelegate>
#include <QPainter>
#include <QSettings>
#include <QTimer>
#include <QDesktopServices>
#include <QUrl>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>


#define ICON_OFFSET 16
#define DECORATION_SIZE 54
#define NUM_ITEMS 3
#define NUM_ITEMS_ADV 7

Q_DECLARE_METATYPE(interfaces::WalletBalances)

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle *_platformStyle, QObject *parent=nullptr):
        QAbstractItemDelegate(parent), unit(BitcoinUnits::SIN),
        platformStyle(_platformStyle)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        mainRect.moveLeft(ICON_OFFSET);
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2*ypad)/2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top()+ypad, mainRect.width() - xspace - ICON_OFFSET, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top()+ypad+halfheight, mainRect.width() - xspace, halfheight);
        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if(value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, address, &boundingRect);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool())
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top()+ypad+halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if(amount < 0)
        {
            foreground = COLOR_NEGATIVE;
        }
        else if(!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = option.palette.color(QPalette::Text);
        }
        painter->setPen(foreground);

        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->setPen(option.palette.color(QPalette::Text));
        painter->drawText(amountRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

};
#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    timer(nullptr),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    pricingTimer = new QTimer();
    networkManager = new QNetworkAccessManager();
    request = new QNetworkRequest();
    pricingTimerBTC = new QTimer();
    networkManagerBTC = new QNetworkAccessManager();
    requestBTC = new QNetworkRequest();
    versionTimer = new QTimer();
    networkManagerVersion = new QNetworkAccessManager();
    requestVersion = new QNetworkRequest();
    ui->setupUi(this);
           
   // Set the Latest Version information
 // Network request code 
        QObject::connect(networkManagerVersion, &QNetworkAccessManager::finished,
                         this, [=](QNetworkReply *replyVersion) {  
                         
                    if (replyVersion->error()) {
                        ui->labelLatestVersion->setText("");
                        qDebug() << replyVersion->errorString();
                        return;
                    }
                    // Get the data from the network request
                    QString answerVersion = replyVersion->readAll();                                
                    
                    ui->labelLatestVersion->setText("<a style=\"color:#000000;\" href=\"https://github.com/SINOVATEblockchain/SIN-core/releases\">"+ answerVersion +"</a>");
                }
                );
   // End Latest Version information
         
         // Create the version timer
        connect(versionTimer, SIGNAL(timeout()), this, SLOT(getVersionInfo()));
        versionTimer->start(300000);
        getVersionInfo();
        /** version timer END */

    // Set the USD pricing information
       

        // Network request code 
        QObject::connect(networkManager, &QNetworkAccessManager::finished,
                         this, [=](QNetworkReply *reply) {  
                         
                    if (reply->error()) {
                        ui->labelCurrentPrice->setText("");
                        qDebug() << reply->errorString();
                        return;
                    }
                    // Get the data from the network request
                    QString answer = reply->readAll();

                    // Create regex expression to find the value with 8 decimals
                    QRegExp rx("\\d*.\\d\\d\\d\\d\\d\\d\\d\\d");
                    rx.indexIn(answer);

                    // List the found values
                    QStringList list = rx.capturedTexts();

                    QString currentPriceStyleSheet = ".QLabel{color: %1;}";
                    // Evaluate the current and next numbers and assign a color (green for positive, red for negative)
                    bool ok;
                    if (!list.isEmpty()) {
                        double next = list.first().toDouble(&ok);
                        if (!ok) {
                            ui->labelCurrentPrice->setStyleSheet(currentPriceStyleSheet.arg("#4960ad"));
                            ui->labelCurrentPrice->setText("");
                        } else {
                            double current = ui->labelCurrentPrice->text().toDouble(&ok);
                            if (!ok) {
                                current = 0.00000000;
                            } else {
                                if (next < current)
                                    ui->labelCurrentPrice->setStyleSheet(currentPriceStyleSheet.arg("red"));
                                else if (next > current)
                                    ui->labelCurrentPrice->setStyleSheet(currentPriceStyleSheet.arg("green"));
                                else
                                    ui->labelCurrentPrice->setStyleSheet(currentPriceStyleSheet.arg("black"));
                                    
                            }
                            ui->labelCurrentPrice->setText(QString("%1").arg(QString().setNum(next, 'f', 8)));
                            //ui->labelCurrentPrice->setToolTip(tr("Brought to you by coinmarketcap.com"));

                            QString total;
    						double current2 = (current * totalBalance / 100000000);
  							total = QString::number(current2, 'f', 2);
  							ui->labelUSDTotal->setText("$" + total + " USD");

                            
                        }
                    }
                }
        );

        
    
       

// Set the BTC pricing information
       

        // Network request code for the header widget
        QObject::connect(networkManagerBTC, &QNetworkAccessManager::finished,
                         this, [=](QNetworkReply *replyBTC) {  
                         
                    if (replyBTC->error()) {
                        ui->labelCurrentPriceBTC->setText("");
                        qDebug() << replyBTC->errorString();
                        return;
                    }
                    // Get the data from the network request
                    QString answerBTC = replyBTC->readAll();

                    // Create regex expression to find the value with 8 decimals
                    QRegExp rx("\\d*.\\d\\d\\d\\d\\d\\d\\d\\d");
                    rx.indexIn(answerBTC);

                    // List the found values
                    QStringList listBTC = rx.capturedTexts();

                    QString currentPriceStyleSheet = ".QLabel{color: %1;}";
                    // Evaluate the current and next numbers and assign a color (green for positive, red for negative)
                    bool ok;
                    if (!listBTC.isEmpty()) {
                        double next = listBTC.first().toDouble(&ok);
                        if (!ok) {
                            ui->labelCurrentPriceBTC->setStyleSheet(currentPriceStyleSheet.arg("#4960ad"));
                            ui->labelCurrentPriceBTC->setText("");
                        } else {
                            double currentBTC = ui->labelCurrentPriceBTC->text().toDouble(&ok);
                            if (!ok) {
                                currentBTC = 0.00000000;
                            } else {
                                if (next < currentBTC)
                                    ui->labelCurrentPriceBTC->setStyleSheet(currentPriceStyleSheet.arg("red"));
                                else if (next > currentBTC)
                                    ui->labelCurrentPriceBTC->setStyleSheet(currentPriceStyleSheet.arg("green"));
                                else
                                    ui->labelCurrentPriceBTC->setStyleSheet(currentPriceStyleSheet.arg("black"));
                                    
                            }
                            ui->labelCurrentPriceBTC->setText(QString("%1").arg(QString().setNum(next, 'f', 8)));
                            //ui->labelCurrentPriceBTC->setToolTip(tr("Brought to you by coinmarketcap.com"));

                            //QString total;
    						//double current2 = (current * totalBalance / 100000000);
  							//total = QString::number(current2, 'f', 2);
  							//ui->labelUSDTotal->setText("$" + total + " USD");

                            
                        }
                    }
                }
        );

        
    
        // Create the timer
        connect(pricingTimerBTC, SIGNAL(timeout()), this, SLOT(getPriceInfoBTC()));
        pricingTimerBTC->start(300000);
        getPriceInfoBTC();
        /** pricing BTC END */




    m_balances.balance = -1;

    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = platformStyle->SingleColorIcon(":/icons/warning");
    icon.addPixmap(icon.pixmap(QSize(64,64), QIcon::Normal), QIcon::Disabled); // also set the disabled icon because we are using a disabled QPushButton to work around missing HiDPI support of QLabel (https://bugreports.qt.io/browse/QTBUG-42503)
    ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText( tr("Out of Sync!"));
    ui->labelTransactionsStatus->setText(tr("Out of Sync!"));


    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));
    connect(ui->labelTransactionsStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));

    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(infinityNodeStat()));
    timer->start(3000);
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if(filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::handleOutOfSyncWarningClicks()
{
    Q_EMIT outOfSyncWarningClicked();
}

OverviewPage::~OverviewPage()
{
    if(timer) disconnect(timer, SIGNAL(timeout()), this, SLOT(privateSendStatus()));
    delete ui;
}

void OverviewPage::infinityNodeStat()
{
    std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();
    std::map<COutPoint, CInfinitynode> mapInfinitynodesNonMatured = infnodeman.GetFullInfinitynodeNonMaturedMap();
    int total = 0, totalBIG = 0, totalMID = 0, totalLIL = 0, totalUnknown = 0;
    for (auto& infpair : mapInfinitynodes) {
        ++total;
        CInfinitynode inf = infpair.second;
        int sintype = inf.getSINType();
        if (sintype == 10) ++totalBIG;
        else if (sintype == 5) ++totalMID;
        else if (sintype == 1) ++totalLIL;
    }

    int totalNonMatured = 0, totalBIGNonMatured = 0, totalMIDNonMatured = 0, totalLILNonMatured = 0, totalUnknownNonMatured = 0;
    for (auto& infpair : mapInfinitynodesNonMatured) {
        ++totalNonMatured;
        CInfinitynode inf = infpair.second;
        int sintype = inf.getSINType();
        if (sintype == 10) ++totalBIGNonMatured;
        else if (sintype == 5) ++totalMIDNonMatured;
        else if (sintype == 1) ++totalLILNonMatured;
    }

    
    //QString strTotalNodeText(tr("Total: %1 nodes (Last Scan: %2)").arg(total + totalNonMatured).arg(infnodeman.getLastScanWithLimit()));
    QString strTotalNodeText(tr("%1").arg(total + totalNonMatured));
    QString strLastScanText(tr("%1").arg(infnodeman.getLastScanWithLimit()));
    QString strBIGNodeText(tr("%1").arg(totalBIG));
    QString strMIDNodeText(tr("%1").arg(totalMID));
    QString strLILNodeText(tr("%1").arg(totalLIL));

    QString strBIGNodeQueuedText(tr("Starting %1").arg(totalBIGNonMatured));
    QString strMIDNodeQueuedText(tr("Starting %1").arg(totalMIDNonMatured));
    QString strLILNodeQueuedText(tr("Starting %1").arg(totalLILNonMatured));

    ui->labelStatisticTotalNode->setText(strTotalNodeText);
    ui->labelStatisticLastScan->setText(strLastScanText);
    ui->labelBIGNode->setText(strBIGNodeText);
    ui->labelMIDNode->setText(strMIDNodeText);
    ui->labelLILNode->setText(strLILNodeText);

    ui->labelBIGNodeQueued->setText(strBIGNodeQueuedText);
    ui->labelMIDNodeQueued->setText(strMIDNodeQueuedText);
    ui->labelLILNodeQueued->setText(strLILNodeQueuedText);

    //QString strBIGNodeROIText(tr("ROI %1 days").arg(infnodeman.getRoi(10, totalBIG)));
    //QString strMIDNodeROIText(tr("ROI %1 days").arg(infnodeman.getRoi(5, totalMID)));
    //QString strLILNodeROIText(tr("ROI %1 days").arg(infnodeman.getRoi(1, totalLIL)));

    //ui->labelBIGNodeRoi->setText(strBIGNodeROIText);
    //ui->labelMIDNodeRoi->setText(strMIDNodeROIText);
    //ui->labelLILNodeRoi->setText(strLILNodeROIText);

    QString strBIGNodeSTMText(tr("Payment Round\n%1").arg(infnodeman.getLastStatement(10)));
    QString strMIDNodeSTMText(tr("Payment Round\n%1").arg(infnodeman.getLastStatement(5)));
    QString strLILNodeSTMText(tr("Payment Round\n%1").arg(infnodeman.getLastStatement(1)));

    ui->labelBIGNodeSTM->setText(strBIGNodeSTMText);
    ui->labelMIDNodeSTM->setText(strMIDNodeSTMText);
    ui->labelLILNodeSTM->setText(strLILNodeSTMText);


}

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    m_balances = balances;
    totalBalance = balances.balance + balances.unconfirmed_balance + balances.immature_balance;
    ui->labelBalance->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.balance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.unconfirmed_balance, false, BitcoinUnits::separatorAlways));
    ui->labelImmature->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.immature_balance, false, BitcoinUnits::separatorAlways));
    ui->labelTotal->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.balance + balances.unconfirmed_balance + balances.immature_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchAvailable->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.watch_only_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.unconfirmed_watch_only_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.immature_watch_only_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.watch_only_balance + balances.unconfirmed_watch_only_balance + balances.immature_watch_only_balance, false, BitcoinUnits::separatorAlways));

     // Create the timer
        connect(pricingTimer, SIGNAL(timeout()), this, SLOT(getPriceInfo()));
        pricingTimer->start(300000);
        getPriceInfo();
        /** pricing USD END */

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = balances.immature_balance != 0;
    bool showWatchOnlyImmature = balances.immature_watch_only_balance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature); // show watch-only immature balance

    static int cachedTxLocks = 0;

    if(cachedTxLocks != nCompleteTXLocks){
        cachedTxLocks = nCompleteTXLocks;
        ui->listTransactions->update();
    }
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance

    if (!showWatchOnly){
        ui->labelWatchImmature->hide();
    }
    else{
        ui->labelBalance->setIndent(20);
        ui->labelUnconfirmed->setIndent(20);
        ui->labelImmature->setIndent(20);
        ui->labelTotal->setIndent(20);
    }
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if(model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        interfaces::Wallet& wallet = model->wallet();
        interfaces::WalletBalances balances = wallet.getBalances();
        setBalance(balances);
        connect(model, SIGNAL(balanceChanged(interfaces::WalletBalances)), this, SLOT(setBalance(interfaces::WalletBalances)));

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateWatchOnlyLabels(wallet.haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));

        // that's it for litemode
        if(fLiteMode) return;
    }
    // update the display unit, to not use the default ("SIN")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        if (m_balances.balance != -1) {
            setBalance(m_balances);
        }

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
    ui->labelTransactionsStatus->setVisible(fShow);
}

void OverviewPage::SetupTransactionList(int nNumItems) {
    ui->listTransactions->setMinimumHeight(nNumItems * (DECORATION_SIZE + 2));

    if(walletModel && walletModel->getOptionsModel()) {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(walletModel->getTransactionTableModel());
        filter->setLimit(nNumItems);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);
    }
}

void OverviewPage::getPriceInfo()
{
        request->setUrl(QUrl("https://sinovate.io/priceUSD.php"));
    
    networkManager->get(*request);
}

void OverviewPage::getPriceInfoBTC()
{
        requestBTC->setUrl(QUrl("https://sinovate.io/priceBTC.php"));
    
    networkManagerBTC->get(*requestBTC);
}


void OverviewPage::getVersionInfo()
{
        requestVersion->setUrl(QUrl("https://sinovate.io/getLatestVersion.php"));
    
    networkManagerVersion->get(*requestVersion);
}
