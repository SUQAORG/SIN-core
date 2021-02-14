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
#include <qt/transactiondescdialog.h>
#include <qt/utilitydialog.h>
#include <qt/walletmodel.h>
#include <wallet/wallet.h>
#include <validation.h>
#include <interfaces/node.h>
#include <init.h>
#include <util.h>
#include <shutdown.h>
#include <instantx.h>
#include <masternode-sync.h>
#include <qt/styleSheet.h>


#include <QAction>
#include <QAbstractItemDelegate>
#include <QPainter>
#include <QSettings>
#include <QTimer>
#include <QDesktopServices>
#include <QUrl>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QToolButton>

#define NUM_ITEMS 5
#define MARGIN 5
#define SYMBOL_WIDTH 80

#define TX_SIZE 40
#define DECORATION_SIZE 20
#define DATE_WIDTH 110
#define TYPE_WIDTH 140
#define AMOUNT_WIDTH 205

#define BUTTON_ICON_SIZE 24

Q_DECLARE_METATYPE(interfaces::WalletBalances)


class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    explicit TxViewDelegate(const PlatformStyle *_platformStyle, QObject *parent=nullptr):
        QAbstractItemDelegate(parent), unit(BitcoinUnits::SIN),
        platformStyle(_platformStyle)
    {
        background_color_selected = GetStringStyleValue("txviewdelegate/background-color-selected", "#009ee5");
        background_color = GetStringStyleValue("txviewdelegate/background-color", "#393939");
        alternate_background_color = GetStringStyleValue("txviewdelegate/alternate-background-color", "#2e2e2e");
        foreground_color = GetStringStyleValue("txviewdelegate/foreground-color", "#dedede");
        foreground_color_selected = GetStringStyleValue("txviewdelegate/foreground-color-selected", "#ffffff");
        amount_color = GetStringStyleValue("txviewdelegate/amount-color", "#ffffff");
        color_unconfirmed = GetColorStyleValue("guiconstants/color-unconfirmed", COLOR_UNCONFIRMED);
        color_negative = GetColorStyleValue("guiconstants/color-negative", COLOR_NEGATIVE);
    
    }


    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
                      const QModelIndex &index ) const
    {
        painter->save();
        bool selected = option.state & QStyle::State_Selected;
        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        if(selected)
        {
            icon = PlatformStyle::SingleColorIcon(icon, foreground_color_selected);
        }
        QString address = index.data(Qt::DisplayRole).toString();
        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();

        QModelIndex ind = index.model()->index(index.row(), TransactionTableModel::Type, index.parent());
        QString typeString = ind.data(Qt::DisplayRole).toString();

        QRect mainRect = option.rect;
        QColor txColor = index.row() % 2 ? background_color : alternate_background_color;
        painter->fillRect(mainRect, txColor);

        if(selected)
        {
            painter->fillRect(mainRect.x()+1, mainRect.y()+1, mainRect.width()-2, mainRect.height()-2, background_color_selected);
        }

        QColor foreground = foreground_color;
        if(selected)
        {
            foreground = foreground_color_selected;
        }
        painter->setPen(foreground);

        QRect dateRect(mainRect.left() + MARGIN, mainRect.top(), DATE_WIDTH, TX_SIZE);
        painter->drawText(dateRect, Qt::AlignLeft|Qt::AlignVCenter, GUIUtil::dateTimeStr(date));

        int topMargin = (TX_SIZE - DECORATION_SIZE) / 2;
        QRect decorationRect(dateRect.topRight() + QPoint(MARGIN, topMargin), QSize(DECORATION_SIZE, DECORATION_SIZE));
        icon.paint(painter, decorationRect);

        QRect typeRect(decorationRect.right() + MARGIN, mainRect.top(), TYPE_WIDTH, TX_SIZE);
        painter->drawText(typeRect, Qt::AlignLeft|Qt::AlignVCenter, typeString);

        bool watchOnly = index.data(TransactionTableModel::WatchonlyRole).toBool();

        if (watchOnly)
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            if(selected)
            {
                iconWatchonly = PlatformStyle::SingleColorIcon(iconWatchonly, foreground_color_selected);
            }
            QRect watchonlyRect(typeRect.right() + MARGIN, mainRect.top() + topMargin, DECORATION_SIZE, DECORATION_SIZE);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        int addressMargin = watchOnly ? MARGIN + 20 : MARGIN;
        int addressWidth = mainRect.width() - DATE_WIDTH - DECORATION_SIZE - TYPE_WIDTH - AMOUNT_WIDTH - 5*MARGIN;
        addressWidth = watchOnly ? addressWidth - 20 : addressWidth;

        QFont addressFont = option.font;
        addressFont.setPointSizeF(addressFont.pointSizeF() * 0.95);
        painter->setFont(addressFont);

        QFontMetrics fmName(painter->font());
        QString clippedAddress = fmName.elidedText(address, Qt::ElideRight, addressWidth);

        QRect addressRect(typeRect.right() + addressMargin, mainRect.top(), addressWidth, TX_SIZE);
        painter->drawText(addressRect, Qt::AlignLeft|Qt::AlignVCenter, clippedAddress);

        QFont amountFont = option.font;
        painter->setFont(amountFont);

        if(amount < 0)
        {
            foreground = color_negative;
        }
        else if(!confirmed)
        {
            foreground = color_unconfirmed;
        }
        else
        {
            foreground = amount_color;
        }

        if(selected)
        {
            foreground = foreground_color_selected;
        }
        painter->setPen(foreground);

        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        if(!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }

        QRect amountRect(addressRect.right() + MARGIN, addressRect.top(), AMOUNT_WIDTH, TX_SIZE);
        painter->drawText(amountRect, Qt::AlignRight|Qt::AlignVCenter, amountText);

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(TX_SIZE, TX_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

private:
    QColor background_color_selected;
    QColor background_color;
    QColor alternate_background_color;
    QColor foreground_color;
    QColor foreground_color_selected;
    QColor amount_color;
    QColor color_unconfirmed;
    QColor color_negative;

    
};
#include <qt/overviewpage.moc>

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    // ++ Explorer Stats
    m_timer(nullptr),
    // --
    
    ui(new Ui::OverviewPage),
    
    m_networkManager(new QNetworkAccessManager(this)),
    clientModel(0),
    walletModel(0),
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    pricingTimer = new QTimer();
    pricingTimerEUR = new QTimer();
    networkManager = new QNetworkAccessManager();
    networkManagerEUR = new QNetworkAccessManager();
    request = new QNetworkRequest();
    requestEUR = new QNetworkRequest();
    
    ui->setupUi(this);

    ui->toolButtonBlog->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    //ui->toolButtonBlog->setIcon(QIcon(":/icons/blog_blue"));
    ui->toolButtonBlog->setIconSize(QSize(64, 64));
    ui->toolButtonBlog->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/blog_white",PlatformStyle::NavBar));
   
    ui->toolButtonBlog->setStatusTip(tr("Visit Sinovate Blog"));

    ui->toolButtonDocs->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonDocs->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/docs_white",PlatformStyle::NavBar));
    ui->toolButtonDocs->setIconSize(QSize(64, 64));
    ui->toolButtonDocs->setStatusTip(tr("Visit Sinovate Docs"));

    
    ui->toolButtonExchanges->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonExchanges->setIconSize(QSize(64, 64));
    ui->toolButtonExchanges->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/cmc_white",PlatformStyle::NavBar));
    ui->toolButtonExchanges->setStatusTip(tr("Buy Sinovate Coin"));

    ui->toolButtonExplorer->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonExplorer->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/explorer_white",PlatformStyle::NavBar));
    ui->toolButtonExplorer->setIconSize(QSize(64, 64));
    ui->toolButtonExplorer->setStatusTip(tr("Visit Sinovate Block Explorer"));

    ui->toolButtonDiscord->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonDiscord->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/discord_white",PlatformStyle::NavBar));
    ui->toolButtonDiscord->setIconSize(QSize(64, 64));
    ui->toolButtonDiscord->setStatusTip(tr("Visit Sinovate Discord Channel"));

    ui->toolButtonRoadmap->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonRoadmap->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/roadmap_white",PlatformStyle::NavBar));
    ui->toolButtonRoadmap->setIconSize(QSize(64, 64));
    ui->toolButtonRoadmap->setStatusTip(tr("Sinovate Roadmap"));

    ui->toolButtonWebTool->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonWebTool->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/webtool_white",PlatformStyle::NavBar));
    ui->toolButtonWebTool->setIconSize(QSize(64, 64));
    ui->toolButtonWebTool->setStatusTip(tr("Visit Sinovate WebTool"));

    ui->toolButtonWallet->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonWallet->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/download_white",PlatformStyle::NavBar));
    ui->toolButtonWallet->setIconSize(QSize(64, 64));
    ui->toolButtonWallet->setStatusTip(tr("Download Latest Sinovate Wallets"));

    ui->toolButtonWhitePaper->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonWhitePaper->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/whitepaper_white",PlatformStyle::NavBar));
    ui->toolButtonWhitePaper->setIconSize(QSize(64, 64));
    ui->toolButtonWhitePaper->setStatusTip(tr("Sinovate WhitePaper"));

    ui->toolButtonFaq->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    ui->toolButtonFaq->setIcon(platformStyle->MultiStatesIcon(":/styles/theme2/app-icons/faq_white",PlatformStyle::NavBar));
    ui->toolButtonFaq->setIconSize(QSize(64, 64));
    ui->toolButtonFaq->setStatusTip(tr("Open FAQ Page"));

    ui->buttonSend->setIcon(platformStyle->MultiStatesIcon(":/icons/send", PlatformStyle::PushButton));
    ui->buttonSend->setIconSize(QSize(BUTTON_ICON_SIZE, BUTTON_ICON_SIZE));

    ui->buttonReceive->setIcon(platformStyle->MultiStatesIcon(":/icons/receiving_addresses", PlatformStyle::PushButton));
    ui->buttonReceive->setIconSize(QSize(BUTTON_ICON_SIZE, BUTTON_ICON_SIZE));
    
    
    // ++ Explorer Stats
    m_timer = new QTimer(this);
    connect(m_timer, SIGNAL(timeout()), this, SLOT(getStatistics()));
    m_timer->start(30000);
    connect(m_networkManager, SIGNAL(finished(QNetworkReply*)), this, SLOT(onResult(QNetworkReply*)));
    getStatistics();
    // --

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

                    QString currentPriceStyleSheet = ".QLabel{color: %1; font-size:12px;}";
                    // Evaluate the current and next numbers and assign a color (green for positive, red for negative)
                    bool ok;
                    if (!list.isEmpty()) {
                        double next = list.first().toDouble(&ok);
                        if (!ok) {
                            ui->labelCurrentPrice->setStyleSheet(".QLabel{font-size:12px;}");
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
                                    ui->labelCurrentPrice->setStyleSheet(".QLabel{font-size:12px;}");
                                    
                            }
                            ui->labelCurrentPrice->setText(QString("%1").arg(QString().setNum(next, 'f', 8)));
                            
                            QString total;
                            double current2 = (current * totalBalance / 100000000);
                            total = QString::number(current2, 'f', 2);
                            ui->labelUSDTotal->setText("$" + total + " USD");
                        }
                    }
                }
        );

     //--

     // Set the EUR pricing information
       

        // Network request code 
        QObject::connect(networkManagerEUR, &QNetworkAccessManager::finished,
                         this, [=](QNetworkReply *replyEUR) {  
                         
                    if (replyEUR->error()) {
                        ui->labelCurrentEURPrice->setText("");
                        qDebug() << replyEUR->errorString();
                        return;
                    }
                    // Get the data from the network request
                    QString answerEUR = replyEUR->readAll();

                    // Create regex expression to find the value with 8 decimals
                    QRegExp rxEUR("\\d*.\\d\\d\\d\\d\\d\\d\\d\\d");
                    rxEUR.indexIn(answerEUR);

                    // List the found values
                    QStringList listEUR = rxEUR.capturedTexts();

                    QString currentPriceStyleSheet = ".QLabel{color: %1; font-size:14px;}";
                    // Evaluate the current and next numbers and assign a color (green for positive, red for negative)
                    bool okEUR;
                    if (!listEUR.isEmpty()) {
                        double next = listEUR.first().toDouble(&okEUR);
                        if (!okEUR) {
                            ui->labelCurrentEURPrice->setStyleSheet(".QLabel{font-size:14px;}");
                            ui->labelCurrentEURPrice->setText("");
                        } else {
                            double currentEUR = ui->labelCurrentEURPrice->text().toDouble(&okEUR);
                            if (!okEUR) {
                                currentEUR = 0.00000000;
                            } else {
                                if (next < currentEUR)
                                    ui->labelCurrentEURPrice->setStyleSheet(currentPriceStyleSheet.arg("red"));
                                else if (next > currentEUR)
                                    ui->labelCurrentEURPrice->setStyleSheet(currentPriceStyleSheet.arg("green"));
                                else
                                    ui->labelCurrentEURPrice->setStyleSheet(".QLabel{font-size:14px;}");
                                    
                            }
                            ui->labelCurrentEURPrice->setText(QString("%1").arg(QString().setNum(next, 'f', 8)));
                            
                            QString totalEUR;
                            double current2EUR = (currentEUR * totalBalance / 100000000);
                            totalEUR = QString::number(current2EUR, 'f', 2);
                            //ui->labelEURTotal->setText("€" + totalEUR + " EUR");
                        }
                    }
                }
        );
//--  

    m_balances.balance = -1;

    // use a SingleColorIcon for the "out of sync warning" icon
    //QIcon icon = platformStyle->SingleColorIcon(":/icons/warning", "#009ee5");
    QIcon icon = PlatformStyle::SingleColorIcon(":/icons/warning", "#009ee5");
    icon.addPixmap(icon.pixmap(QSize(24,24), QIcon::Normal), QIcon::Disabled); // also set the disabled icon because we are using a disabled QPushButton to work around missing HiDPI support of QLabel (https://bugreports.qt.io/browse/QTBUG-42503)
    //to do
    //ui->labelTransactionsStatus->setIcon(icon);
    ui->labelWalletStatus->setIcon(icon);

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);
    ui->listTransactions->setSelectionBehavior(QAbstractItemView::SelectRows);
 
       
    //connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));
    connect(ui->listTransactions, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(showDetails()));

    // init "out of sync" warning labels
    ui->labelWalletStatus->setText( tr(""));
    // to do
    //ui->labelTransactionsStatus->setText(tr("Out of Sync!"));


    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    connect(ui->labelWalletStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));
    // to do
    //connect(ui->labelTransactionsStatus, SIGNAL(clicked()), this, SLOT(handleOutOfSyncWarningClicks()));

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
    // ++ Explorer Stats
    if(m_timer) disconnect(m_timer, SIGNAL(timeout()), this, SLOT(privateSendStatus()));
    delete m_networkManager;
    // --

    delete ui;
}


// ++ Explorer Stats
void OverviewPage::getStatistics()
{
    QUrl summaryUrl("https://explorer.sinovate.io/ext/summary");
    QNetworkRequest request;
    request.setUrl(summaryUrl);
    m_networkManager->get(request);
}
// --

void OverviewPage::setBalance(const interfaces::WalletBalances& balances)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    m_balances = balances;
    totalBalance = balances.balance + balances.unconfirmed_balance + balances.immature_balance;
    ui->labelBalance->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.balance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::format(unit, balances.unconfirmed_balance, false, BitcoinUnits::separatorAlways));
    ui->labelImmature->setText(BitcoinUnits::format(unit, balances.immature_balance, false, BitcoinUnits::separatorAlways));
    //to do
    //ui->labelTotal->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.balance + balances.unconfirmed_balance + balances.immature_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchAvailable->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.watch_only_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchPending->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.unconfirmed_watch_only_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchImmature->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.immature_watch_only_balance, false, BitcoinUnits::separatorAlways));
    ui->labelWatchTotal->setText(BitcoinUnits::floorHtmlWithUnit(unit, balances.watch_only_balance + balances.unconfirmed_watch_only_balance + balances.immature_watch_only_balance, false, BitcoinUnits::separatorAlways));

     // Create the timer
        connect(pricingTimer, SIGNAL(timeout()), this, SLOT(getPriceInfo()));
        pricingTimer->start(300000);
        getPriceInfo();
        /** pricing USD END */

        // Create the timer
        connect(pricingTimerEUR, SIGNAL(timeout()), this, SLOT(getPriceInfoEur()));
        pricingTimerEUR->start(300000);
        getPriceInfoEur();
        /** pricing EUR END */

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = balances.immature_balance != 0;
    bool showWatchOnlyImmature = balances.immature_watch_only_balance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    //ui->labelImmature->setVisible(showImmature || showWatchOnlyImmature);
    //ui->labelImmatureText->setVisible(showImmature || showWatchOnlyImmature);
    // For visual reasons, the Immature label will be constantly shown.
    ui->labelImmature;
    ui->labelImmatureText;
    //
    ui->labelWatchImmature->setVisible(showWatchOnlyImmature); // show watch-only immature balance

    static int cachedTxLocks = 0;

    if(cachedTxLocks != nCompleteTXLocks){
        cachedTxLocks = nCompleteTXLocks;
        //ui->listTransactions->update();
    }
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{
    //ui->labelSpendable->setVisible(showWatchOnly);      // show spendable label (only when watch-only is active)
    ui->labelWatchonly->setVisible(showWatchOnly);      // show watch-only label
    //ui->lineWatchBalance->setVisible(showWatchOnly);    // show watch-only balance separator line
    ui->labelWatchAvailable->setVisible(showWatchOnly); // show watch-only available balance
    ui->labelWatchPending->setVisible(showWatchOnly);   // show watch-only pending balance
    ui->labelWatchTotal->setVisible(showWatchOnly);     // show watch-only total balance
    ui->watchOnlyFrame->setVisible(showWatchOnly);
    
    if (!showWatchOnly){
        ui->labelWatchImmature->hide();

    }
    else{
        ui->labelBalance->setIndent(20);
        ui->labelUnconfirmed->setIndent(20);
        ui->labelImmature->setIndent(20);
        //to do
        //ui->labelTotal->setIndent(20);
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
    ui->layoutWarning->setVisible(fShow);
    // to do
    //ui->labelTransactionsStatus->setVisible(fShow);
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
        request->setUrl(QUrl("https://stats.sinovate.io/priceUSD.php"));
    
    networkManager->get(*request);
}

void OverviewPage::getPriceInfoEur()
{
        requestEUR->setUrl(QUrl("https://stats.sinovate.io/priceEUR.php"));
    
    networkManagerEUR->get(*requestEUR);
}


// ++ BTC Value Stats and Available BTC Total
void OverviewPage::onResult(QNetworkReply* replystats)
{
    QVariant statusCode = replystats->attribute(QNetworkRequest::HttpStatusCodeAttribute);

    if( statusCode == 200)
    {
        QString replyString = (QString) replystats->readAll();

        QJsonDocument jsonResponse = QJsonDocument::fromJson(replyString.toUtf8());
        QJsonObject jsonObject = jsonResponse.object();

        QJsonObject dataObject = jsonObject.value("data").toArray()[0].toObject();

        QLocale l = QLocale(QLocale::English);

        // Set LatestBTC strings
        ui->labelCurrentPriceBTC->setText(QString::number(dataObject.value("lastPrice").toDouble(), 'f', 8)); 

        double currentBTC = dataObject.value("lastPrice").toDouble();
        double availableBTC = (currentBTC * totalBalance / 100000000);
        ui->labelBTCTotal->setText(QString::number(availableBTC, 'f', 8) + " BTC");
       
    }
    else
    {
        const QString noValue = "NaN";
       
        ui->labelCurrentPriceBTC->setText(noValue);
       
    }

    replystats->deleteLater();
}


void OverviewPage::showTransactionWidget(bool bShow)   {
    if (bShow)  {
    ui->buttonWidget->show();
    ui->recentWidget->show();
    ui->recentHeaderWidget->show();
    ui->line->show();
    }
    else {        
        ui->buttonWidget->hide();
        ui->recentWidget->hide();
        ui->recentHeaderWidget->hide();
        ui->line->hide();
    }
}

void OverviewPage::showToolBoxWidget(bool bShow)   {
    if (bShow) {  
        ui->toolBoxWidget->show();
        ui->buttonWidget->hide();
        ui->recentWidget->hide();
        ui->recentHeaderWidget->hide();
        ui->line->hide();
    }
    else {         
        ui->toolBoxWidget->hide();
        ui->buttonWidget->show();
        ui->recentWidget->show();
        ui->recentHeaderWidget->show();
        ui->line->show();
    }
}

void OverviewPage::on_buttonSend_clicked()
{
    Q_EMIT sendCoinsClicked();
}

void OverviewPage::on_buttonReceive_clicked()
{
    Q_EMIT receiveCoinsClicked();
}

void OverviewPage::on_buttonMore_clicked()
{
    Q_EMIT moreClicked();
}

void OverviewPage::on_toolButtonFaq_clicked()
{
    Q_EMIT toolButtonFaqClicked();
}

void OverviewPage::on_toolButtonDiscord_clicked() {
    QDesktopServices::openUrl(QUrl("https://sinovate.io/links/discord/", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonBlog_clicked() {
    QDesktopServices::openUrl(QUrl("https://sinovate.io/blog/", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonDocs_clicked() {
    QDesktopServices::openUrl(QUrl("https://docs.sinovate.io/", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonExchanges_clicked() {
    QDesktopServices::openUrl(QUrl("https://coinmarketcap.com/currencies/sinovate/markets/", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonExplorer_clicked() {
    QDesktopServices::openUrl(QUrl("https://explorer.sinovate.io/", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonRoadmap_clicked() {
    QDesktopServices::openUrl(QUrl("https://sinovate.io/roadmap/", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonWallet_clicked() {
    QDesktopServices::openUrl(QUrl("https://github.com/SINOVATEblockchain/SIN-core/releases", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonWebTool_clicked() {
    QDesktopServices::openUrl(QUrl("https://github.com/SINOVATEblockchain/SINWebTool", QUrl::TolerantMode));
}

void OverviewPage::on_toolButtonWhitePaper_clicked() {
    QDesktopServices::openUrl(QUrl("https://docs.sinovate.io/#/sin_webtool_guide/", QUrl::TolerantMode));
}

void OverviewPage::showDetails()
{
    if(!ui->listTransactions->selectionModel())
        return;
    QModelIndexList selection = ui->listTransactions->selectionModel()->selectedRows();
    if(!selection.isEmpty())
    {
        TransactionDescDialog *dlg = new TransactionDescDialog(selection.at(0));
        dlg->setAttribute(Qt::WA_DeleteOnClose);
        dlg->show();
    }
}

// --
