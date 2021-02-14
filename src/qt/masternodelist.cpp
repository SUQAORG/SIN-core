// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 FXTC developers
// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/masternodelist.h>
#include <qt/forms/ui_masternodelist.h>

#include <activemasternode.h>
#include <clientversion.h>
#include <qt/sinunits.h>
#include <interfaces/wallet.h>
#include <interfaces/node.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/guiutil.h>
#include <qt/styleSheet.h>
#include <init.h>
#include <key_io.h>
#include <core_io.h>
#include <masternode-sync.h>
#include <masternodeconfig.h>
#include <masternodeman.h>
//SIN
#include <infinitynode.h>
#include <infinitynodeman.h>
#include <infinitynodemeta.h>
//
#include <sync.h>
#include <wallet/wallet.h>
#include <qt/walletmodel.h>

#include <QDialog>
#include <QInputDialog>
#include <QTimer>
#include <QMessageBox>
#include <QStyleFactory>
#include <QDesktopServices>
#include <QTextCodec>
#include <QSignalMapper>

// begin nodeSetup
#include <boost/algorithm/string.hpp>
#include "rpc/server.h"
#include "rpc/client.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QSettings>
#include <QNetworkAccessManager>
#include <QUrl>
#include <QUrlQuery>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QMovie>

UniValue nodeSetupCallRPC(std::string args);
// end nodeSetup

int GetOffsetFromUtc()
{
#if QT_VERSION < 0x050200
    const QDateTime dateTime1 = QDateTime::currentDateTime();
    const QDateTime dateTime2 = QDateTime(dateTime1.date(), dateTime1.time(), Qt::UTC);
    return dateTime1.secsTo(dateTime2);
#else
    return QDateTime::currentDateTime().offsetFromUtc();
#endif
}

bool DINColumnsEventHandler::eventFilter(QObject *pQObj, QEvent *pQEvent)
{
  if (pQEvent->type() == QEvent::MouseButtonRelease) {
     if ( QMenu* menu = dynamic_cast<QMenu*>(pQObj) ) {
         QAction *action = menu->activeAction();
         if (action) {
             action->trigger();
         }
         return true;    // don't close menu
     }
  }
  // standard event processing
  return QObject::eventFilter(pQObj, pQEvent);
}

MasternodeList::MasternodeList(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    // ++ DIN ROI Stats
    m_timer(nullptr),
    // --
    ui(new Ui::MasternodeList),
    m_networkManager(new QNetworkAccessManager(this)),
    clientModel(0),
    walletModel(0)
{
    ui->setupUi(this);

    // ++ DIN ROI Stats
    m_timer = new QTimer(this);
    connect(m_timer, SIGNAL(timeout()), this, SLOT(getStatistics()));
    m_timer->start(300000);
    connect(m_networkManager, SIGNAL(finished(QNetworkReply*)), this, SLOT(onResult(QNetworkReply*)));
    getStatistics();
    // --


    //ui->btnSetup->setIcon(QIcon(":/icons/setup"));
    //ui->btnSetup->setIconSize(QSize(177, 26));
    
    ui->dinTable->setContextMenuPolicy(Qt::CustomContextMenu);

    mCheckNodeAction = new QAction(tr("Check node status"), this);
    contextDINMenu = new QMenu();
    contextDINMenu->addAction(mCheckNodeAction);
    connect(ui->dinTable, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showContextDINMenu(const QPoint&)));
    connect(mCheckNodeAction, SIGNAL(triggered()), this, SLOT(on_checkDINNode()));

    mCheckAllNodesAction = new QAction(tr("Check ALL nodes status"), this);
    contextDINMenu->addAction(mCheckAllNodesAction);
    connect(mCheckAllNodesAction, SIGNAL(triggered()), this, SLOT(nodeSetupCheckAllDINNodes()));

    // select columns context menu
    QHeaderView *horizontalHeader;
    horizontalHeader = ui->dinTable->horizontalHeader();
    horizontalHeader->setContextMenuPolicy(Qt::CustomContextMenu);     //set contextmenu
    contextDINColumnsMenu = new QMenu();
    menuEventHandler = new DINColumnsEventHandler();
    contextDINColumnsMenu->installEventFilter(menuEventHandler);

    connect(horizontalHeader, SIGNAL(customContextMenuRequested(const QPoint&)), this, SLOT(showContextDINColumnsMenu(const QPoint&)));

    int columnID = 0;
    QTableWidgetItem *headerItem;
    QSignalMapper* signalMapper = new QSignalMapper (this) ;
    QSettings settings;

    while ( (headerItem = ui->dinTable->horizontalHeaderItem(columnID)) != nullptr )   {
        QAction * actionCheckColumnVisible = new QAction(headerItem->text(), this);
        bool bCheck = settings.value("bShowDINColumn_"+QString::number(columnID), true).toBool();
        if (!bCheck)    ui->dinTable->setColumnHidden( columnID, true);

        actionCheckColumnVisible->setCheckable(true);
        actionCheckColumnVisible->setChecked(bCheck);
        contextDINColumnsMenu->addAction(actionCheckColumnVisible);

        connect (actionCheckColumnVisible, SIGNAL(triggered()), signalMapper, SLOT(map())) ;
        signalMapper->setMapping (actionCheckColumnVisible, columnID) ;

        contextDINColumnsActions.push_back( std::make_pair(columnID, actionCheckColumnVisible) );
        columnID++;
    }
    connect (signalMapper, SIGNAL(mapped(int)), this, SLOT(nodeSetupDINColumnToggle( int )));

    // timers
    timerSingleShot = new QTimer(this);
    connect(timerSingleShot, SIGNAL(timeout()), this, SLOT(updateDINList()));
    timerSingleShot->setSingleShot(true);
    timerSingleShot->start(1000);

    fFilterUpdated = false;
    nTimeFilterUpdated = GetTime();
    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(updateDINList()));
    timer->start(60000);
    updateDINList();

    // DIN list filtering
    // Delay before filtering transactions in ms
    static const int input_filter_delay = 500;

    QTimer* prefix_typing_delay = new QTimer(this);
    prefix_typing_delay->setSingleShot(true);
    prefix_typing_delay->setInterval(input_filter_delay);

    connect(ui->searchOwnerAddr, SIGNAL(textChanged(QString)), prefix_typing_delay, SLOT(start()));
    connect(prefix_typing_delay, SIGNAL(timeout()), this, SLOT(updateDINList()));
    connect(ui->searchIP, SIGNAL(textChanged(QString)), prefix_typing_delay, SLOT(start()));
    connect(prefix_typing_delay, SIGNAL(timeout()), this, SLOT(updateDINList()));
    connect(ui->searchPeerAddr, SIGNAL(textChanged(QString)), prefix_typing_delay, SLOT(start()));
    connect(prefix_typing_delay, SIGNAL(timeout()), this, SLOT(updateDINList()));
    connect(ui->searchBurnTx, SIGNAL(textChanged(QString)), prefix_typing_delay, SLOT(start()));
    connect(prefix_typing_delay, SIGNAL(timeout()), this, SLOT(updateDINList()));
    connect(ui->searchBackupAddr, SIGNAL(textChanged(QString)), prefix_typing_delay, SLOT(start()));
    connect(prefix_typing_delay, SIGNAL(timeout()), this, SLOT(updateDINList()));

    connect(ui->comboStatus, SIGNAL(currentIndexChanged(const QString&)), this, SLOT(updateDINList()));
    connect(ui->comboTier, SIGNAL(currentIndexChanged(const QString&)), this, SLOT(updateDINList()));

    // node setup
    std::string baseURL = ( Params().NetworkIDString() == CBaseChainParams::TESTNET ) ? "https://setup2dev.sinovate.io" : "https://setup.sinovate.io";
    NODESETUP_ENDPOINT_NODE = QString::fromStdString(gArgs.GetArg("-nodesetupurl", baseURL + "/includes/api/nodecp.php"));
    NODESETUP_ENDPOINT_BASIC = QString::fromStdString(gArgs.GetArg("-nodesetupurlbasic", baseURL + "/includes/api/basic.php"));
    NODESETUP_RESTORE_URL = QString::fromStdString(gArgs.GetArg("-nodesetupurlrestore", baseURL + "/index.php?rp=/password/reset/begin"));
    NODESETUP_SUPPORT_URL = QString::fromStdString(gArgs.GetArg("-nodesetupsupporturl", baseURL + "/submitticket.php"));
    NODESETUP_PID = ( Params().NetworkIDString() == CBaseChainParams::TESTNET ) ? "1" : "22";
    NODESETUP_UPDATEMETA_AMOUNT = ( Params().NetworkIDString() == CBaseChainParams::TESTNET ) ? 5 : 25;
    NODESETUP_CONFIRMS = 2;
    NODESETUP_REFRESHCOMBOS = 6;
    nodeSetup_RefreshCounter = NODESETUP_REFRESHCOMBOS;

    // define timers
    invoiceTimer = new QTimer(this);
    connect(invoiceTimer, SIGNAL(timeout()), this, SLOT(nodeSetupCheckInvoiceStatus()));

    burnPrepareTimer = new QTimer(this);
    connect(burnPrepareTimer, SIGNAL(timeout()), this, SLOT(nodeSetupCheckBurnPrepareConfirmations()));

    burnSendTimer = new QTimer(this);
    connect(burnSendTimer, SIGNAL(timeout()), this, SLOT(nodeSetupCheckBurnSendConfirmations()));

    pendingPaymentsTimer = new QTimer(this);
    connect(pendingPaymentsTimer, SIGNAL(timeout()), this, SLOT(nodeSetupCheckPendingPayments()));

    checkAllNodesTimer = new QTimer(this);
    connect(checkAllNodesTimer, SIGNAL(timeout()), this, SLOT(nodeSetupCheckDINNodeTimer()));

    nodeSetupInitialize();
}

MasternodeList::~MasternodeList()
{
    delete ui;
    delete ConnectionManager;
    delete mCheckNodeAction;
    delete mCheckAllNodesAction;
    for(auto const& value: contextDINColumnsActions) {
        delete value.second;
    }
    delete contextDINMenu;
    delete contextDINColumnsMenu;
    delete menuEventHandler;
}

void MasternodeList::setClientModel(ClientModel *model)
{
    this->clientModel = model;
}

void MasternodeList::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void MasternodeList::showContextDINMenu(const QPoint &point)
{
    QTableWidgetItem *item = ui->dinTable->itemAt(point);
    if(item)    {
        contextDINMenu->exec(QCursor::pos());
    }
}

void MasternodeList::showContextDINColumnsMenu(const QPoint &point)
{
    contextDINColumnsMenu->exec(QCursor::pos());
}

void MasternodeList::updateDINList()
{
    if(walletModel && walletModel->getOptionsModel())
    {
        std::map<COutPoint, std::string> mOnchainDataInfo = walletModel->wallet().GetOnchainDataInfo();
        std::map<COutPoint, std::string> mapMynode;
        std::map<std::string, int> mapLockRewardHeight;

        ui->dinTable->setSortingEnabled(false);

        interfaces::Node& node = clientModel->node();
        int nCurrentHeight = node.getNumBlocks();
        ui->currentHeightLabel->setText(QString::number(nCurrentHeight));

        int countNode = 0;
        for(auto &pair : mOnchainDataInfo){
            string s, sDataType = "", sData1 = "", sData2 = "";
            stringstream ss(pair.second);
            int i=0;
            while (getline(ss, s,';')) {
                if (i==0) {
                    sDataType = s;
                }
                if (i==1) {
                    sData1 = s;
                }
                if (i==2) {
                    sData2 = s;
                }
                if(sDataType == "NodeCreation"){
                    mapMynode[pair.first] = sData1;
                } else if(sDataType == "LockReward" && i==2){
                    int nRewardHeight = atoi(sData2);
                    if(nRewardHeight > nCurrentHeight){
                        mapLockRewardHeight[sData1] = nRewardHeight;
                    }
                }
                i++;
            }
        }

        ui->dinTable->setRowCount(0);

        // update used burn tx map
        nodeSetupUsedBurnTxs.clear();

        bool bNeedToQueryAPIServiceId = false;
        int serviceId;
        int k=0;
        int nIncomplete = 0, nExpired = 0, nReady = 0;
        for(auto &pair : mapMynode){
            infinitynode_info_t infoInf;
            std::string status = "Unknown", sPeerAddress = "";
            QString strIP = "---";
            if(!infnodeman.GetInfinitynodeInfo(pair.first, infoInf)){
                continue;
            }
            CMetadata metadata = infnodemeta.Find(infoInf.metadataID);
            std::string burnfundTxId = infoInf.vinBurnFund.prevout.hash.ToString().substr(0, 16);
            QString strBurnTx = QString::fromStdString(burnfundTxId).left(16);

            if (metadata.getMetadataHeight() == 0 || metadata.getMetaPublicKey() == "" ){
                status="Incomplete";
            } else {
                status="Ready";

                std::string metaPublicKey = metadata.getMetaPublicKey();
                std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
                if(tx_data.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE){
                    CPubKey pubKey(tx_data.begin(), tx_data.end());
                    CTxDestination dest = GetDestinationForKey(pubKey, DEFAULT_ADDRESS_TYPE);
                    sPeerAddress = EncodeDestination(dest);
                }
                strIP = QString::fromStdString(metadata.getService().ToString());
                if (sPeerAddress!="")   {
                    int serviceValue = (bDINNodeAPIUpdate) ? -1 : 0;
                    serviceId = nodeSetupGetServiceForNodeAddress( QString::fromStdString(sPeerAddress) );

                    if (serviceId==0 || serviceValue==0)   {   // 0 = not checked
                        bNeedToQueryAPIServiceId = true;
                        nodeSetupSetServiceForNodeAddress( QString::fromStdString(sPeerAddress), serviceValue );  // -1 = reset to checked, not queried
                    }
                }
            }

            if (strIP=="" && nodeSetupTempIPInfo.find(strBurnTx) != nodeSetupTempIPInfo.end() )  {
                strIP = nodeSetupTempIPInfo[strBurnTx];
            }

            // get node type info
            QString strNodeType = "";
            CTransactionRef txr;
            uint256 hashblock;
            if(!GetTransaction(infoInf.vinBurnFund.prevout.hash, txr, Params().GetConsensus(), hashblock, false)) {
                LogPrintf("nodeSetUp: updateDINNode GetTransaction -- BurnFund tx is not in block\n");
            }
            else    {
                CTransaction tx = *txr;
                for (unsigned int i = 0; i < tx.vout.size(); i++) {
                    const CTxOut& txout = tx.vout[i];

                    CAmount roundAmount = ((int)(txout.nValue / COIN)+1);
                    strNodeType = nodeSetupGetNodeType(roundAmount);
                    if (strNodeType!="")    break;  // found, leave
                }
            }

            if(infoInf.nExpireHeight < nCurrentHeight){
                status="Expired";
                // update used burn tx map
                nodeSetupUsedBurnTxs.insert( { burnfundTxId, 1  } );
                nExpired++;
            } else {
                QString nodeTxId = QString::fromStdString(infoInf.collateralAddress);
                QString strPeerAddress = QString::fromStdString(sPeerAddress);
                ui->dinTable->insertRow(k);
                ui->dinTable->setItem(k, 0, new QTableWidgetItem(QString(nodeTxId)));
                QTableWidgetItem *itemHeight = new QTableWidgetItem;
                itemHeight->setData(Qt::EditRole, infoInf.nHeight);
                ui->dinTable->setItem(k, 1, itemHeight);
                QTableWidgetItem *itemExpiryHeight = new QTableWidgetItem;
                itemExpiryHeight->setData(Qt::EditRole, infoInf.nExpireHeight);
                ui->dinTable->setItem(k, 2, itemExpiryHeight);
                ui->dinTable->setItem(k, 3, new QTableWidgetItem(QString::fromStdString(status)));
                ui->dinTable->setItem(k, 4, new QTableWidgetItem(strIP) );
                ui->dinTable->setItem(k, 5, new QTableWidgetItem(strPeerAddress) );
                ui->dinTable->setItem(k, 6, new QTableWidgetItem(strBurnTx) );
                ui->dinTable->setItem(k, 7, new QTableWidgetItem(strNodeType) );
                bool flocked = mapLockRewardHeight.find(sPeerAddress) != mapLockRewardHeight.end();
                if(flocked) {
                    ui->dinTable->setItem(k, 8, new QTableWidgetItem(QString::number(mapLockRewardHeight[sPeerAddress])));
                    ui->dinTable->setItem(k, 9, new QTableWidgetItem(QString(QString::fromStdString("Yes"))));
                } else {
                    ui->dinTable->setItem(k, 8, new QTableWidgetItem(QString(QString::fromStdString(""))));
                    ui->dinTable->setItem(k, 9, new QTableWidgetItem(QString(QString::fromStdString("No"))));
                }
                ui->dinTable->setItem(k,10, new QTableWidgetItem(QString(QString::fromStdString(pair.second))));

                // node status column info from cached map
                if (nodeSetupNodeInfoCache.find(strPeerAddress) != nodeSetupNodeInfoCache.end() ) {
                    pair_nodestatus pairStatus = nodeSetupNodeInfoCache[strPeerAddress];
                    ui->dinTable->setItem(k, 11, new QTableWidgetItem(pairStatus.first));
                    ui->dinTable->setItem(k, 12, new QTableWidgetItem(pairStatus.second));
                }

                if (status == "Incomplete") {
                    nIncomplete++;
                }
                if (status == "Ready") {
                    nReady++;
                }

                if ( filterNodeRow(k) ) {
                    k++;
                }
                else    {
                    ui->dinTable->removeRow(k);
                }
            }
        }

        bDINNodeAPIUpdate = true;

        // use as nodeSetup combo refresh too
        nodeSetup_RefreshCounter++;
        if ( nodeSetup_RefreshCounter >= NODESETUP_REFRESHCOMBOS )  {
            nodeSetup_RefreshCounter = 0;
            nodeSetupPopulateInvoicesCombo();
            nodeSetupPopulateBurnTxCombo();
        }
        ui->dinTable->setSortingEnabled(true);
        ui->ReadyNodesLabel->setText(QString::number(nReady));
        ui->IncompleteNodesLabel->setText(QString::number(nIncomplete));
        ui->ExpiredNodesLabel->setText(QString::number(nExpired));
        if (nReady == 0) {
            ui->ReadyNodes_label->hide();
            ui->ReadyNodesLabel->hide();
        }
        if (nIncomplete == 0) {
            ui->IncompleteNodes_label->hide();
            ui->IncompleteNodesLabel->hide();
        }
        if (nExpired == 0) {
            ui->ExpiredNodes_label->hide();
            ui->ExpiredNodesLabel->hide();
        }
    }
}

bool MasternodeList::filterNodeRow( int nRow )    {

    if (ui->searchOwnerAddr->text() != "" && !ui->dinTable->item(nRow, 0)->text().contains(ui->searchOwnerAddr->text(), Qt::CaseInsensitive) )  {
//LogPrintf("filterNodeRow owner %d, #%s#, %s \n", nRow, ui->searchOwnerAddr->text().toStdString(), ui->dinTable->item(nRow, 0)->text().toStdString());
        return false;
    }

    if (ui->comboStatus->currentText() != "<Status>" && ui->dinTable->item(nRow, 3)->text() != ui->comboStatus->currentText() )  {
//LogPrintf("filterNodeRow status %d, %s, %s \n", nRow, ui->comboStatus->currentText().toStdString(), ui->dinTable->item(nRow, 3)->text().toStdString());
        return false;
    }

    if (ui->searchIP->text() != "" && !ui->dinTable->item(nRow, 4)->text().contains(ui->searchIP->text(), Qt::CaseInsensitive) )  {
//LogPrintf("filterNodeRow IP %d, %s \n", nRow, ui->dinTable->item(nRow, 4)->text().toStdString());
        return false;
    }

    if (ui->searchPeerAddr->text() != "" && !ui->dinTable->item(nRow, 5)->text().contains(ui->searchPeerAddr->text(), Qt::CaseInsensitive) )  {
//LogPrintf("filterNodeRow Peer addr %d, %s \n", nRow, ui->dinTable->item(nRow, 5)->text().toStdString());
        return false;
    }

    if (ui->searchBurnTx->text() != "" && !ui->dinTable->item(nRow, 6)->text().contains(ui->searchBurnTx->text(), Qt::CaseInsensitive) )  {
//LogPrintf("filterNodeRow burntx %d, %s \n", nRow, ui->dinTable->item(nRow, 6)->text().toStdString());
        return false;
    }

    if (ui->comboTier->currentText() != "<Node Tier>" && ui->dinTable->item(nRow, 7)->text() != ui->comboTier->currentText() )  {
//LogPrintf("filterNodeRow tier %d, %s \n", nRow, ui->dinTable->item(nRow, 7)->text().toStdString());
        return false;
    }

    if (ui->searchBackupAddr->text() != "" && !ui->dinTable->item(nRow, 10)->text().contains(ui->searchBackupAddr->text(), Qt::CaseInsensitive) )  {
//LogPrintf("filterNodeRow backup addr %d, %s \n", nRow, ui->dinTable->item(nRow, 10)->text().toStdString());
        return false;
    }

    return true;
}

void MasternodeList::on_checkDINNode()
{
    QItemSelectionModel* selectionModel = ui->dinTable->selectionModel();
    QModelIndexList selected = selectionModel->selectedRows();
    if(selected.count() == 0) return;

    QModelIndex index = selected.at(0);
    int nSelectedRow = index.row();
    mCheckNodeAction->setEnabled(false);
    nodeSetupCheckDINNode(nSelectedRow, true);
    mCheckNodeAction->setEnabled(true);

}

void MasternodeList::nodeSetupCheckDINNode(int nSelectedRow, bool bShowMsg )    {

    QString strAddress = ui->dinTable->item(nSelectedRow, 5)->text();
    QString strError;
    QString strStatus = ui->dinTable->item(nSelectedRow, 3)->text();
    QMessageBox msg;

//LogPrintf("nodeSetupCheckDINNode %d, %s \n", nSelectedRow, strStatus.toStdString());
    if ( strStatus!="Ready" )    {
        if (bShowMsg)   {
            msg.setText(tr("DIN node must be in Ready status"));
            msg.exec();
        }
    }
    else    {
        QString email, pass, strError;
        int clientId = nodeSetupGetClientId( email, pass, true );
        ui->dinTable->setItem(nSelectedRow, 11, new QTableWidgetItem("Loading..."));
        ui->dinTable->setItem(nSelectedRow, 12, new QTableWidgetItem("Loading..."));
        int serviceId = nodeSetupGetServiceForNodeAddress( strAddress );
        if (serviceId <= 0)   {     // retry load nodes' service data
            if (clientId>0 && pass != "") {
                nodeSetupAPINodeList( email, pass, strError );
                serviceId = nodeSetupGetServiceForNodeAddress( strAddress );
            }
        }

        if (serviceId > 0)    {
            if (clientId>0 && pass != "") {
                QJsonObject obj = nodeSetupAPINodeInfo( serviceId, mClientid , email, pass, strError );
                if (obj.contains("Blockcount") && obj.contains("MyPeerInfo"))   {
                    int blockCount = obj["Blockcount"].toInt();
                    QString strBlockCount = QString::number(blockCount);
                    QString peerInfo = obj["MyPeerInfo"].toString();
                    ui->dinTable->setItem(nSelectedRow, 11, new QTableWidgetItem(strBlockCount));
                    ui->dinTable->setItem(nSelectedRow, 12, new QTableWidgetItem(peerInfo));

                    if (nodeSetupNodeInfoCache.find(strAddress) != nodeSetupNodeInfoCache.end() ) {   // replace cache value
                        nodeSetupNodeInfoCache[strAddress] = std::make_pair(strBlockCount, peerInfo);
                    }
                    else    {   // insert new cache value
                        nodeSetupNodeInfoCache.insert( { strAddress,  std::make_pair(strBlockCount, peerInfo) } );
                    }
                }
                else    {
                    if (bShowMsg)   {
                        msg.setText("Node status check timeout:\nCheck if your Node Setup password is correct, then try again.");
                        msg.exec();
                    }
                    ui->dinTable->setItem(nSelectedRow, 11, new QTableWidgetItem("Error 1"));
                    ui->dinTable->setItem(nSelectedRow, 12, new QTableWidgetItem(""));
                }
            }
            else    {
                if (bShowMsg)   {
                    msg.setText("Only for SetUP hosted nodes\nCould not recover node's client ID\nPlease log in with your user email and password in the Node SetUP tab");
                    msg.exec();
                }
                ui->dinTable->setItem(nSelectedRow, 11, new QTableWidgetItem("Error 2"));
                ui->dinTable->setItem(nSelectedRow, 12, new QTableWidgetItem(""));
            }
        }
        else    {
            if (bShowMsg)   {
                msg.setText("Only for SetUP hosted nodes\nCould not recover node's service ID\nPlease log in with your user email and password in the Node SetUP tab");
                msg.exec();
            }
            ui->dinTable->setItem(nSelectedRow, 11, new QTableWidgetItem("Login required"));
            ui->dinTable->setItem(nSelectedRow, 12, new QTableWidgetItem(""));
        }
    }
}

void MasternodeList::nodeSetupCheckAllDINNodes()    {
    int rows = ui->dinTable->rowCount();
    if (rows == 0)  return;

    nodeSetupNodeInfoCache.clear();
    nCheckAllNodesCurrentRow = 0;
    if ( checkAllNodesTimer !=NULL && !checkAllNodesTimer->isActive() )  {
        checkAllNodesTimer->start(1000);
    }
    mCheckAllNodesAction->setEnabled(false);
    mCheckNodeAction->setEnabled(false);
}

void MasternodeList::nodeSetupDINColumnToggle(int nColumn ) {
    bool bHide = false;
    QSettings settings;

    // find action
    auto it = std::find_if( contextDINColumnsActions.begin(), contextDINColumnsActions.end(),
    [&nColumn](const std::pair<int, QAction*>& element){ return element.first == nColumn;} );

    if (it != contextDINColumnsActions.end())
    {
        QAction *a = it->second;
        if (!a->isChecked()) {
            bHide = true;
        }
        settings.setValue("bShowDINColumn_"+QString::number(nColumn), !bHide);
        ui->dinTable->setColumnHidden( nColumn, bHide);
    }
}

void MasternodeList::nodeSetupCheckDINNodeTimer()    {
    int rows = ui->dinTable->rowCount();

    if ( nCheckAllNodesCurrentRow >= rows )  {
        if ( checkAllNodesTimer !=NULL && checkAllNodesTimer->isActive() )  {
            checkAllNodesTimer->stop();
        }
//LogPrintf("nodeSetupCheckDINNode stop timer %d, %d \n", nCheckAllNodesCurrentRow, rows);
        mCheckAllNodesAction->setEnabled(true);
        mCheckNodeAction->setEnabled(true);
    }
    else    {
        nodeSetupCheckDINNode(nCheckAllNodesCurrentRow, false);
        nCheckAllNodesCurrentRow++;
    }
}

// nodeSetup buttons
void MasternodeList::on_btnSetup_clicked()
{
    QString email, pass, strError;

    // check for chain synced...
    if (!masternodeSync.IsBlockchainSynced())    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText("Chain is out-of-sync. Please wait until it's fully synced.");
        return;
    }

    // check again in case they changed the tier...
    nodeSetupCleanProgress();
    if ( !nodeSetupCheckFunds() )   {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText("You didn't pass the funds check. Please review.");
        return;
    }

    nodeSetupGetClientId( email, pass, true );

    int orderid, invoiceid, productid;
    QString strBillingCycle = QString::fromStdString(billingOptions[ui->comboBilling->currentData().toInt()]);

//LogPrintf("place order %d, %s ", mClientid, strBillingCycle);
    if ( ! (mOrderid > 0 && mInvoiceid > 0) ) {     // place new order if there is none already
        mOrderid = nodeSetupAPIAddOrder( mClientid, strBillingCycle, mProductIds, mInvoiceid, email, pass, strError );
    }

    if (mInvoiceid==0)  {
        QMessageBox::warning(this, "Maintenance Mode", "We are sorry, Node Setup is in maintenance mode at this moment. Please try later.", QMessageBox::Ok, QMessageBox::Ok);
    }

    if ( mOrderid > 0 && mInvoiceid > 0) {
        nodeSetupSetOrderId( mOrderid, mInvoiceid, mProductIds );
        nodeSetupEnableOrderUI(true, mOrderid, mInvoiceid);
        ui->labelMessage->setText(QString::fromStdString(strprintf("Order placed successfully. Order ID #%d Invoice ID #%d", mOrderid, mInvoiceid)));

        // get invoice data and do payment
        QString strAmount, strStatus, paymentAddress;
        strStatus = nodeSetupCheckInvoiceStatus();
    }
    else    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText(strError);
    }
}

void MasternodeList::on_payButton_clicked()
{
     int invoiceToPay = ui->comboInvoice->currentData().toInt();
     QString strAmount, strStatus, paymentAddress;
     QString email, pass, strError;

     nodeSetupGetClientId( email, pass, true );

     if (invoiceToPay>0)    {
        bool res = nodeSetupAPIGetInvoice( invoiceToPay, strAmount, strStatus, paymentAddress, email, pass, strError );
        CAmount invoiceAmount = strAmount.toDouble();
        //LogPrintf("nodeSetupCheckPendingPayments nodeSetupAPIGetInvoice %s, %d \n", strStatus.toStdString(), invoiceToPay );

        if ( !res )   {
            ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
            ui->labelMessage->setText(strError);
            return;
        }

         if ( strStatus == "Unpaid" )  {
             // Display message box
             QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Invoice Payment"),
                 "Are you sure you want to pay " + QString::number(invoiceAmount) + " SIN?",
                 QMessageBox::Yes | QMessageBox::Cancel,
                 QMessageBox::Cancel);

             if(retval != QMessageBox::Yes)  {
                 return;
             }

             WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();

             QString paymentTx = "";
             if(encStatus == walletModel->Locked) {
                 WalletModel::UnlockContext ctx(walletModel->requestUnlock());

                 if(!ctx.isValid()) return; // Unlock wallet was cancelled
                 paymentTx = nodeSetupSendToAddress( paymentAddress, invoiceAmount, NULL );
             }
             else   {
                 paymentTx = nodeSetupSendToAddress( paymentAddress, invoiceAmount, NULL );
             }

             if ( paymentTx != "" ) {
                 std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
                 CWallet * const pwallet = (wallets.size() > 0) ? wallets[0].get() : nullptr;
                 if (pwallet!=nullptr)   {
                    CTxDestination dest = DecodeDestination(paymentAddress.toStdString());
                    pwallet->SetAddressBook(dest, strprintf("Invoice #%d", invoiceToPay), "send");
                 }
                 nodeSetupPendingPayments.insert( { paymentTx.toStdString(), invoiceToPay } );
                 if ( pendingPaymentsTimer !=NULL && !pendingPaymentsTimer->isActive() )  {
                     pendingPaymentsTimer->start(30000);
                 }
                 nodeSetupStep( "setupWait", "Pending Invoice Payment finished, please wait for confirmations.");
                 //ui->labelMessage->setText( "Pending Invoice Payment finished, please wait for confirmations." );
             }
         }
     }
}

void MasternodeList::nodeSetupCheckPendingPayments()    {
    int invoiceToPay;
    QString strAmount, strStatus, paymentAddress;
    QString email, pass, strError;

    nodeSetupGetClientId( email, pass, true );

    for(auto& itemPair : nodeSetupPendingPayments)   {
        invoiceToPay = itemPair.second;
        nodeSetupAPIGetInvoice( invoiceToPay, strAmount, strStatus, paymentAddress, email, pass, strError );
        if ( strStatus != "Unpaid" )  { // either paid or cancelled/removed
            nodeSetupPendingPayments.erase(itemPair.first);
            nodeSetupStep( "setupOk", strprintf("Payment for invoice #%d processed", invoiceToPay) );
        }
    }

    if ( nodeSetupPendingPayments.size()==0 )   {
        if ( pendingPaymentsTimer !=NULL && pendingPaymentsTimer->isActive() )  {
            pendingPaymentsTimer->stop();
        }
    }
}

QString MasternodeList::nodeSetupGetNewAddress()    {

    QString strAddress = "";
    std::ostringstream cmd;
    try {
        cmd.str("");
        cmd << "getnewaddress";
        UniValue jsonVal = nodeSetupCallRPC( cmd.str() );
        if ( jsonVal.type() == UniValue::VSTR )       // new address returned
        {
            strAddress = QString::fromStdString(jsonVal.get_str());
        }
    } catch (UniValue& objError ) {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;font-weight:bold;color: red}");
        ui->labelMessage->setText( "Error getting new wallet address" );
    }
    catch ( std::runtime_error e)
    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( QString::fromStdString( "ERROR getnewaddress: unexpected error " ) + QString::fromStdString( e.what() ));
    }

    return strAddress;
}

QString MasternodeList::nodeSetupSendToAddress( QString strAddress, int amount, QTimer* timer )    {
    QString strTxId = "";
    std::ostringstream cmd;
    try {
        cmd.str("");
        cmd << "sendtoaddress " << strAddress.toUtf8().constData() << " " << amount;

        UniValue jsonVal = nodeSetupCallRPC( cmd.str() );
        if ( jsonVal.type() == UniValue::VSTR )       // tx id returned
        {
            strTxId = QString::fromStdString(jsonVal.get_str());
            if ( timer!=NULL && !timer->isActive() )  {
                timer->start(20000);
            }
        }
    } catch (UniValue& objError ) {
        QString errMessage = QString::fromStdString(find_value(objError, "message").get_str());
        if ( errMessage.contains("walletpassphrase") )  {
            QMessageBox::warning(this, "Please Unlock Wallet", "In order to make payments, please unlock your wallet and retry", QMessageBox::Ok, QMessageBox::Ok);
        }

        ui->labelMessage->setText( QString::fromStdString(find_value(objError, "message").get_str()) );
    }
    catch ( std::runtime_error e)
    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( QString::fromStdString( "ERROR sendtoaddress: unexpected error " ) + QString::fromStdString( e.what() ));
    }

    return strTxId;
}

UniValue MasternodeList::nodeSetupGetTxInfo( QString txHash, std::string attribute)  {
    UniValue ret = 0;

    if ( txHash.length() != 64  )
        return ret;

    std::ostringstream cmd;
    try {
        cmd.str("");
        cmd << "gettransaction " << txHash.toUtf8().constData();
        UniValue jsonVal = nodeSetupCallRPC( cmd.str() );
        if ( jsonVal.type() == UniValue::VOBJ )       // object returned
        {
            ret = find_value(jsonVal.get_obj(), attribute);
        }
        else {
            ui->labelMessage->setStyleSheet("QLabel { font-size:14px;font-weight:bold;color: red}");
            ui->labelMessage->setText( "Error calling RPC gettransaction");
        }
    } catch (UniValue& objError ) {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;font-weight:bold;color: red}");
        ui->labelMessage->setText( "Error calling RPC gettransaction");
    }
    catch ( std::runtime_error e)
    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( QString::fromStdString( "ERROR gettransaction: unexpected error " ) + QString::fromStdString( e.what() ));
    }

    return ret;
}

QString MasternodeList::nodeSetupCheckInvoiceStatus()  {
    QString strAmount, strStatus, paymentAddress;
    QString email, pass, strError;

    nodeSetupGetClientId( email, pass, true );

    nodeSetupAPIGetInvoice( mInvoiceid, strAmount, strStatus, paymentAddress, email, pass, strError );

    CAmount invoiceAmount = strAmount.toDouble();
    if ( strStatus == "Cancelled" || strStatus == "Refunded" )  {  // reset and call again
        nodeSetupStep( "setupWait", "Order cancelled or refunded, creating a new order");
        invoiceTimer->stop();
        nodeSetupResetOrderId();
        on_btnSetup_clicked();
    }

    if ( strStatus == "Unpaid" )  {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
        ui->labelMessage->setText(QString::fromStdString(strprintf("Invoice amount %f SIN", invoiceAmount)));
        if ( mPaymentTx != "" ) {   // already paid, waiting confirmations
            nodeSetupStep( "setupWait", "Invoice paid, waiting for confirmation");
            ui->btnSetup->setEnabled(false);
            ui->btnSetupReset->setEnabled(false);
        }
        else    {
            // Display message box
            QMessageBox::StandardButton retval = QMessageBox::question(this, tr("Confirm Invoice Payment"),
                "Are you sure you want to pay " + QString::number(invoiceAmount) + " SIN?",
                QMessageBox::Yes | QMessageBox::Cancel,
                QMessageBox::Cancel);

            if(retval != QMessageBox::Yes)  {
                invoiceTimer->stop();
                ui->btnSetup->setEnabled(true);
                ui->btnSetupReset->setEnabled(true);
                ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
                ui->labelMessage->setText( "Press Reset Order button to cancel node setup process, or Continue setUP button to resume." );
                return "cancelled";
            }

            if (nodeSetupUnlockWallet()) {
                mPaymentTx = nodeSetupSendToAddress( paymentAddress, invoiceAmount, invoiceTimer );
            }
            else   {
                ui->labelMessage->setStyleSheet("QLabel { font-size:14px;font-weight:bold;color: red}");
                ui->labelMessage->setText( "Unlocking wallet is required to make the payments." );
                return "cancelled";
            }

            nodeSetupStep( "setupWait", "Paying invoice");
            if ( mPaymentTx != "" ) {
                std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
                CWallet * const pwallet = (wallets.size() > 0) ? wallets[0].get() : nullptr;
                if (pwallet!=nullptr)   {
                    CTxDestination dest = DecodeDestination(paymentAddress.toStdString());
                    pwallet->SetAddressBook(dest, strprintf("Invoice #%d", mInvoiceid), "send");
                }

                nodeSetupSetPaymentTx(mPaymentTx);
                ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
                ui->labelMessage->setText( "Payment finished, please wait until platform confirms payment to proceed to node creation." );
                ui->btnSetup->setEnabled(false);
                ui->btnSetupReset->setEnabled(false);
                if ( !invoiceTimer->isActive() )  {
                    invoiceTimer->start(60000);
                }
            }
        }
    }

    if ( strStatus == "Paid" )  {           // launch node setup (RPC)
        if (invoiceAmount==0)   {
            ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
            ui->labelMessage->setText(QString::fromStdString("Invoice paid with balance"));
        }

        invoiceTimer->stop();

        QString strPrivateKey, strPublicKey, strDecodePublicKey, strAddress, strNodeIp;

        mBurnTx = nodeSetupGetBurnTx();
        QString strSelectedBurnTx = ui->comboBurnTx->currentData().toString();
        if (strSelectedBurnTx=="WAIT")  strSelectedBurnTx = "NEW";

//LogPrintf("nodeSetupCheckInvoiceStatus mBurnTx = %s, selected=%s \n", mBurnTx.toStdString(), strSelectedBurnTx.toStdString());

        if ( mBurnTx=="" && strSelectedBurnTx!="NEW")   {
            mBurnTx = strSelectedBurnTx;
            nodeSetupSetBurnTx(mBurnTx);
        }

        if ( mBurnTx!="" )   {   // skip to check burn tx
            mBurnAddress = nodeSetupGetOwnerAddressFromBurnTx(mBurnTx);
            if ( !burnSendTimer->isActive() )  {
                burnSendTimer->start(20000);    // check every 20 secs
            }
            // amount necessary for updatemeta may be already spent, send again.
            if (nodeSetupUnlockWallet()) {
                mMetaTx = nodeSetupSendToAddress( mBurnAddress, NODESETUP_UPDATEMETA_AMOUNT , NULL );
                nodeSetupStep( "setupWait", "Maturing, please wait...");
            }
        }
        else    {   // burn tx not made yet
            mBurnAddress = nodeSetupGetNewAddress();
            int nMasternodeBurn = nodeSetupGetBurnAmount();

            if (nodeSetupUnlockWallet()) {
                mBurnPrepareTx = nodeSetupSendToAddress( mBurnAddress, nMasternodeBurn, burnPrepareTimer );
            }

            if ( mBurnPrepareTx=="" )  {
               ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
               ui->labelMessage->setText( "ERROR: failed to prepare burn transaction." );
            }
            nodeSetupStep( "setupWait", "Preparing burn transaction");
        }
    }

    return strStatus;
}

QString MasternodeList::nodeSetupGetOwnerAddressFromBurnTx( QString burnTx )    {
    QString address = "";

    std::ostringstream cmd;
    try {
        cmd.str("");
        cmd << "getrawtransaction " << burnTx.toUtf8().constData() << " 1";
        UniValue jsonVal = nodeSetupCallRPC( cmd.str() );
        if ( jsonVal.type() == UniValue::VOBJ )       // object returned
        {
            UniValue vinArray = find_value(jsonVal.get_obj(), "vin").get_array();
            UniValue vin0 = vinArray[0].get_obj();
            QString txid = QString::fromStdString(find_value(vin0, "txid").get_str());
LogPrintf("nodeSetupGetOwnerAddressFromBurnTx txid %s \n", txid.toStdString());
            if ( txid!="" ) {
                int vOutN = find_value(vin0, "vout").get_int();
                cmd.str("");
                cmd << "getrawtransaction " << txid.toUtf8().constData() << " 1";
                jsonVal = nodeSetupCallRPC( cmd.str() );
                UniValue voutArray = find_value(jsonVal.get_obj(), "vout").get_array();

                // take output considered for owner address. amount does not have to be exactly the burn amount (may include change amounts)
                const UniValue &vout = voutArray[vOutN].get_obj();
                CAmount value = find_value(vout, "value").get_real();

                UniValue obj = find_value(vout, "scriptPubKey").get_obj();
                UniValue addressesArray = find_value(obj, "addresses").get_array();
                address = QString::fromStdString(addressesArray[0].get_str());
LogPrintf("nodeSetupGetOwnerAddressFromBurnTx vout=%d, address %s \n", vOutN, address.toStdString());
            }
        }
        else {
            ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
            ui->labelMessage->setText( "Error calling RPC getrawtransaction");
        }
    } catch (UniValue& objError ) {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( "Error RPC obtaining owner address");
    }
    catch ( std::runtime_error e)
    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( QString::fromStdString( "ERROR get owner address: unexpected error " ) + QString::fromStdString( e.what() ));
    }
    return address;
}

void MasternodeList::nodeSetupCheckBurnPrepareConfirmations()   {

    UniValue objConfirms = nodeSetupGetTxInfo( mBurnPrepareTx, "confirmations" );
    int numConfirms = objConfirms.get_int();
    if ( numConfirms>NODESETUP_CONFIRMS )    {
        nodeSetupStep( "setupWait", "Sending burn transaction");
        burnPrepareTimer->stop();
        QString strAddressBackup = nodeSetupGetNewAddress();
        int nMasternodeBurn = nodeSetupGetBurnAmount();

        mBurnTx = nodeSetupRPCBurnFund( mBurnAddress, nMasternodeBurn , strAddressBackup);
        if (nodeSetupUnlockWallet()) {
            mMetaTx = nodeSetupSendToAddress( mBurnAddress, NODESETUP_UPDATEMETA_AMOUNT , NULL );
        }
        if ( mBurnTx!="" )  {
            nodeSetupSetBurnTx(mBurnTx);
            if ( !burnSendTimer->isActive() )  {
                burnSendTimer->start(20000);    // check every 20 secs
            }
        }
        else    {
            ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
            ui->labelMessage->setText( "ERROR: failed to create burn transaction." );
        }
    }
}

void MasternodeList::nodeSetupCheckBurnSendConfirmations()   {

    // recover data
    QString email, pass, strError;
    int clientId = nodeSetupGetClientId( email, pass );

    UniValue objConfirms = nodeSetupGetTxInfo( mBurnTx, "confirmations" );
    UniValue objConfirmsMeta = nodeSetupGetTxInfo( mMetaTx, "confirmations" );

    int numConfirms = objConfirms.get_int();
    int numConfirmsMeta = objConfirmsMeta.get_int();
    if ( numConfirms>NODESETUP_CONFIRMS && numConfirmsMeta>NODESETUP_CONFIRMS && pass != "" )    {
        nodeSetupStep( "setupOk", "Finishing node setup");
        burnSendTimer->stop();

        QJsonObject root = nodeSetupAPIInfo( mServiceId, clientId, email, pass, strError );
        if ( root.contains("PrivateKey") ) {
            QString strPrivateKey = root["PrivateKey"].toString();
            QString strPublicKey = root["PublicKey"].toString();
            QString strDecodePublicKey = root["DecodePublicKey"].toString();
            QString strAddress = root["Address"].toString();
            QString strNodeIp = root["Nodeip"].toString();

            nodeSetupTempIPInfo[mBurnTx.left(16)] = strNodeIp;
            std::ostringstream cmd;

            try {
                cmd.str("");
                cmd << "infinitynodeupdatemeta " << mBurnAddress.toUtf8().constData() << " " << strPublicKey.toUtf8().constData() << " " << strNodeIp.toUtf8().constData() << " " << mBurnTx.left(16).toUtf8().constData();
LogPrintf("[nodeSetup] infinitynodeupdatemeta %s \n", cmd.str() );
                UniValue jsonVal = nodeSetupCallRPC( cmd.str() );
LogPrintf("[nodeSetup] infinitynodeupdatemeta SUCCESS \n" );

                nodeSetupSendToAddress( strAddress, 3, NULL );  // send 1 coin as per recommendation to expedite the rewards
                nodeSetupSetServiceForNodeAddress( strAddress, mServiceId); // store serviceid
                // cleanup
                nodeSetupResetOrderId();
                nodeSetupSetBurnTx("");

                nodeSetupLockWallet();
                nodeSetupResetOrderId();
                nodeSetupEnableOrderUI(false);
                nodeSetupStep( "setupOk", "Node setup finished");
            }
            catch (const UniValue& objError)    {
                QString str = nodeSetupGetRPCErrorMessage( objError );
                ui->labelMessage->setText( str ) ;
                nodeSetupStep( "setupKo", "Node setup failed");
            }
            catch ( std::runtime_error e)
            {
                ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
                ui->labelMessage->setText( QString::fromStdString( "ERROR infinitynodeupdatemeta: unexpected error " ) + QString::fromStdString( e.what() ));
                nodeSetupStep( "setupKo", "Node setup failed");
            }
        }
        else    {
            LogPrintf("infinitynodeupdatemeta Error while obtaining node info \n");
            ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
            ui->labelMessage->setText( "ERROR: infinitynodeupdatemeta " );
            nodeSetupStep( "setupKo", "Node setup failed");
        }
        nodeSetupLockWallet();
    }
}

/*
 * To setup DIN node, we do by RPC command. We need Qt to replace RPC command
RPC steps :
infinitynodeburnfund your_Burn_Address Amount Your_Backup_Address
cBurnAddress
    Sample for MINI
    infinitynodeburnfund SQ5Qnpf3mWituuXtQrEknKYDaKUtinvMzT 100000 SWyHHvnPNaH18TcfszAzWfKyojmTqtZQqy
 *
 */

QString MasternodeList::nodeSetupRPCBurnFund( QString collateralAddress, CAmount amount, QString backupAddress ) {
    QString burnTx = "";
    std::ostringstream cmd;

    try {
        cmd.str("");
        cmd << "infinitynodeburnfund " << collateralAddress.toUtf8().constData() << " " << amount << " " << backupAddress.toUtf8().constData();
        UniValue jsonVal = nodeSetupCallRPC( cmd.str() );
        if ( jsonVal.isStr() )       // some error happened, cannot continue
        {
            ui->labelMessage->setText(QString::fromStdString( "ERROR infinitynodeburnfund: " ) + QString::fromStdString(jsonVal.get_str()));
        }
        else if ( jsonVal.isArray() ){
            UniValue jsonArr = jsonVal.get_array();
            if (jsonArr.size()>0)   {
                UniValue jsonObj = jsonArr[0].get_obj();
                burnTx = QString::fromStdString(find_value(jsonObj, "BURNTX").get_str());
            }
        }
        else {
            ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
            ui->labelMessage->setText(QString::fromStdString( "ERROR infinitynodeburnfund: unknown response") );
        }
    }
    catch (const UniValue& objError)
    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( QString::fromStdString(find_value(objError, "message").get_str()) );
    }
    catch ( std::runtime_error e)
    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( QString::fromStdString( "ERROR infinitynodeburnfund: unexpected error " ) + QString::fromStdString( e.what() ));
    }
    return burnTx;
}

void MasternodeList::on_btnLogin_clicked()
{
    QString strError = "", pass = ui->txtPassword->text();
//LogPrintf("nodeSetup::on_btnLogin_clicked -- %d\n", mClientid);
    if ( bNodeSetupLogged )    {   // reset
        nodeSetupResetClientId();
        ui->btnLogin->setText("Login");
        bNodeSetupLogged = false;
        return;
    }

    int clientId = nodeSetupAPIAddClient( "", "", ui->txtEmail->text(), ui->txtPassword->text(), strError );
    if ( strError != "" )  {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: red}");
        ui->labelMessage->setText( strError );
    }

    if ( clientId > 0 ) {
        bNodeSetupLogged = true;
        nodeSetupEnableClientId( clientId );
        nodeSetupSetClientId( clientId, ui->txtEmail->text(), ui->txtPassword->text() );
        ui->btnLogin->setText("Logout");
        ui->btnSetup->setEnabled(true);
    }
}

void MasternodeList::on_btnSetupReset_clicked()
{
    nodeSetupResetOrderId();
    nodeSetupEnableOrderUI(false);
}

// END nodeSetup buttons

void MasternodeList::nodeSetupInitialize()   {

    ConnectionManager = new QNetworkAccessManager(this);

    labelPic[0] = ui->labelPic_1;
    labelTxt[0] = ui->labelTxt_1;
    labelPic[1] = ui->labelPic_2;
    labelTxt[1] = ui->labelTxt_2;
    labelPic[2] = ui->labelPic_3;
    labelTxt[2] = ui->labelTxt_3;
    labelPic[3] = ui->labelPic_4;
    labelTxt[3] = ui->labelTxt_4;
    labelPic[4] = ui->labelPic_5;
    labelTxt[4] = ui->labelTxt_5;
    labelPic[5] = ui->labelPic_6;
    labelTxt[5] = ui->labelTxt_6;
    labelPic[6] = ui->labelPic_7;
    labelTxt[6] = ui->labelTxt_7;
    labelPic[7] = ui->labelPic_8;
    labelTxt[7] = ui->labelTxt_8;

    ui->dinTable->setSortingEnabled(false);

    // combo billing
    int i;
    for (i=0; i<sizeof(billingOptions)/sizeof(billingOptions[0]); i++)    {
        std::string option = billingOptions[i];
        ui->comboBilling->addItem(QString::fromStdString(option), QVariant(i));
    }
    ui->comboBilling->setCurrentIndex(2);

#if defined(Q_OS_WIN)
#else
    ui->payButton->setStyleSheet("font-size: 16px");
    ui->comboBilling->setStyle(QStyleFactory::create("Windows"));
    ui->comboInvoice->setStyle(QStyleFactory::create("Windows"));
    ui->comboBurnTx->setStyle(QStyleFactory::create("Windows"));

    ui->comboStatus->setStyle(QStyleFactory::create("Windows"));
    ui->comboTier->setStyle(QStyleFactory::create("Windows"));
#endif

    // buttons
    ui->btnSetup->setEnabled(false);

    // progress lines
    nodeSetupCleanProgress();

    // recover data
    QString email, pass;

    int clientId = nodeSetupGetClientId( email, pass, true );
    ui->txtEmail->setText(email);
    if ( clientId == 0 || pass=="" )    {
        //ui->widgetLogin->show();
        //ui->widgetCurrent->hide();
        ui->setupButtons->hide();
        ui->labelClientId->setText("");
        ui->labelClientIdValue->hide();
    }
    else {
        nodeSetupEnableClientId(clientId);
        ui->btnLogin->setText("Logout");
    }
    mClientid = clientId;

    mOrderid = nodeSetupGetOrderId( mInvoiceid, mProductIds );
    if ( mOrderid > 0 )    {
        ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
        ui->labelMessage->setText(QString::fromStdString(strprintf("There is an order ongoing (#%d). Press 'Continue' or 'Reset' order.", mOrderid)));
        nodeSetupEnableOrderUI(true, mOrderid, mInvoiceid);
        mPaymentTx = nodeSetupGetPaymentTx();
    }
    else    {
        nodeSetupEnableOrderUI(false);
    }

    nodeSetupPopulateInvoicesCombo();
    nodeSetupPopulateBurnTxCombo();
    ui->dinTable->setSortingEnabled(true);
}

void MasternodeList::nodeSetupEnableOrderUI( bool bEnable, int orderID , int invoiceID ) {
    if (bEnable)    {
        ui->comboBilling->setEnabled(false);
        ui->btnSetup->setEnabled(true);
        ui->btnSetupReset->setEnabled(true);
        ui->payButton->setEnabled(false);
        ui->labelOrder->setVisible(true);
        ui->labelOrderID->setVisible(true);
        ui->labelOrderID->setText(QString::fromStdString("#")+QString::number(orderID));
        //ui->btnSetup->setIcon(QIcon(":/icons/setup_con"));
        //ui->btnSetup->setIconSize(QSize(200, 32));
        ui->btnSetup->setText(QString::fromStdString("Continue setUP"));
        ui->labelInvoice->setVisible(true);
        ui->labelInvoiceID->setVisible(true);
        ui->labelInvoiceID->setText(QString::fromStdString("#")+QString::number(mInvoiceid));
    }
    else {
        ui->comboBilling->setEnabled(true);
        ui->btnSetup->setEnabled(true);
        ui->btnSetupReset->setEnabled(false);
        ui->payButton->setEnabled(true);
        ui->labelOrder->setVisible(false);
        ui->labelOrderID->setVisible(false);
        ui->labelInvoice->setVisible(false);
        ui->labelInvoiceID->setVisible(false);
    }
}

void MasternodeList::nodeSetupResetClientId( )  {
    nodeSetupSetClientId( 0 , "", "");
    //ui->widgetLogin->show();
    //ui->widgetCurrent->hide();
    ui->setupButtons->hide();
    ui->labelClientId->setText("");
    ui->labelClientIdValue->hide();
    ui->btnRestore->setText("Restore");

    ui->btnSetup->setEnabled(false);
    mClientid = 0;
    nodeSetupResetOrderId();
    ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
    ui->labelMessage->setText("Enter your client data and create a new user or login an existing one.");
}

void MasternodeList::nodeSetupResetOrderId( )   {
    nodeSetupLockWallet();
    nodeSetupSetOrderId( 0, 0, "");
    ui->btnSetupReset->setEnabled(false);
    ui->btnSetup->setEnabled(true);
    //ui->btnSetup->setIcon(QIcon(":/icons/setup"));
    //ui->btnSetup->setIconSize(QSize(200, 32));
    ui->btnSetup->setText(QString::fromStdString("1-click setUP"));
    ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
    ui->labelMessage->setText("Select a node Tier and then follow below steps for setup.");
    mOrderid = mInvoiceid = mServiceId = 0;
    mPaymentTx = "";
    nodeSetupSetPaymentTx("");
    nodeSetupSetBurnTx("");
    nodeSetupCleanProgress();
}

void MasternodeList::nodeSetupEnableClientId( int clientId )  {
    //ui->widgetLogin->hide();
    //ui->widgetCurrent->show();
    ui->setupButtons->show();
    ui->labelClientIdValue->show();
    ui->labelClientId->setText("#"+QString::number(clientId));
    ui->labelMessage->setStyleSheet("QLabel { font-size:14px;color: #6f80ab;}");
    ui->labelMessage->setText("Select a node Tier and press '1-Click setUP' to verify if you meet the prerequisites");
    mClientid = clientId;
    ui->btnRestore->setText("Support");
}

void MasternodeList::nodeSetupPopulateInvoicesCombo( )  {
    QString email, pass, strError;
    int clientId = nodeSetupGetClientId( email, pass, true );
    if ( clientId == 0 || pass == "" )    return;   // not logged in

    std::map<int, std::string> pendingInvoices = nodeSetupAPIListInvoices( email, pass, strError );

    // preserve previous selection before clearing
    int invoiceToPay = ui->comboInvoice->currentData().toInt();
    ui->comboInvoice->clear();

    // populate
    for(auto& itemPair : pendingInvoices)   {
        if (mInvoiceid!=itemPair.first) {       // discard current setup invoice from pending invoices combo
            ui->comboInvoice->addItem(QString::fromStdString(itemPair.second), QVariant(itemPair.first));
        }
    }

    // restore selection (if still exists)
    int index = ui->comboInvoice->findData(invoiceToPay);
    if ( index != -1 ) { // -1 for not found
       ui->comboInvoice->setCurrentIndex(index);
    }
}

void MasternodeList::nodeSetupPopulateBurnTxCombo( )  {
    std::map<std::string, pair_burntx> freeBurnTxs = nodeSetupGetUnusedBurnTxs( );

    // preserve previous selection before clearing
    QString burnTxSelection = ui->comboBurnTx->currentData().toString();

    ui->comboBurnTx->clear();
    ui->comboBurnTx->addItem(tr("<Create new>"),"NEW");

    // sort the hashmap by confirms (desc)
    std::vector<std::pair<string, pair_burntx> > orderedVector (freeBurnTxs.begin(), freeBurnTxs.end());
    std::sort(orderedVector.begin(), orderedVector.end(), vectorBurnTxCompare());

    for(auto& itemPair : orderedVector)   {
        ui->comboBurnTx->addItem(QString::fromStdString(itemPair.second.second), QVariant(QString::fromStdString(itemPair.first)));
    }

    // restore selection (if still exists)
    int index = ui->comboBurnTx->findData(burnTxSelection);
    if ( index != -1 ) { // -1 for not found
       ui->comboBurnTx->setCurrentIndex(index);
    }

}

int MasternodeList::nodeSetupGetBurnAmount()    {
    int nMasternodeBurn = 0;

    if ( ui->radioLILNode->isChecked() )    nMasternodeBurn = Params().GetConsensus().nMasternodeBurnSINNODE_1;
    if ( ui->radioMIDNode->isChecked() )    nMasternodeBurn = Params().GetConsensus().nMasternodeBurnSINNODE_5;
    if ( ui->radioBIGNode->isChecked() )    nMasternodeBurn = Params().GetConsensus().nMasternodeBurnSINNODE_10;

    return nMasternodeBurn;
}

bool MasternodeList::nodeSetupCheckFunds( CAmount invoiceAmount )   {

    bool bRet = false;
    int nMasternodeBurn = nodeSetupGetBurnAmount();

    QString strSelectedBurnTx = ui->comboBurnTx->currentData().toString();
    if (strSelectedBurnTx!="NEW" && strSelectedBurnTx!="WAIT")   {
        nMasternodeBurn = 0;    // burn tx re-used, no need of funds
    }

    std::string strChecking = "Checking funds";
    nodeSetupStep( "setupWait", strChecking );

    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    CWallet * const pwallet = (wallets.size() > 0) ? wallets[0].get() : nullptr;
    CAmount curBalance = pwallet->GetBalance();
    std::ostringstream stringStream;
    CAmount nNodeRequirement = nMasternodeBurn * COIN ;
    CAmount nUpdateMetaRequirement = (NODESETUP_UPDATEMETA_AMOUNT + 1) * COIN ;

    if ( curBalance > invoiceAmount + nNodeRequirement + nUpdateMetaRequirement)  {
        nodeSetupStep( "setupOk", strChecking + " : " + "funds available.");
        bRet = true;
    }
    else    {
        if ( curBalance > nNodeRequirement + nUpdateMetaRequirement)  {
            QString strAvailable = BitcoinUnits::floorHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), curBalance - nNodeRequirement - nUpdateMetaRequirement);
            QString strInvoiceAmount = BitcoinUnits::floorHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), invoiceAmount );
            stringStream << strChecking << " : not enough funds to pay invoice amount. (you have " << strAvailable.toStdString() << " , need " << strInvoiceAmount.toStdString() << " )";
            std::string copyOfStr = stringStream.str();
                nodeSetupStep( "setupKo", copyOfStr);
        }
        else if ( curBalance > nNodeRequirement  )  {
            QString strAvailable = BitcoinUnits::floorHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), (curBalance - nNodeRequirement) );
            QString strUpdateMeta = BitcoinUnits::floorHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), nUpdateMetaRequirement );
            stringStream << strChecking << " : not enough amount for UpdateMeta operation (you have " <<  strAvailable.toStdString() << " , you need " << strUpdateMeta.toStdString() << " )";
            std::string copyOfStr = stringStream.str();
            nodeSetupStep( "setupKo", copyOfStr);
        }
        else    {
            QString strAvailable = BitcoinUnits::floorHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), curBalance );
            QString strNeed = BitcoinUnits::floorHtmlWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), invoiceAmount + nNodeRequirement + nUpdateMetaRequirement );
            stringStream << strChecking << " : not enough funds (you have " <<  strAvailable.toStdString() << " , you need " << strNeed.toStdString() << " )";
            std::string copyOfStr = stringStream.str();
            nodeSetupStep( "setupKo", copyOfStr);
        }
    }

    currentStep++;
    return bRet;
}

int MasternodeList::nodeSetupGetClientId( QString& email, QString& pass, bool bSilent)  {
    int ret = 0;
    QSettings settings;

    if (settings.contains("nodeSetupClientId"))
        ret = settings.value("nodeSetupClientId").toInt();

    if (settings.contains("nodeSetupEmail"))
        email = settings.value("nodeSetupEmail").toString();

    // pass taken from text control (not stored in settings)
    pass = ui->txtPassword->text();
    if ( pass == "" && !bSilent )   {
        QMessageBox::warning(this, "Please enter password", "Node Setup password is not stored. Please enter nodeSetup password and retry.", QMessageBox::Ok, QMessageBox::Ok);
        ui->txtPassword->setFocus();
    }

    return ret;
}

void MasternodeList::nodeSetupSetClientId( int clientId, QString email, QString pass )  {
    QSettings settings;
    settings.setValue("nodeSetupClientId", clientId);
    settings.setValue("nodeSetupEmail", email);
}

int MasternodeList::nodeSetupGetOrderId( int& invoiceid, QString& productids )  {
    int ret = 0;
    QSettings settings;

    if (settings.contains("nodeSetupOrderId"))
        ret = settings.value("nodeSetupOrderId").toInt();

    if (settings.contains("nodeSetupInvoiceId"))
        invoiceid = settings.value("nodeSetupInvoiceId").toInt();

    if (settings.contains("nodeSetupProductIds"))
        productids = settings.value("nodeSetupProductIds").toString();

    return ret;
}

void MasternodeList::nodeSetupSetOrderId( int orderid , int invoiceid, QString productids )  {
    QSettings settings;
    settings.setValue("nodeSetupOrderId", orderid);
    settings.setValue("nodeSetupInvoiceId", invoiceid);
    settings.setValue("nodeSetupProductIds", productids);
}

QString MasternodeList::nodeSetupGetBurnTx( )  {
    QString ret = 0;
    QSettings settings;

    if (settings.contains("nodeSetupBurnTx"))
        ret = settings.value("nodeSetupBurnTx").toString();

    if (ret=="WAIT")    ret = "";
    return ret;
}

void MasternodeList::nodeSetupSetBurnTx( QString strBurnTx )  {
    QSettings settings;
    settings.setValue("nodeSetupBurnTx", strBurnTx);
}

int MasternodeList::nodeSetupGetServiceForNodeAddress( QString nodeAdress ) {
    int ret = 0;
    QSettings settings;
    QString key = "nodeSetupService"+nodeAdress;

    if (settings.contains(key))
        ret = settings.value(key).toInt();

    return ret;
}

void MasternodeList::nodeSetupSetServiceForNodeAddress( QString nodeAdress, int serviceId )  {
    QSettings settings;
    QString key = "nodeSetupService"+nodeAdress;

    settings.setValue(key, serviceId);
}

QString MasternodeList::nodeSetupGetPaymentTx( )  {
    QString ret = 0;
    QSettings settings;

    if (settings.contains("nodeSetupPaymentTx"))
        ret = settings.value("nodeSetupPaymentTx").toString();

    return ret;
}

void MasternodeList::nodeSetupSetPaymentTx( QString txHash )  {
    QSettings settings;
    settings.setValue("nodeSetupPaymentTx", txHash);
}

int MasternodeList::nodeSetupAPIAddClient( QString firstName, QString lastName, QString email, QString password, QString& strError )  {
    int ret = 0;

    QString commit = QString::fromStdString(getGitCommitId());
    QString Service = QString::fromStdString("AddClient");
    QUrl url( MasternodeList::NODESETUP_ENDPOINT_BASIC );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("action", Service);
    urlQuery.addQueryItem("firstname", firstName);
    urlQuery.addQueryItem("lastname", lastName);
    urlQuery.addQueryItem("email", email);
    urlQuery.addQueryItem("password2", password);
    urlQuery.addQueryItem("ver", commit);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
//LogPrintf("nodeSetupAPIAddClient -- %s\n", url.toString().toStdString());

    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);

    if ( json.object().contains("clientid") )   {
        ret = json.object()["clientid"].toInt();
    }

    if ( json.object().contains("result") && json.object()["result"]=="error" && ret == 0 && json.object().contains("message")) {
        strError = json.object()["message"].toString();
    }
    return ret;
}

int MasternodeList::nodeSetupAPIAddOrder( int clientid, QString billingCycle, QString& productids, int& invoiceid, QString email, QString password, QString& strError )  {
    int orderid = 0;

    QString Service = QString::fromStdString("AddOrder");
    QUrl url( MasternodeList::NODESETUP_ENDPOINT_BASIC );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("action", Service);
    urlQuery.addQueryItem("clientid", QString::number(clientid));
    urlQuery.addQueryItem("pid", NODESETUP_PID );
    urlQuery.addQueryItem("domain", "nodeSetup.sinovate.io");
    urlQuery.addQueryItem("billingcycle", billingCycle);
    urlQuery.addQueryItem("paymentmethod", "sin");
    urlQuery.addQueryItem("email", email);
    urlQuery.addQueryItem("password2", password);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
//LogPrintf("nodeSetup::AddOrder -- %s\n", url.toString().toStdString());
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);

    if ( json.object().contains("result") ) {
        if ( json.object()["result"]=="success" ) {
            if ( json.object().contains("orderid") ) {
                orderid = json.object()["orderid"].toInt();
            }
            if ( json.object().contains("productids") ) {
                productids = json.object()["productids"].toString();
            }
            if ( json.object().contains("invoiceid") ) {
                invoiceid = json.object()["invoiceid"].toInt();
            }
        }
        else    {
            if ( json.object().contains("message") )    {
                strError = json.object()["message"].toString();
            }
        }
    }

    return orderid;
}

bool MasternodeList::nodeSetupAPIGetInvoice( int invoiceid, QString& strAmount, QString& strStatus, QString& paymentAddress, QString email, QString password, QString& strError )  {
    bool ret = false;

    QString Service = QString::fromStdString("GetInvoice");
    QUrl url( MasternodeList::NODESETUP_ENDPOINT_BASIC );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("action", Service);
    urlQuery.addQueryItem("invoiceid", QString::number(invoiceid));
    urlQuery.addQueryItem("email", email);
    urlQuery.addQueryItem("password2", password);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
//LogPrintf("nodeSetup::GetInvoice -- %s\n", url.toString().toStdString());
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);
    QString strData = QString(data);

    QJsonObject root = json.object();

    if ( root.contains("result") ) {
        if ( root["result"]=="success" && root.contains("transactions") ) {
// LogPrintf("nodeSetup::GetInvoice result \n" );
            if ( root.contains("status") ) {
                strStatus = root["status"].toString();
                LogPrintf("nodeSetup::GetInvoice contains status %s \n", strStatus.toStdString() );
            }

            QJsonArray jsonArray = root["transactions"].toObject()["transaction"].toArray();
            QJsonObject tx = jsonArray.first().toObject();
            if ( tx.contains("description") ) {
                strAmount = tx["description"].toString();
            }

            if ( tx.contains("transid") ) {
                paymentAddress = tx["transid"].toString();
            }

            QJsonArray jsonArray2 = root["items"].toObject()["item"].toArray();
            QJsonObject item = jsonArray2.first().toObject();
            if ( item.contains("relid") ) {
                mServiceId = item["relid"].toInt();
            }

            ret = true;
        }
        else    {
            if ( root.contains("message") )    {
                strError = root["message"].toString();
            }
        }
    }
    else    {
        strError = strData;
    }

    return ret;
}

std::map<int,std::string> MasternodeList::nodeSetupAPIListInvoices( QString email, QString password, QString& strError )    {
    std::map<int,std::string> ret;

    QString Service = QString::fromStdString("ListInvoices");
    QUrl url( MasternodeList::NODESETUP_ENDPOINT_BASIC );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("action", Service);
    urlQuery.addQueryItem("email", email);
    urlQuery.addQueryItem("password2", password);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);
    QJsonObject root = json.object();

    if ( root.contains("result") && root["result"]=="success" && root.contains("invoices") ) {
        QJsonArray jsonArray = root["invoices"].toObject()["invoice"].toArray();
        for (const QJsonValue & value : jsonArray) {
            QJsonObject obj = value.toObject();
            int invoiceId = obj["id"].toInt();
            QString status = obj["status"].toString();
            QString total = obj["total"].toString() + " " + obj["currencycode"].toString();
            QString duedate = obj["duedate"].toString();
//LogPrintf("nodeSetupAPIListInvoices %d, %s, %s \n",invoiceId, status.toStdString(), duedate.toStdString() );
            if ( status == "Unpaid" )   {
                QString description = "#" + QString::number(invoiceId) + " " + duedate + " (" + total + " )";
                ret.insert( { invoiceId , description.toStdString() } );
            }
        }
    }
    else    {
        if ( root.contains("message") )    {
            strError = root["message"].toString();
        }
        else    {
            strError = "ERROR API ListInvoices";
        }
    }

    return ret;
}

QJsonObject MasternodeList::nodeSetupAPIInfo( int serviceid, int clientid, QString email, QString password, QString& strError )  {

    QString Service = QString::fromStdString("info");
    QUrl url( MasternodeList::NODESETUP_ENDPOINT_NODE );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("action", Service);
    urlQuery.addQueryItem("serviceid", QString::number(serviceid));
    urlQuery.addQueryItem("clientid", QString::number(clientid));
    urlQuery.addQueryItem("email", email);
    urlQuery.addQueryItem("password", password);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
//LogPrintf("nodeSetup::Info -- %s\n", url.toString().toStdString());
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);
    QJsonObject root = json.object();

    return root;
}

bool MasternodeList::nodeSetupAPINodeList( QString email, QString password, QString& strError  )  {
    bool ret = false;

    QString Service = QString::fromStdString("nodelist");
    QUrl url( MasternodeList::NODESETUP_ENDPOINT_BASIC );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("action", Service);
    urlQuery.addQueryItem("email", email);
    urlQuery.addQueryItem("password2", password);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
//LogPrintf("nodeSetup::NodeList -- %s\n", url.toString().toStdString());
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);
    QJsonObject root = json.object();
    int serviceId;
    QString strAddress;

    if ( root.contains("result") && root["result"]=="success" && root.contains("products") ) {
        QJsonArray jsonArray = root["products"].toObject()["product"].toArray();
        for (const QJsonValue & value : jsonArray) {
            QJsonObject obj = value.toObject();
            serviceId = obj["id"].toInt();
            if ( obj.contains("customfields") )   {
                QJsonArray customfieldsArray = obj["customfields"].toObject()["customfield"].toArray();
                for (const QJsonValue & customfield : customfieldsArray) {
                    QJsonObject field = customfield.toObject();
                    if ( field["name"].toString() == "Address" )    {
                        nodeSetupSetServiceForNodeAddress( field["value"].toString(), serviceId );
                        ret = true;
                        break;
                    }
                }
            }
        }
    }
    else    {
        if ( root.contains("message") )    {
            strError = root["message"].toString();
        }
        else    {
            strError = "ERROR reading NodeList from API";
        }
    }
    return ret;
}

QJsonObject MasternodeList::nodeSetupAPINodeInfo( int serviceid, int clientid, QString email, QString password, QString& strError )  {
    QJsonObject ret;

    QString Service = QString::fromStdString("nodeinfo");
    QUrl url( MasternodeList::NODESETUP_ENDPOINT_NODE );
    QUrlQuery urlQuery( url );
    urlQuery.addQueryItem("action", Service);
    urlQuery.addQueryItem("serviceid", QString::number(serviceid));
    urlQuery.addQueryItem("clientid", QString::number(clientid));
    urlQuery.addQueryItem("email", email);
    urlQuery.addQueryItem("password", password);
    url.setQuery( urlQuery );

    QNetworkRequest request( url );
//LogPrintf("nodeSetup::Info -- %s\n", url.toString().toStdString());
    QNetworkReply *reply = ConnectionManager->get(request);
    QEventLoop loop;

    connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
    loop.exec();

    QByteArray data = reply->readAll();
    QJsonDocument json = QJsonDocument::fromJson(data);
    QJsonObject root = json.object();

    return root;
}

// facilitate reusing burn txs and migration from VPS hosting to nodeSetup hosting
// pick only burn txs less than 1yr old, and not in use by any "ready" DIN node.
std::map<std::string, pair_burntx> MasternodeList::nodeSetupGetUnusedBurnTxs( ) {

    std::map<std::string, pair_burntx> ret;

    CAmount nFee;
    std::string strSentAccount;
    std::list<COutputEntry> listReceived;
    std::list<COutputEntry> listSent;
    isminefilter filter = ISMINE_SPENDABLE;

    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    CWallet * const pwallet = (wallets.size() > 0) ? wallets[0].get() : nullptr;

    if (pwallet==nullptr)   return ret;

    LOCK2(cs_main, pwallet->cs_wallet);

    const CWallet::TxItems & txOrdered = pwallet->wtxOrdered;

    // iterate backwards until we reach >1 yr to return:
    for (CWallet::TxItems::const_reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
    {
        CWalletTx *const pwtx = (*it).second.first;
        if (pwtx == nullptr)    continue;

        int confirms = pwtx->GetDepthInMainChain(false);
        if (confirms>720*365)   continue;  // expired

        pwtx->GetAmounts(listReceived, listSent, nFee, strSentAccount, filter);
        for (const COutputEntry& s : listSent)
        {
            std::string destAddress="";
            if (IsValidDestination(s.destination)) {
                destAddress = EncodeDestination(s.destination);
            }
            std::string txHash = pwtx->GetHash().GetHex();
            if (destAddress == Params().GetConsensus().cBurnAddress && confirms<720*365 && nodeSetupUsedBurnTxs.find(txHash.substr(0, 16)) == nodeSetupUsedBurnTxs.end() )  {

                std::string description = "";
                QString strNodeType = "";
                CAmount roundAmount = ((int)(s.amount / COIN)+1);
                strNodeType = nodeSetupGetNodeType(roundAmount);

                description = strNodeType.toStdString() + " " + GUIUtil::dateTimeStr(pwtx->GetTxTime()).toUtf8().constData() + " " + txHash.substr(0, 8);
//LogPrintf("nodeSetupGetUnusedBurnTxs  confirmed %s, %d, %s \n", txHash.substr(0, 16), roundAmount, description);
                ret.insert( { txHash,  std::make_pair(confirms, description) } );
            }
        }
    }

    return ret;
}

QString MasternodeList::nodeSetupGetNodeType( CAmount amount )   {
    QString strNodeType;

    if ( amount == Params().GetConsensus().nMasternodeBurnSINNODE_1 )  {
        strNodeType = "MINI";
    }
    else if ( amount == Params().GetConsensus().nMasternodeBurnSINNODE_5 )  {
        strNodeType = "MID";
    }
    else if ( amount == Params().GetConsensus().nMasternodeBurnSINNODE_10 )  {
        strNodeType = "BIG";
    }
    else    {
        strNodeType = "Unknown";
    }
    return strNodeType;
}

void MasternodeList::nodeSetupStep( std::string icon , std::string text )   {

    QString themeVersion = GetStringStyleValue("platformstyle/version", "1");
    if (themeVersion == "1") {
    std::string strIcon = ":/styles/theme1/app-icons/" + icon;
    QMovie *movie = new QMovie( QString::fromStdString(strIcon));
    labelPic[currentStep]->setMovie(movie);
    movie->start();    
    }
    if (themeVersion == "2") {
    std::string strIcon = ":/styles/theme2/app-icons/" + icon;
    QMovie *movie = new QMovie( QString::fromStdString(strIcon));
    labelPic[currentStep]->setMovie(movie);
    movie->start();    
    }
    if (themeVersion == "3") {
    std::string strIcon = ":/styles/theme3/app-icons/" + icon;
    QMovie *movie = new QMovie( QString::fromStdString(strIcon));
    labelPic[currentStep]->setMovie(movie);
    movie->start();    
    }
    labelPic[currentStep]->setVisible(true);
    labelTxt[currentStep]->setVisible(true);
    labelTxt[currentStep]->setText( QString::fromStdString( text ) );

}

void MasternodeList::nodeSetupCleanProgress()   {

    for(int idx=0;idx<8;idx++) {
        labelPic[idx]->setVisible(false);
        labelTxt[idx]->setVisible(false);
    }
    currentStep = 0;
}

void MasternodeList::showTab_setUP(bool fShow)
{
    ui->tabWidget->setCurrentIndex(1);
    
}

// RPC helper
UniValue nodeSetupCallRPC(string args)
{
    vector<string> vArgs;
    string uri;

//LogPrintf("nodeSetupCallRPC  %s\n", args);

    boost::split(vArgs, args, boost::is_any_of(" \t"));
    string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    //Array params = RPCConvertValues(strMethod, vArgs);
    UniValue params = RPCConvertValues(strMethod, vArgs );

    JSONRPCRequest req;
    req.params = params;
    req.strMethod = strMethod;
    req.URI = uri;
    return ::tableRPC.execute(req);
}

void MasternodeList::on_btnRestore_clicked()
{
    if (bNodeSetupLogged)   {
        QDesktopServices::openUrl(QUrl(NODESETUP_SUPPORT_URL, QUrl::TolerantMode));
    }
    else    {
        QDesktopServices::openUrl(QUrl(NODESETUP_RESTORE_URL, QUrl::TolerantMode));
    }
}

bool MasternodeList::nodeSetupUnlockWallet()    {

    if (pUnlockCtx!=NULL)   return true; // already unlocked
    WalletModel::EncryptionStatus encStatus = walletModel->getEncryptionStatus();
    if(encStatus == walletModel->Locked) {
        pUnlockCtx = new WalletModel::UnlockContext(walletModel->requestUnlock());

        if(!pUnlockCtx->isValid()) {
            nodeSetupLockWallet();
            return false; // Unlock wallet was cancelled
        }
//LogPrintf("nodeSetupUnlockWallet: unlocked \n" );
        return true;
    }
    return true;
}

void MasternodeList::nodeSetupLockWallet()    {
    if (pUnlockCtx==NULL)   return; // already locked
    delete pUnlockCtx;
    pUnlockCtx = NULL;
//LogPrintf("nodeSetupLockWallet: locked \n" );
}

QString MasternodeList::nodeSetupGetRPCErrorMessage( UniValue objError )    {
    QString ret;
    try // Nice formatting for standard-format error
    {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        ret = QString::fromStdString(message) + " (code " + QString::number(code) + ")";
    }
    catch (const std::runtime_error&) // raised when converting to invalid type, i.e. missing code or message
    {   // Show raw JSON object
        ret = QString::fromStdString(objError.write());
    }

    return ret;
}

// ++ DIN ROI Stats
void MasternodeList::onResult(QNetworkReply* replystats)
{
    QVariant statusCode = replystats->attribute(QNetworkRequest::HttpStatusCodeAttribute);

    if( statusCode == 200)
    {
        QString replyString = (QString) replystats->readAll();

        QJsonDocument jsonResponse = QJsonDocument::fromJson(replyString.toUtf8());
        QJsonObject jsonObject = jsonResponse.object();

        QJsonObject dataObject = jsonObject.value("data").toArray()[0].toObject();

        QLocale l = QLocale(QLocale::English);

          // Set INFINITY NODE STATS strings
        int bigRoiDays = (365/(1000000/((720/dataObject.value("inf_online_big").toDouble())*1752)))*100-100;
        int midRoiDays = (365/(500000/((720/dataObject.value("inf_online_mid").toDouble())*838)))*100-100;
        int lilRoiDays = (365/(100000/((720/dataObject.value("inf_online_lil").toDouble())*560)))*100-100;

        QString bigROIString = QString::number(bigRoiDays, 'f', 0);
        QString midROIString = QString::number(midRoiDays, 'f', 0);
        QString lilROIString = QString::number(lilRoiDays, 'f', 0);

        ui->bigRoiLabel->setText("ROI " + bigROIString + "%");
        ui->midRoiLabel->setText("ROI " + midROIString + "%");
        ui->miniRoiLabel->setText("ROI " + lilROIString + "%");
        
       
    }
    else
    {
        const QString noValue = "NaN";
       
        ui->bigRoiLabel->setText(noValue);
        ui->midRoiLabel->setText(noValue);
        ui->miniRoiLabel->setText(noValue);
       
    }
}
    
void MasternodeList::getStatistics()
{
    QUrl summaryUrl("https://explorer.sinovate.io/ext/summary");
    QNetworkRequest request;
    request.setUrl(summaryUrl);
    m_networkManager->get(request);
}

void MasternodeList::on_setupSinovateButton_clicked() {
    QDesktopServices::openUrl(QUrl("https://setup.sinovate.io/", QUrl::TolerantMode));
}

// --
