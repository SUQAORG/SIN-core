#include "statspage.h"
#include "forms/ui_statspage.h"
#include <qt/platformstyle.h>

#include <QTimer>
#include <QUrl>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>


StatsPage::StatsPage(const PlatformStyle* platformStyle, QWidget *parent) :
    QWidget(parent),
    m_timer(nullptr),
    m_ui(new Ui::StatsPage),
    m_networkManager(new QNetworkAccessManager(this)),
    m_platformStyle(platformStyle)
{
    m_ui->setupUi(this);

 	m_timer = new QTimer(this);
    connect(m_timer, SIGNAL(timeout()), this, SLOT(getStatistics()));
    m_timer->start(311000);
    connect(m_networkManager, SIGNAL(finished(QNetworkReply*)), this, SLOT(onResult(QNetworkReply*)));
    getStatistics();
}

StatsPage::~StatsPage()
{
    if(m_timer) disconnect(m_timer, SIGNAL(timeout()), this, SLOT(privateSendStatus()));
    delete m_ui;
    delete m_networkManager;
}

void StatsPage::getStatistics()
{
    QUrl summaryUrl("https://stats.sinovate.io/summary.php");
    QNetworkRequest request;
    request.setUrl(summaryUrl);
    m_networkManager->get(request);
}

void StatsPage::onResult(QNetworkReply* reply)
{
    QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);

    if( statusCode == 200)
    {
        QString replyString = (QString) reply->readAll();

        QJsonDocument jsonResponse = QJsonDocument::fromJson(replyString.toUtf8());
        QJsonObject jsonObject = jsonResponse.object();

        QJsonObject dataObject = jsonObject.value("data").toArray()[0].toObject();

        QLocale l = QLocale(QLocale::English);
        // Set NETWORK strings
        QString heightValue(dataObject.value("blockcount").toVariant().toString());
        QString knownHashrateString = QString::number(dataObject.value("known_hashrate").toDouble()/1000000, 'f', 2);
        QString hashrateString = knownHashrateString;
        m_ui->hashrateValueLabel->setText(hashrateString +" MH/s");
        m_ui->difficultyValueLabel->setText(dataObject.value("difficulty").toVariant().toString());
        m_ui->lastPriceValueLabel->setText(QString::number(dataObject.value("lastPrice").toDouble(), 'f', 8) + QString(" BTC"));
        m_ui->heightValueLabel->setText(heightValue);

          
        // Set ADDRESS STATS strings
        int top10 = dataObject.value("explorerTop10").toDouble();
        int top50 = dataObject.value("explorerTop50").toDouble();
        m_ui->addressesValueLabel->setText(dataObject.value("explorerAddresses").toVariant().toString());
        m_ui->activeValueLabel->setText(dataObject.value("explorerActiveAddresses").toVariant().toString());
        m_ui->top10ValueLabel->setText(l.toString(top10) + " SIN");
        m_ui->top50ValueLabel->setText(l.toString(top50) + " SIN");

        // Set BURNT COIN STATS strings
        int supplyNumber = dataObject.value("supply").toDouble() - dataObject.value("burnFee").toDouble();
        int feeNumber = dataObject.value("burnFee").toDouble() - dataObject.value("burnNode").toDouble();
        int burntNumber = dataObject.value("burnFee").toDouble();

        m_ui->feeValueLabel->setText(l.toString(feeNumber)+ " SIN");
        m_ui->nodesValueLabel->setText(l.toString(dataObject.value("burnNode").toInt())+ " SIN");
        m_ui->totalBurntValueLabel->setText(l.toString(burntNumber)+ " SIN");
        m_ui->totalSupplyValueLabel->setText(l.toString(supplyNumber)+ " SIN");
        m_ui->circulationSupplyValueLabel->setText(l.toString(supplyNumber)+ " SIN");

        // Set INFINITY NODE STATS strings
        int bigRoiDays = 1000000/((720/dataObject.value("inf_online_big").toDouble())*1752);
        int midRoiDays = 500000/((720/dataObject.value("inf_online_mid").toDouble())*838);
        int lilRoiDays = 100000/((720/dataObject.value("inf_online_lil").toDouble())*560);

        //++
        int bigRoiDaysPercent = (365/(1000000/((720/dataObject.value("inf_online_big").toDouble())*1752)))*100-100;
        int midRoiDaysPercent = (365/(500000/((720/dataObject.value("inf_online_mid").toDouble())*838)))*100-100;
        int lilRoiDaysPercent = (365/(100000/((720/dataObject.value("inf_online_lil").toDouble())*560)))*100-100;

        QString bigROIStringPercent = QString::number(bigRoiDaysPercent, 'f', 0);
        QString midROIStringPercent = QString::number(midRoiDaysPercent, 'f', 0);
        QString lilROIStringPercent = QString::number(lilRoiDaysPercent, 'f', 0);
        //--

        QString bigROIString = "ROI: " + QString::number(bigRoiDays) + " days" ;
        QString midROIString = "ROI: " + QString::number(midRoiDays) + " days";
        QString lilROIString = "ROI: " + QString::number(lilRoiDays) + " days";
        QString totalNodesString = QString::number(dataObject.value("inf_online_big").toInt() + dataObject.value("inf_online_mid").toInt() + dataObject.value("inf_online_lil").toInt());
    
        QString bigString = dataObject.value("inf_online_big").toVariant().toString();
        QString midString = dataObject.value("inf_online_mid").toVariant().toString();
        QString lilString = dataObject.value("inf_online_lil").toVariant().toString();
        m_ui->bigValueLabel->setText(bigString);
        m_ui->midValueLabel->setText(midString);
        m_ui->lilValueLabel->setText(lilString);
        m_ui->totalValueLabel->setText(totalNodesString);
        m_ui->bigRoiLabel->setText(bigROIStringPercent + "%");
        m_ui->midRoiLabel->setText(midROIStringPercent + "%");
        m_ui->miniRoiLabel->setText(lilROIStringPercent + "%");

    }
    else
    {
        const QString noValue = "NaN";
        m_ui->hashrateValueLabel->setText(noValue);
        m_ui->difficultyValueLabel->setText(noValue);
        m_ui->lastPriceValueLabel->setText(noValue);
        m_ui->heightValueLabel->setText(noValue);

        m_ui->addressesValueLabel->setText(noValue);
        m_ui->activeValueLabel->setText(noValue);
        m_ui->top10ValueLabel->setText(noValue);
        m_ui->top50ValueLabel->setText(noValue);

        m_ui->feeValueLabel->setText(noValue);
        m_ui->nodesValueLabel->setText(noValue);
        m_ui->totalBurntValueLabel->setText(noValue);
        m_ui->totalSupplyValueLabel->setText(noValue);

        m_ui->bigValueLabel->setText(noValue);
        m_ui->midValueLabel->setText(noValue);
        m_ui->lilValueLabel->setText(noValue);
        m_ui->totalValueLabel->setText(noValue);
    }
    reply->deleteLater();
}
