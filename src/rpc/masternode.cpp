// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 FXTC developers
// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <activemasternode.h>
#include <init.h>
#include <netbase.h>
#include <key_io.h>
#include <validation.h>
#include <masternode-payments.h>
#include <masternode-sync.h>
#include <masternodeconfig.h>
#include <masternodeman.h>
#include <infinitynodeman.h>
#include <infinitynodersv.h>
#include <infinitynodemeta.h>
#include <infinitynodepeer.h>
#ifdef ENABLE_WALLET
#include <wallet/coincontrol.h>
#endif // ENABLE_WALLET
#include <rpc/server.h>
#include <util/system.h>
#include <util/moneystr.h>
#include <consensus/validation.h>

#include <fstream>
#include <iomanip>
#include <univalue.h>

UniValue masternodelist(const JSONRPCRequest& request);

#ifdef ENABLE_WALLET
void EnsureWalletIsUnlocked();
#endif // ENABLE_WALLET

UniValue masternode(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
#endif // ENABLE_WALLET

    std::string strCommand;
    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }

#ifdef ENABLE_WALLET
    if (strCommand == "start-many")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "DEPRECATED, please use start-all instead");
#endif // ENABLE_WALLET

    if (request.fHelp  ||
        (
#ifdef ENABLE_WALLET
            strCommand != "start-alias" && strCommand != "start-all" && strCommand != "start-missing" &&
         strCommand != "start-disabled" && strCommand != "outputs" &&
#endif // ENABLE_WALLET
         strCommand != "list" && strCommand != "list-conf" && strCommand != "count" &&
         strCommand != "debug" && strCommand != "current" && strCommand != "winner" && strCommand != "winners" && strCommand != "genkey" &&
         strCommand != "connect" && strCommand != "status" && strCommand != "collateral"))
            throw std::runtime_error(
                "masternode \"command\"...\n"
                "Set of commands to execute masternode related actions\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "\nAvailable commands:\n"
                "  count        - Print number of all known masternodes (optional: 'ps', 'enabled', 'all', 'qualify')\n"
                "  current      - Print info on current masternode winner to be paid the next block (calculated locally)\n"
                "  genkey       - Generate new masternodeprivkey\n"
#ifdef ENABLE_WALLET
                "  outputs      - Print masternode compatible outputs\n"
                "  start-alias  - Start single remote masternode by assigned alias configured in masternode.conf\n"
                "  start-<mode> - Start remote masternodes configured in masternode.conf (<mode>: 'all', 'missing', 'disabled')\n"
#endif // ENABLE_WALLET
                "  status       - Print masternode status information\n"
                "  list         - Print list of all known masternodes (see masternodelist for more info)\n"
                "  list-conf    - Print masternode.conf in JSON format\n"
                "  winner       - Print info on next masternode winner to vote for\n"
                "  winners      - Print list of masternode winners\n"
                );

    if (strCommand == "list")
    {
        JSONRPCRequest newRequest;
        newRequest.fHelp = request.fHelp;
        // forward params but skip "list"
        for (unsigned int i = 1; i < request.params.size(); i++) {
            newRequest.params.push_back(request.params[i]);
        }
        return masternodelist(newRequest);
    }

    if(strCommand == "connect")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode address required");

        std::string strAddress = request.params[1].get_str();

        CService addr;
        if (!Lookup(strAddress.c_str(), addr, 0, false))
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Incorrect masternode address %s", strAddress));

        // TODO: Pass CConnman instance somehow and don't use global variable.
        CNode *pnode = g_connman->OpenNetworkConnection(CAddress(addr, NODE_NETWORK), false, nullptr, NULL, false, false, false, true);
        //
        if(!pnode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Couldn't connect to masternode %s", strAddress));

        return "successfully connected";
    }

    if (strCommand == "count")
    {
        if (request.params.size() > 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters");

        if (request.params.size() == 1)
            return mnodeman.size();

        std::string strMode = request.params[1].get_str();

        if (strMode == "enabled")
            return mnodeman.CountEnabled();

        int nCount;
        masternode_info_t mnInfo;
        mnodeman.GetNextMasternodeInQueueForPayment(true, nCount, mnInfo);

        if (strMode == "qualify")
            return nCount;

        if (strMode == "all")
            return strprintf("Total: %d (Enabled: %d / Qualify: %d)",
                mnodeman.size(), mnodeman.CountEnabled(), nCount);
    }

    if (strCommand == "current" || strCommand == "winner")
    {
        int nCount;
        int nHeight;
        masternode_info_t mnInfo;
        CBlockIndex* pindex = NULL;
        {
            LOCK(cs_main);
            pindex = chainActive.Tip();
        }
        nHeight = pindex->nHeight + (strCommand == "current" ? 1 : 10);
        mnodeman.UpdateLastPaid(pindex);

        if(!mnodeman.GetNextMasternodeInQueueForPayment(nHeight, true, nCount, mnInfo))
            return "unknown";

        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("height",        nHeight));
        obj.push_back(Pair("IP:port",       mnInfo.addr.ToString()));
        obj.push_back(Pair("protocol",      (int64_t)mnInfo.nProtocolVersion));
        obj.push_back(Pair("outpoint",      mnInfo.vin.prevout.ToStringShort()));
        obj.push_back(Pair("payee",         EncodeDestination(mnInfo.pubKeyCollateralAddress.GetID())));
        obj.push_back(Pair("lastseen",      mnInfo.nTimeLastPing));
        obj.push_back(Pair("activeseconds", mnInfo.nTimeLastPing - mnInfo.sigTime));
        return obj;
    }

#ifdef ENABLE_WALLET
    if (strCommand == "start-alias")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify an alias");

        {
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
        }

        std::string strAlias = request.params[1].get_str();

        bool fFound = false;

        UniValue statusObj(UniValue::VOBJ);
        statusObj.push_back(Pair("alias", strAlias));

        for (CMasternodeConfig::CMasternodeEntry mne : masternodeConfig.getEntries()) {
            if(mne.getAlias() == strAlias) {
                fFound = true;
                std::string strError;
                CMasternodeBroadcast mnb;

                bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), mne.getTxHashBurnFund(), mne.getOutputIndexBurnFund(), strError, mnb);

                statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));
                if(fResult) {
                    mnodeman.UpdateMasternodeList(mnb, *g_connman);
                    mnb.Relay(*g_connman);
                } else {
                    statusObj.push_back(Pair("errorMessage", strError));
                }
                mnodeman.NotifyMasternodeUpdates(*g_connman);
                break;
            }
        }

        if(!fFound) {
            statusObj.push_back(Pair("result", "failed"));
            statusObj.push_back(Pair("errorMessage", "Could not find alias in config. Verify with list-conf."));
        }

        return statusObj;

    }

    if (strCommand == "start-all" || strCommand == "start-missing" || strCommand == "start-disabled")
    {
        {
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
        }

        if((strCommand == "start-missing" || strCommand == "start-disabled") && !masternodeSync.IsMasternodeListSynced()) {
            throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "You can't use this command until masternode list is synced");
        }

        int nSuccessful = 0;
        int nFailed = 0;

        UniValue resultsObj(UniValue::VOBJ);

        for (CMasternodeConfig::CMasternodeEntry mne : masternodeConfig.getEntries()) {
            std::string strError;

            COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
            CMasternode mn;
            bool fFound = mnodeman.Get(outpoint, mn);
            CMasternodeBroadcast mnb;

            if(strCommand == "start-missing" && fFound) continue;
            if(strCommand == "start-disabled" && fFound && mn.IsEnabled()) continue;

            bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), mne.getTxHashBurnFund(), mne.getOutputIndexBurnFund(), strError, mnb);

            UniValue statusObj(UniValue::VOBJ);
            statusObj.push_back(Pair("alias", mne.getAlias()));
            statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));

            if (fResult) {
                nSuccessful++;
                mnodeman.UpdateMasternodeList(mnb, *g_connman);
                mnb.Relay(*g_connman);
            } else {
                nFailed++;
                statusObj.push_back(Pair("errorMessage", strError));
            }

            resultsObj.push_back(Pair("status", statusObj));
        }
        mnodeman.NotifyMasternodeUpdates(*g_connman);

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d masternodes, failed to start %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }
#endif // ENABLE_WALLET

    if (strCommand == "genkey")
    {
        CKey secret;
        secret.MakeNewKey(false);

        return EncodeSecret(secret);
    }

    if (strCommand == "list-conf")
    {
        UniValue resultObj(UniValue::VOBJ);

        for (CMasternodeConfig::CMasternodeEntry mne : masternodeConfig.getEntries()) {
            COutPoint outpoint = COutPoint(uint256S(mne.getTxHash()), uint32_t(atoi(mne.getOutputIndex().c_str())));
            CMasternode mn;
            bool fFound = mnodeman.Get(outpoint, mn);

            std::string strStatus = fFound ? mn.GetStatus() : "MISSING";

            UniValue mnObj(UniValue::VOBJ);
            mnObj.push_back(Pair("alias", mne.getAlias()));
            mnObj.push_back(Pair("address", mne.getIp()));
            mnObj.push_back(Pair("privateKey", mne.getPrivKey()));
            mnObj.push_back(Pair("txHash", mne.getTxHash()));
            mnObj.push_back(Pair("outputIndex", mne.getOutputIndex()));
            mnObj.push_back(Pair("status", strStatus));
            resultObj.push_back(Pair("masternode", mnObj));
        }

        return resultObj;
    }

#ifdef ENABLE_WALLET
    if (strCommand == "outputs") {
        // Find possible candidates
        std::vector<COutput> vPossibleCoins;
        LOCK2(cs_main, pwallet->cs_wallet);
        pwallet->AvailableCoins(vPossibleCoins, true, NULL, false, ONLY_MASTERNODE_COLLATERAL);

        UniValue obj(UniValue::VOBJ);
        for (COutput& out : vPossibleCoins) {
            obj.push_back(Pair(out.tx->GetHash().ToString(), strprintf("%d", out.i)));
        }

        return obj;
    }
#endif // ENABLE_WALLET

    if (strCommand == "status")
    {
        if (!fMasterNode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not a masternode");

        UniValue mnObj(UniValue::VOBJ);

        mnObj.push_back(Pair("outpoint", activeMasternode.outpoint.ToStringShort()));
        mnObj.push_back(Pair("service", activeMasternode.service.ToString()));

        CMasternode mn;
        if(mnodeman.Get(activeMasternode.outpoint, mn)) {
            mnObj.push_back(Pair("payee", EncodeDestination(mn.pubKeyCollateralAddress.GetID())));
        }

        mnObj.push_back(Pair("status", activeMasternode.GetStatus()));
        return mnObj;
    }

    if (strCommand == "winners")
    {
        int nHeight;
        {
            LOCK(cs_main);
            CBlockIndex* pindex = chainActive.Tip();
            if(!pindex) return NullUniValue;

            nHeight = pindex->nHeight;
        }

        int nLast = 10;
        std::string strFilter = "";

        if (request.params.size() >= 2) {
            nLast = atoi(request.params[1].get_str());
        }

        if (request.params.size() == 3) {
            strFilter = request.params[2].get_str();
        }

        if (request.params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'masternode winners ( \"count\" \"filter\" )'");

        UniValue obj(UniValue::VOBJ);

        for(int i = nHeight - nLast; i < nHeight + 20; i++) {
            std::string strPayment = GetRequiredPaymentsString(i);
            if (strFilter !="" && strPayment.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strprintf("%d", i), strPayment));
        }

        return obj;
    }

    return NullUniValue;
}

UniValue masternodelist(const JSONRPCRequest& request)
{
    std::string strMode = "status";
    std::string strFilter = "";

    if (request.params.size() >= 1) strMode = request.params[0].get_str();
    if (request.params.size() == 2) strFilter = request.params[1].get_str();

    if (request.fHelp || (
                strMode != "activeseconds" && strMode != "addr" && strMode != "full" && strMode != "info" &&
                strMode != "lastseen" && strMode != "lastpaidtime" && strMode != "lastpaidblock" &&
                strMode != "protocol" && strMode != "payee" && strMode != "pubkey" &&
                strMode != "rank" && strMode != "status"))
    {
        throw std::runtime_error(
                "masternodelist ( \"mode\" \"filter\" )\n"
                "Get a list of masternodes in different modes\n"
                "\nArguments:\n"
                "1. \"mode\"      (string, optional/required to use filter, defaults = status) The mode to run list in\n"
                "2. \"filter\"    (string, optional) Filter results. Partial match by outpoint by default in all modes,\n"
                "                                    additional matches in some modes are also available\n"
                "\nAvailable modes:\n"
                "  activeseconds  - Print number of seconds masternode recognized by the network as enabled\n"
                "                   (since latest issued \"masternode start/start-many/start-alias\")\n"
                "  addr           - Print ip address associated with a masternode (can be additionally filtered, partial match)\n"
                "  full           - Print info in format 'status protocol payee lastseen activeseconds lastpaidtime lastpaidblock IP'\n"
                "                   (can be additionally filtered, partial match)\n"
                "  info           - Print info in format 'status protocol payee lastseen activeseconds sentinelversion sentinelstate IP'\n"
                "                   (can be additionally filtered, partial match)\n"
                "  lastpaidblock  - Print the last block height a node was paid on the network\n"
                "  lastpaidtime   - Print the last time a node was paid on the network\n"
                "  lastseen       - Print timestamp of when a masternode was last seen on the network\n"
                "  payee          - Print Dash address associated with a masternode (can be additionally filtered,\n"
                "                   partial match)\n"
                "  protocol       - Print protocol of a masternode (can be additionally filtered, exact match)\n"
                "  pubkey         - Print the masternode (not collateral) public key\n"
                "  rank           - Print rank of a masternode based on current block\n"
                "  status         - Print masternode status: PRE_ENABLED / ENABLED / EXPIRED / WATCHDOG_EXPIRED / NEW_START_REQUIRED /\n"
                "                   UPDATE_REQUIRED / POSE_BAN / OUTPOINT_SPENT (can be additionally filtered, partial match)\n"
                );
    }

    if (strMode == "full" || strMode == "lastpaidtime" || strMode == "lastpaidblock") {
        CBlockIndex* pindex = NULL;
        {
            LOCK(cs_main);
            pindex = chainActive.Tip();
        }
        mnodeman.UpdateLastPaid(pindex);
    }

    UniValue obj(UniValue::VOBJ);
    if (strMode == "rank") {
        CMasternodeMan::rank_pair_vec_t vMasternodeRanks;
        mnodeman.GetMasternodeRanks(vMasternodeRanks);
        for (std::pair<int, CMasternode>& s : vMasternodeRanks) {
            std::string strOutpoint = s.second.vin.prevout.ToStringShort();
            if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
            obj.push_back(Pair(strOutpoint, s.first));
        }
    } else {
        std::map<COutPoint, CMasternode> mapMasternodes = mnodeman.GetFullMasternodeMap();
        for (auto& mnpair : mapMasternodes) {
            CMasternode mn = mnpair.second;
            std::string strOutpoint = mnpair.first.ToStringShort();
            if (strMode == "activeseconds") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, (int64_t)(mn.lastPing.sigTime - mn.sigTime)));
            } else if (strMode == "addr") {
                std::string strAddress = mn.addr.ToString();
                if (strFilter !="" && strAddress.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strAddress));
            } else if (strMode == "full") {
                std::ostringstream streamFull;
                int infinityType = mn.GetSinTypeInt();
                int rewardAtHeight = GetMasternodePayment(chainActive.Height(), infinityType) / COIN;
                int burnAmountByType = 0;
                if (infinityType == 1) burnAmountByType = Params().GetConsensus().nMasternodeBurnSINNODE_1;
                if (infinityType == 5) burnAmountByType = Params().GetConsensus().nMasternodeBurnSINNODE_5;
                if (infinityType == 10) burnAmountByType = Params().GetConsensus().nMasternodeBurnSINNODE_10;
                streamFull << std::setw(18) <<
                               mn.GetStatus() << " " <<
                               mn.nProtocolVersion << " " <<
                               EncodeDestination(mn.pubKeyCollateralAddress.GetID()) << " " <<
                               (int64_t)mn.lastPing.sigTime << " " << std::setw(8) <<
                               (int64_t)(mn.lastPing.sigTime - mn.sigTime) << " " << std::setw(10) <<
                               mn.GetLastPaidTime() << " "  << std::setw(6) <<
                               mn.GetLastPaidBlock() << " " <<
                               mn.addr.ToString() << " " << infinityType << " " << rewardAtHeight << " " <<burnAmountByType;
                std::string strFull = streamFull.str();
                if (strFilter !="" && strFull.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strFull));
            } else if (strMode == "info") {
                std::ostringstream streamInfo;
                int infinityType = mn.GetSinTypeInt();
                int rewardAtHeight = GetMasternodePayment(chainActive.Height(), infinityType) / COIN;
                int burnAmountByType = 0;
                if (infinityType == 1) burnAmountByType = Params().GetConsensus().nMasternodeBurnSINNODE_1;
                if (infinityType == 5) burnAmountByType = Params().GetConsensus().nMasternodeBurnSINNODE_5;
                if (infinityType == 10) burnAmountByType = Params().GetConsensus().nMasternodeBurnSINNODE_10;
                streamInfo << std::setw(18) <<
                               mn.GetStatus() << " " <<
                               mn.nProtocolVersion << " " <<
                               EncodeDestination(mn.pubKeyCollateralAddress.GetID()) << " " <<
                               (int64_t)mn.lastPing.sigTime << " " << std::setw(8) <<
                               (int64_t)(mn.lastPing.sigTime - mn.sigTime) << " " <<
                               SafeIntVersionToString(mn.lastPing.nSentinelVersion) << " "  <<
                               (mn.lastPing.fSentinelIsCurrent ? "current" : "expired") << " " <<
                               mn.addr.ToString() << " " << infinityType << " " << rewardAtHeight << " " <<burnAmountByType << " " << mn.GetBurnFundTxInfo();
                std::string strInfo = streamInfo.str();
                if (strFilter !="" && strInfo.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strInfo));
            } else if (strMode == "lastpaidblock") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.GetLastPaidBlock()));
            } else if (strMode == "lastpaidtime") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, mn.GetLastPaidTime()));
            } else if (strMode == "lastseen") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, (int64_t)mn.lastPing.sigTime));
            } else if (strMode == "payee") {
                std::string strPayee = EncodeDestination(mn.pubKeyCollateralAddress.GetID());
                if (strFilter !="" && strPayee.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strPayee));
            } else if (strMode == "protocol") {
                if (strFilter !="" && strFilter != strprintf("%d", mn.nProtocolVersion) &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, (int64_t)mn.nProtocolVersion));
            } else if (strMode == "pubkey") {
                if (strFilter !="" && strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, HexStr(mn.pubKeyMasternode)));
            } else if (strMode == "status") {
                std::string strStatus = mn.GetStatus();
                if (strFilter !="" && strStatus.find(strFilter) == std::string::npos &&
                    strOutpoint.find(strFilter) == std::string::npos) continue;
                obj.push_back(Pair(strOutpoint, strStatus));
            }
        }
    }
    return obj;
}

bool DecodeHexVecMnb(std::vector<CMasternodeBroadcast>& vecMnb, std::string strHexMnb) {

    if (!IsHex(strHexMnb))
        return false;

    std::vector<unsigned char> mnbData(ParseHex(strHexMnb));
    CDataStream ssData(mnbData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> vecMnb;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

UniValue masternodebroadcast(const JSONRPCRequest& request)
{
#ifdef ENABLE_WALLET
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();
#endif // ENABLE_WALLET

    std::string strCommand;
    if (request.params.size() >= 1)
        strCommand = request.params[0].get_str();

    if (request.fHelp  ||
        (
#ifdef ENABLE_WALLET
            strCommand != "create-alias" && strCommand != "create-all" &&
#endif // ENABLE_WALLET
            strCommand != "decode" && strCommand != "relay"))
        throw std::runtime_error(
                "masternodebroadcast \"command\"...\n"
                "Set of commands to create and relay masternode broadcast messages\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "\nAvailable commands:\n"
#ifdef ENABLE_WALLET
                "  create-alias  - Create single remote masternode broadcast message by assigned alias configured in masternode.conf\n"
                "  create-all    - Create remote masternode broadcast messages for all masternodes configured in masternode.conf\n"
#endif // ENABLE_WALLET
                "  decode        - Decode masternode broadcast message\n"
                "  relay         - Relay masternode broadcast message to the network\n"
                );

#ifdef ENABLE_WALLET
    if (strCommand == "create-alias")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Please specify an alias");

        {
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
        }

        bool fFound = false;
        std::string strAlias = request.params[1].get_str();

        UniValue statusObj(UniValue::VOBJ);
        std::vector<CMasternodeBroadcast> vecMnb;

        statusObj.push_back(Pair("alias", strAlias));

        for (CMasternodeConfig::CMasternodeEntry mne : masternodeConfig.getEntries()) {
            if(mne.getAlias() == strAlias) {
                fFound = true;
                std::string strError;
                CMasternodeBroadcast mnb;

                bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), mne.getTxHashBurnFund(), mne.getOutputIndexBurnFund(), strError, mnb, true);

                statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));
                if(fResult) {
                    vecMnb.push_back(mnb);
                    CDataStream ssVecMnb(SER_NETWORK, PROTOCOL_VERSION);
                    ssVecMnb << vecMnb;
                    statusObj.push_back(Pair("hex", HexStr(ssVecMnb.begin(), ssVecMnb.end())));
                } else {
                    statusObj.push_back(Pair("errorMessage", strError));
                }
                break;
            }
        }

        if(!fFound) {
            statusObj.push_back(Pair("result", "not found"));
            statusObj.push_back(Pair("errorMessage", "Could not find alias in config. Verify with list-conf."));
        }

        return statusObj;

    }

    if (strCommand == "create-all")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        {
            LOCK(pwallet->cs_wallet);
            EnsureWalletIsUnlocked(pwallet);
        }

        std::vector<CMasternodeConfig::CMasternodeEntry> mnEntries;
        mnEntries = masternodeConfig.getEntries();

        int nSuccessful = 0;
        int nFailed = 0;

        UniValue resultsObj(UniValue::VOBJ);
        std::vector<CMasternodeBroadcast> vecMnb;

        for (CMasternodeConfig::CMasternodeEntry mne : masternodeConfig.getEntries()) {
            std::string strError;
            CMasternodeBroadcast mnb;

            bool fResult = CMasternodeBroadcast::Create(mne.getIp(), mne.getPrivKey(), mne.getTxHash(), mne.getOutputIndex(), mne.getTxHashBurnFund(), mne.getOutputIndexBurnFund(), strError, mnb, true);

            UniValue statusObj(UniValue::VOBJ);
            statusObj.push_back(Pair("alias", mne.getAlias()));
            statusObj.push_back(Pair("result", fResult ? "successful" : "failed"));

            if(fResult) {
                nSuccessful++;
                vecMnb.push_back(mnb);
            } else {
                nFailed++;
                statusObj.push_back(Pair("errorMessage", strError));
            }

            resultsObj.push_back(Pair("status", statusObj));
        }

        CDataStream ssVecMnb(SER_NETWORK, PROTOCOL_VERSION);
        ssVecMnb << vecMnb;
        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully created broadcast messages for %d masternodes, failed to create %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));
        returnObj.push_back(Pair("detail", resultsObj));
        returnObj.push_back(Pair("hex", HexStr(ssVecMnb.begin(), ssVecMnb.end())));

        return returnObj;
    }
#endif // ENABLE_WALLET

    if (strCommand == "decode")
    {
        if (request.params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'masternodebroadcast decode \"hexstring\"'");

        std::vector<CMasternodeBroadcast> vecMnb;

        if (!DecodeHexVecMnb(vecMnb, request.params[1].get_str()))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Masternode broadcast message decode failed");

        int nSuccessful = 0;
        int nFailed = 0;
        int nDos = 0;
        UniValue returnObj(UniValue::VOBJ);

        for (CMasternodeBroadcast& mnb : vecMnb) {
            UniValue resultObj(UniValue::VOBJ);

            if(mnb.CheckSignature(nDos)) {
                nSuccessful++;
                resultObj.push_back(Pair("outpoint", mnb.vin.prevout.ToStringShort()));
                resultObj.push_back(Pair("addr", mnb.addr.ToString()));
                resultObj.push_back(Pair("pubKeyCollateralAddress", EncodeDestination(mnb.pubKeyCollateralAddress.GetID())));
                resultObj.push_back(Pair("pubKeyMasternode", EncodeDestination(mnb.pubKeyMasternode.GetID())));
                resultObj.push_back(Pair("vchSig", EncodeBase64(&mnb.vchSig[0], mnb.vchSig.size())));
                resultObj.push_back(Pair("sigTime", mnb.sigTime));
                resultObj.push_back(Pair("protocolVersion", mnb.nProtocolVersion));
                resultObj.push_back(Pair("nLastDsq", mnb.nLastDsq));

                UniValue lastPingObj(UniValue::VOBJ);
                lastPingObj.push_back(Pair("outpoint", mnb.lastPing.vin.prevout.ToStringShort()));
                lastPingObj.push_back(Pair("blockHash", mnb.lastPing.blockHash.ToString()));
                lastPingObj.push_back(Pair("sigTime", mnb.lastPing.sigTime));
                lastPingObj.push_back(Pair("vchSig", EncodeBase64(&mnb.lastPing.vchSig[0], mnb.lastPing.vchSig.size())));

                resultObj.push_back(Pair("lastPing", lastPingObj));
            } else {
                nFailed++;
                resultObj.push_back(Pair("errorMessage", "Masternode broadcast signature verification failed"));
            }

            returnObj.push_back(Pair(mnb.GetHash().ToString(), resultObj));
        }

        returnObj.push_back(Pair("overall", strprintf("Successfully decoded broadcast messages for %d masternodes, failed to decode %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));

        return returnObj;
    }

    if (strCommand == "relay")
    {
        if (request.params.size() < 2 || request.params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER,   "masternodebroadcast relay \"hexstring\" ( fast )\n"
                                                        "\nArguments:\n"
                                                        "1. \"hex\"      (string, required) Broadcast messages hex string\n"
                                                        "2. fast       (string, optional) If none, using safe method\n");

        std::vector<CMasternodeBroadcast> vecMnb;

        if (!DecodeHexVecMnb(vecMnb, request.params[1].get_str()))
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Masternode broadcast message decode failed");

        int nSuccessful = 0;
        int nFailed = 0;
        bool fSafe = request.params.size() == 2;
        UniValue returnObj(UniValue::VOBJ);

        // verify all signatures first, bailout if any of them broken
        for (CMasternodeBroadcast& mnb : vecMnb) {
            UniValue resultObj(UniValue::VOBJ);

            resultObj.push_back(Pair("outpoint", mnb.vin.prevout.ToStringShort()));
            resultObj.push_back(Pair("addr", mnb.addr.ToString()));

            int nDos = 0;
            bool fResult;
            if (mnb.CheckSignature(nDos)) {
                if (fSafe) {
                    fResult = mnodeman.CheckMnbAndUpdateMasternodeList(NULL, mnb, nDos, *g_connman);
                } else {
                    mnodeman.UpdateMasternodeList(mnb, *g_connman);
                    mnb.Relay(*g_connman);
                    fResult = true;
                }
                mnodeman.NotifyMasternodeUpdates(*g_connman);
            } else fResult = false;

            if(fResult) {
                nSuccessful++;
                resultObj.push_back(Pair(mnb.GetHash().ToString(), "successful"));
            } else {
                nFailed++;
                resultObj.push_back(Pair("errorMessage", "Masternode broadcast signature verification failed"));
            }

            returnObj.push_back(Pair(mnb.GetHash().ToString(), resultObj));
        }

        returnObj.push_back(Pair("overall", strprintf("Successfully relayed broadcast messages for %d masternodes, failed to relay %d, total %d", nSuccessful, nFailed, nSuccessful + nFailed)));

        return returnObj;
    }

    return NullUniValue;
}

UniValue sentinelping(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "sentinelping version\n"
            "\nSentinel ping.\n"
            "\nArguments:\n"
            "1. version           (string, required) Sentinel version in the form \"x.x.x\"\n"
            "\nResult:\n"
            "state                (boolean) Ping result\n"
            "\nExamples:\n"
            + HelpExampleCli("sentinelping", "1.0.2")
            + HelpExampleRpc("sentinelping", "1.0.2")
        );
    }

    activeMasternode.UpdateSentinelPing(StringVersionToInt(request.params[0].get_str()));
    return true;
}

UniValue infinitynode(const JSONRPCRequest& request)
{
    std::string strCommand;
    std::string strFilter = "";
    std::string strOption = "";
    std::string strError;

    if (request.params.size() >= 1) {
        strCommand = request.params[0].get_str();
    }
    if (request.params.size() == 2) strFilter = request.params[1].get_str();
    if (request.params.size() == 3) {
        strFilter = request.params[1].get_str();
        strOption = request.params[2].get_str();
    }
    if (request.params.size() > 3)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Too many parameters");

    if (request.fHelp  ||
        (strCommand != "build-list" && strCommand != "show-lastscan" && strCommand != "show-infos" && strCommand != "stats"
                                    && strCommand != "show-lastpaid" && strCommand != "build-stm" && strCommand != "show-stm"
                                    && strCommand != "show-candidate" && strCommand != "show-script" && strCommand != "show-proposal"
                                    && strCommand != "scan-vote" && strCommand != "show-proposals" && strCommand != "keypair"
                                    && strCommand != "mypeerinfo" && strCommand != "checkkey" && strCommand != "scan-metadata"
                                    && strCommand != "show-metadata"
        ))
            throw std::runtime_error(
                "infinitynode \"command\"...\n"
                "Set of commands to execute masternode related actions\n"
                "\nArguments:\n"
                "1. \"command\"        (string or set of strings, required) The command to execute\n"
                "\nAvailable commands:\n"
                "  keypair                     - Generation the compressed key pair\n"
                "  mypeerinfo                  - Get status of Peer if this node is Infinitynode\n"
                "  build-list                  - Build list of all infinitynode from block height 165000 to last block\n"
                "  build-stm                   - Build statement list from genesis parameter\n"
                "  show-infos                  - Show the list of nodes and last information\n"
                "  show-lastscan               - Last nHeight when list is updated\n"
                "  show-lastpaid               - Last paid of all nodes\n"
                "  show-stm                    - Last statement of each SinType\n"
                "  show-metadata               - Show the list of metadata\n"
                "  show-candidate nHeight      - Show candidata of reward at Height\n"
                "  scan-vote                   - Build list voted\n"
                "  scan-metadata               - Build/update list metadata\n"
                );

    UniValue obj(UniValue::VOBJ);

    if (strCommand == "keypair")
    {
        CKey secret;
        secret.MakeNewKey(true);
        CPubKey pubkey = secret.GetPubKey();
        assert(secret.VerifyPubKey(pubkey));

        std::string sBase64 = EncodeBase64(pubkey.begin(), pubkey.size());
        std::vector<unsigned char> tx_data = DecodeBase64(sBase64.c_str());
        CPubKey decodePubKey(tx_data.begin(), tx_data.end());

        obj.push_back(Pair("PrivateKey", EncodeSecret(secret)));
        obj.push_back(Pair("PublicKey", sBase64));
        obj.push_back(Pair("DecodePublicKey", decodePubKey.GetID().ToString()));
        obj.push_back(Pair("isCompressed", pubkey.IsCompressed()));


        return obj;
    }

    if (strCommand == "checkkey")
    {
        std::string strKey = request.params[1].get_str();
        CKey secret = DecodeSecret(strKey);
        if (!secret.IsValid()) throw JSONRPCError(RPC_INTERNAL_ERROR, "Not a valid key");

        CPubKey pubkey = secret.GetPubKey();
        assert(secret.VerifyPubKey(pubkey));

        std::string sBase64 = EncodeBase64(pubkey.begin(), pubkey.size());
        std::vector<unsigned char> tx_data = DecodeBase64(sBase64.c_str());
        CPubKey decodePubKey(tx_data.begin(), tx_data.end());

        obj.push_back(Pair("PrivateKey", EncodeSecret(secret)));
        obj.push_back(Pair("PublicKey", sBase64));
        obj.push_back(Pair("DecodePublicKey", decodePubKey.GetID().ToString()));
        obj.push_back(Pair("isCompressed", pubkey.IsCompressed()));

        return obj;
    }

    if (strCommand == "mypeerinfo")
    {
        if (!fInfinityNode)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "This is not an InfinityNode");

        UniValue infObj(UniValue::VOBJ);
        infinitynodePeer.ManageState(*g_connman);
        infObj.push_back(Pair("MyPeerInfo", infinitynodePeer.GetMyPeerInfo()));
        return infObj;
    }

    if (strCommand == "build-list")
    {
        CBlockIndex* pindex = NULL;
        {
                LOCK(cs_main);
                pindex = chainActive.Tip();
        }

        if (request.params.size() == 1)
            return infnodeman.buildInfinitynodeList(pindex->nHeight);

        std::string strMode = request.params[1].get_str();

        if (strMode == "lastscan")
            return infnodeman.getLastScan();
    }

    if (strCommand == "build-stm")
    {
            return infnodeman.deterministicRewardStatement(10) &&
                   infnodeman.deterministicRewardStatement(5) &&
                   infnodeman.deterministicRewardStatement(1);
    }

    if (strCommand == "show-stm")
    {
        return infnodeman.getLastStatementString();
    }

    if (strCommand == "show-candidate")
    {
        if (request.params.size() != 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'infinitynode show-candidate \"nHeight\"'");
        int nextHeight = 10;
        nextHeight = atoi(strFilter);

        if (nextHeight < Params().GetConsensus().nInfinityNodeGenesisStatement) {
            strError = strprintf("nHeight must be higher than the Genesis Statement height (%s)", Params().GetConsensus().nInfinityNodeGenesisStatement);
            throw JSONRPCError(RPC_INVALID_PARAMETER, strError);
        }

        CInfinitynode infBIG, infMID, infLIL;
        infnodeman.deterministicRewardAtHeight(nextHeight, 10, infBIG);
        infnodeman.deterministicRewardAtHeight(nextHeight, 5, infMID);
        infnodeman.deterministicRewardAtHeight(nextHeight, 1, infLIL);

        obj.push_back(Pair("Candidate BIG: ", infBIG.getCollateralAddress()));
        obj.push_back(Pair("Candidate MID: ", infMID.getCollateralAddress()));
        obj.push_back(Pair("Candidate LIL: ", infLIL.getCollateralAddress()));

        return obj;
    }

    if (strCommand == "show-lastscan")
    {
            return infnodeman.getLastScan();
    }

    if (strCommand == "show-lastpaid")
    {
        std::map<CScript, int>  mapLastPaid = infnodeman.GetFullLastPaidMap();
        for (auto& pair : mapLastPaid) {
            std::string scriptPublicKey = pair.first.ToString();
            obj.push_back(Pair(scriptPublicKey, pair.second));
        }
        return obj;
    }

    if (strCommand == "show-infos")
    {
        std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();
        for (auto& infpair : mapInfinitynodes) {
            std::string strOutpoint = infpair.first.ToStringShort();
            CInfinitynode inf = infpair.second;
                std::ostringstream streamInfo;
                streamInfo << std::setw(8) <<
                               inf.getCollateralAddress() << " " <<
                               inf.getHeight() << " " <<
                               inf.getExpireHeight() << " " <<
                               inf.getRoundBurnValue() << " " <<
                               inf.getSINType() << " " <<
                               inf.getBackupAddress() << " " <<
                               inf.getLastRewardHeight() << " " <<
                               inf.getRank() << " " << 
                               infnodeman.getLastStatementSize(inf.getSINType()) << " " <<
                               inf.getMetaID()
                               ;
                std::string strInfo = streamInfo.str();
                obj.push_back(Pair(strOutpoint, strInfo));
        }
        return obj;
    }

    if (strCommand == "show-script")
    {
        std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();
        for (auto& infpair : mapInfinitynodes) {
            std::string strOutpoint = infpair.first.ToStringShort();
            CInfinitynode inf = infpair.second;
                std::ostringstream streamInfo;
                        std::vector<std::vector<unsigned char>> vSolutions;
                        txnouttype whichType;
                        const CScript& prevScript = inf.getScriptPublicKey();
                        Solver(prevScript, whichType, vSolutions);
                        std::string backupAddresstmp(vSolutions[1].begin(), vSolutions[1].end());
                streamInfo << std::setw(8) <<
                               inf.getCollateralAddress() << " " <<
                               backupAddresstmp << " " <<
                               inf.getRoundBurnValue();
                std::string strInfo = streamInfo.str();
                obj.push_back(Pair(strOutpoint, strInfo));
        }
        return obj;
    }

    if (strCommand == "show-proposal")
    {
        if (request.params.size() < 2)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Correct usage is 'infinitynode show-proposal \"ProposalId\" \"(Optional)Mode\" '");

        std::string proposalId  = strFilter;
        std::vector<CVote>* vVote = infnodersv.Find(proposalId);
        obj.push_back(Pair("ProposalId", proposalId));
        if(vVote != NULL){
            obj.push_back(Pair("Votes", (int)vVote->size()));
        }else{
            obj.push_back(Pair("Votes", "0"));
        }
        int mode = 0;
        if (strOption == "public"){mode=0;}
        if (strOption == "node"){mode=1;}
        if (strOption == "all"){mode=2;}
        obj.push_back(Pair("Yes", infnodersv.getResult(proposalId, true, mode)));
        obj.push_back(Pair("No", infnodersv.getResult(proposalId, false, mode)));
        for (auto& v : *vVote){
            CTxDestination addressVoter;
            ExtractDestination(v.getVoter(), addressVoter);
            obj.push_back(Pair(EncodeDestination(addressVoter), v.getOpinion()));
        }
        return obj;
    }

    if (strCommand == "show-proposals")
    {
        std::map<std::string, std::vector<CVote>> mapCopy = infnodersv.GetFullProposalVotesMap();
        obj.push_back(Pair("Proposal", (int)mapCopy.size()));
        for (auto& infpair : mapCopy) {
            obj.push_back(Pair(infpair.first, (int)infpair.second.size()));
        }

        return obj;
    }

    if (strCommand == "show-metadata")
    {
        std::map<std::string, CMetadata>  mapCopy = infnodemeta.GetFullNodeMetadata();
        obj.push_back(Pair("Metadata", (int)mapCopy.size()));
        for (auto& infpair : mapCopy) {
            std::ostringstream streamInfo;
                streamInfo << std::setw(8) <<
                               infpair.second.getMetaPublicKey() << " " <<
                               infpair.second.getService().ToString() << " " <<
                               infpair.second.getMetadataHeight();
                std::string strInfo = streamInfo.str();
            obj.push_back(Pair(infpair.first, strInfo));
        }
        return obj;
    }

    if (strCommand == "scan-vote")
    {
        CBlockIndex* pindex = NULL;
        {
                LOCK(cs_main);
                pindex = chainActive.Tip();
        }

        bool result = infnodersv.rsvScan(pindex->nHeight);
        obj.push_back(Pair("Result", result));
        obj.push_back(Pair("Details", infnodersv.ToString()));
        return obj;
    }

    if (strCommand == "scan-metadata")
    {
        CBlockIndex* pindex = NULL;
        {
                LOCK(cs_main);
                pindex = chainActive.Tip();
        }

        bool result = infnodemeta.metaScan(pindex->nHeight);
        obj.push_back(Pair("Result", result));
        return obj;
    }
    return NullUniValue;
}

/**
 * @xtdevcoin
 * this function help user burn correctly their funds to run infinity node
 */
static UniValue infinitynodeburnfund(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 3)
       throw std::runtime_error(
            "infinitynodeburnfund NodeOwnerAddress amount SINBackupAddress"
            "\nSend an amount to BurnAddress.\n"
            "\nArguments:\n"
            "1. \"NodeOwnerAddress\" (string, required) Address of Collateral.\n"
            "2. \"amount\"             (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"NodeOwnerBackupAddress\"  (string, required) The SIN address to send to when you make a notification(new feature soon).\n"
            "\nResult:\n"
            "\"BURNtxid\"                  (string) The Burn transaction id. Need to run infinity node\n"
            "\"CollateralAddress\"         (string) Address of Collateral. Please send 10000 SIN to this address.\n"
            "\nExamples:\n"
            + HelpExampleCli("infinitynodeburnfund", "NodeOwnerAddress 1000000 SINBackupAddress")
        );

    if(!masternodeSync.IsMasternodeListSynced())
    {
        throw JSONRPCError(RPC_TYPE_ERROR, "Please wait until InfinityNode data is synced!");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::string strError;
    std::vector<COutput> vPossibleCoins;
    pwallet->AvailableCoins(vPossibleCoins, true, NULL, false, ALL_COINS);

    UniValue results(UniValue::VARR);
    // Amount

    CTxDestination NodeOwnerAddress = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(NodeOwnerAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SIN address for NodeOwnerAddress");

    CAmount nAmount = AmountFromValue(request.params[1]);
    if (nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN &&
        nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN &&
        nAmount != Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN)
    {
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount to burn and run an InfinityNode");
    }

    CTxDestination BKaddress = DecodeDestination(request.params[2].get_str());
    if (!IsValidDestination(BKaddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SIN address for Backup");

    std::map<COutPoint, CInfinitynode> mapInfinitynodes = infnodeman.GetFullInfinitynodeMap();
    int totalNode = 0, totalBIG = 0, totalMID = 0, totalLIL = 0, totalUnknown = 0;
    for (auto& infpair : mapInfinitynodes) {
        ++totalNode;
        CInfinitynode inf = infpair.second;
        int sintype = inf.getSINType();
        if (sintype == 10) ++totalBIG;
        else if (sintype == 5) ++totalMID;
        else if (sintype == 1) ++totalLIL;
        else ++totalUnknown;
    }

    // BurnAddress
    CTxDestination dest = DecodeDestination(Params().GetConsensus().cBurnAddress);
    CScript scriptPubKeyBurnAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKeyBurnAddress, whichType, vSolutions))
        return false;
    CKeyID keyid = CKeyID(uint160(vSolutions[0]));

    // Wallet comments
    std::set<CTxDestination> destinations;
    LOCK(pwallet->cs_wallet);
    for (COutput& out : vPossibleCoins) {
        CTxDestination address;
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (!fValidAddress || address != NodeOwnerAddress)
            continue;

        UniValue entry(UniValue::VOBJ);
        entry.pushKV("txid", out.tx->GetHash().GetHex());
        entry.pushKV("vout", out.i);

        if (fValidAddress) {
            entry.pushKV("address", EncodeDestination(address));

            auto i = pwallet->mapAddressBook.find(address);
            if (i != pwallet->mapAddressBook.end()) {
                entry.pushKV("label", i->second.name);
                if (IsDeprecatedRPCEnabled("accounts")) {
                    entry.pushKV("account", i->second.name);
                }
            }

            if (scriptPubKey.IsPayToScriptHash()) {
                const CScriptID& hash = boost::get<CScriptID>(address);
                CScript redeemScript;
                if (pwallet->GetCScript(hash, redeemScript)) {
                    entry.pushKV("redeemScript", HexStr(redeemScript.begin(), redeemScript.end()));
                }
            }
        }

        entry.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));
        entry.pushKV("amount", ValueFromAmount(out.tx->tx->vout[out.i].nValue));
        entry.pushKV("spendable", out.fSpendable);
        entry.pushKV("solvable", out.fSolvable);
        entry.pushKV("safe", out.fSafe);
        if (out.tx->tx->vout[out.i].nValue >= nAmount && out.nDepth >= 2) {
            /*check address is unique*/
            for (auto& infpair : mapInfinitynodes) {
                CInfinitynode inf = infpair.second;
                if(inf.getCollateralAddress() == EncodeDestination(address)){
                    strError = strprintf("Error: Address %s exist in list. Please use another address to make sure it is unique.", EncodeDestination(address));
                    throw JSONRPCError(RPC_TYPE_ERROR, strError);
                }
            }
            // Wallet comments
            mapValue_t mapValue;
            bool fSubtractFeeFromAmount = true;
            bool fUseInstantSend=false;
            CCoinControl coin_control;
            coin_control.Select(COutPoint(out.tx->GetHash(), out.i));
            coin_control.destChange = NodeOwnerAddress;//fund go back to NodeOwnerAddress

            CScript script;
            script = GetScriptForBurn(keyid, request.params[1].get_str());

            CReserveKey reservekey(pwallet);
            CAmount nFeeRequired;
            CAmount curBalance = pwallet->GetBalance();
            
            std::vector<CRecipient> vecSend;
            int nChangePosRet = -1;
            CRecipient recipient = {script, nAmount, fSubtractFeeFromAmount};
            vecSend.push_back(recipient);
            CTransactionRef tx;
            if (!pwallet->CreateTransaction(vecSend, tx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control, true, ALL_COINS, fUseInstantSend)) {
                if (!fSubtractFeeFromAmount && nAmount + nFeeRequired > curBalance)
                    strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
                throw JSONRPCError(RPC_WALLET_ERROR, strError);
            }
            CValidationState state;
            if (!pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */, {}/*fromAccount*/, reservekey, g_connman.get(),
                            state, fUseInstantSend ? NetMsgType::TXLOCKREQUEST : NetMsgType::TX)) {
                strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
                throw JSONRPCError(RPC_WALLET_ERROR, strError);
            }
            entry.pushKV("BURNADDRESS", EncodeDestination(dest));
            entry.pushKV("BURNPUBLICKEY", HexStr(keyid.begin(), keyid.end()));
            entry.pushKV("BURNSCRIPT", HexStr(scriptPubKeyBurnAddress.begin(), scriptPubKeyBurnAddress.end()));
            entry.pushKV("BURNTX", tx->GetHash().GetHex());
            entry.pushKV("OWNER_ADDRESS",EncodeDestination(address));
            entry.pushKV("BACKUP_ADDRESS",EncodeDestination(BKaddress));
            //coins is good to burn
            results.push_back(entry);
            break; //immediat
        }
    }
    return results;
}


static UniValue infinitynodeupdatemeta(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 4)
       throw std::runtime_error(
            "infinitynodeupdatemeta INFAddress UpdateInfo"
            "\nSend update info.\n"
            "\nArguments:\n"
            "1. \"OwnerAddress\"      (string, required) Address of node OWNER which funds are burnt.\n"
            "2. \"PublicKey\"         (string, required) PublicKey of node which will be used for LockReward, FlashSend...\n"
            "3. \"IP\"                (string, required) IP of node.\n"
            "4. \"NodeBurnFundTx\"    (string, required) 16 characters.\n"
            "\nResult:\n"
            "\"UpdateInfo upadted message\"   (string) Metadata information\n"
            "\nExamples:\n"
            + HelpExampleCli("infinitynodeupdatemeta", "OwnerAddress NodeAddress IP")
        );
    UniValue results(UniValue::VOBJ);

    std::string strOwnerAddress = request.params[0].get_str();
    CTxDestination INFAddress = DecodeDestination(strOwnerAddress);
    if (!IsValidDestination(INFAddress)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SIN address: OwnerAddress");
    }

    //limit data carrier, so we accept only 66 char
    std::string nodePublickeyHexStr = "";
    if(request.params[1].get_str().length() == 44){
        nodePublickeyHexStr = request.params[1].get_str();
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid node publickey");
    }

    std::string strService = request.params[2].get_str();
    CService service;
    if (!Lookup(strService.c_str(), service, 0, false)){
           throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "IP address is not valide");
    }

    std::string burnfundTxID = "";
    if(request.params[3].get_str().length() == 16){
        burnfundTxID = request.params[3].get_str();
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "node BurnFundTx ID is invalid. Please enter first 16 characters of BurnFundTx");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::string strError;
    std::vector<COutput> vPossibleCoins;
    pwallet->AvailableCoins(vPossibleCoins, true, NULL, false, ALL_COINS);

    // cMetadataAddress
    CTxDestination dest = DecodeDestination(Params().GetConsensus().cMetadataAddress);
    CScript scriptPubKeyMetaAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKeyMetaAddress, whichType, vSolutions))
            return false;
    CKeyID keyid = CKeyID(uint160(vSolutions[0]));

    std::ostringstream streamInfo;

    for (COutput& out : vPossibleCoins) {
        CTxDestination address;
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (!fValidAddress) continue;
        if (EncodeDestination(INFAddress) != EncodeDestination(address)) continue;
        //use coin with limit value
        if (out.tx->tx->vout[out.i].nValue / COIN >= Params().GetConsensus().nInfinityNodeUpdateMeta
            && out.tx->tx->vout[out.i].nValue / COIN < Params().GetConsensus().nInfinityNodeUpdateMeta*100
            && out.nDepth >= 2) {
            CAmount nAmount = Params().GetConsensus().nInfinityNodeUpdateMeta*COIN;
            mapValue_t mapValue;
            bool fSubtractFeeFromAmount = true;
            bool fUseInstantSend=false;
            CCoinControl coin_control;
            coin_control.Select(COutPoint(out.tx->GetHash(), out.i));
            coin_control.destChange = INFAddress;

            streamInfo << nodePublickeyHexStr << ";" << strService << ";" << burnfundTxID;
            std::string strInfo = streamInfo.str();
            CScript script;
            script = GetScriptForBurn(keyid, streamInfo.str());

            CReserveKey reservekey(pwallet);
            CAmount nFeeRequired;
            CAmount curBalance = pwallet->GetBalance();
            
            std::vector<CRecipient> vecSend;
            int nChangePosRet = -1;
            CRecipient recipient = {script, nAmount, fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            results.push_back(Pair("Metadata",streamInfo.str()));


            CTransactionRef tx;
            if (!pwallet->CreateTransaction(vecSend, tx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control, true, ALL_COINS, fUseInstantSend)) {
                if (!fSubtractFeeFromAmount && nAmount + nFeeRequired > curBalance)
                    strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
                throw JSONRPCError(RPC_WALLET_ERROR, strError);
            }
            CValidationState state;

            if (!pwallet->CommitTransaction(tx, std::move(mapValue), {}, {}, reservekey, g_connman.get(),
                            state, fUseInstantSend ? NetMsgType::TXLOCKREQUEST : NetMsgType::TX)) {
                strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
                throw JSONRPCError(RPC_WALLET_ERROR, strError);
            }

            break; //immediat
        }
    }

    return results;
}


static UniValue infinitynodevote(const JSONRPCRequest& request)
{
    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    if (request.fHelp || request.params.size() != 3)
       throw std::runtime_error(
            "infinitynodevote AddressVote ProposalId [yes/no]"
            "\nSend update info.\n"
            "\nArguments:\n"
            "1. \"AddressVote\"  (string, required) Address of vote.\n"
            "2. \"ProposalId\"   (string, required) Vote for proposalId\n"
            "3. \"[yes/no]\"            (string, required) opinion.\n"
            "\nResult:\n"
            "\"Vote information\"   (string) result of vote\n"
            "\nExamples:\n"
            + HelpExampleCli("infinitynodevote", "AddressVote ProposalId [yes/no]")
        );
    UniValue results(UniValue::VOBJ);
    std::string strError = "";

    std::string strOwnerAddress = request.params[0].get_str();
    CTxDestination INFAddress = DecodeDestination(strOwnerAddress);
    if (!IsValidDestination(INFAddress)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid SIN address: OwnerAddress");
    }

    std::string ProposalId = request.params[1].get_str();
    bool has_only_digits = (ProposalId.find_first_not_of( "0123456789" ) == string::npos);
    //if (!has_only_digits || ProposalId.size() != 8){
    if (!has_only_digits || ProposalId != "10000000"){//it will be update at hardfork
        strError = strprintf("ProposalID %s must be in format xxxxxxxx (8 digits) number.", ProposalId);
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strError);
    }

    std::string opinion = request.params[2].get_str();
    transform(opinion.begin(), opinion.end(), opinion.begin(), ::toupper);
    std::string vote = "0";
    if (opinion != "YES" && opinion != "NO"){
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Please give your opinion yes or no.");
    }
    if (opinion == "YES") {vote = "1";}

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    std::vector<COutput> vPossibleCoins;
    pwallet->AvailableCoins(vPossibleCoins, true, NULL, false, ALL_COINS);

    // cBurnAddress
    CTxDestination dest = DecodeDestination(Params().GetConsensus().cGovernanceAddress);
    CScript scriptPubKeyBurnAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKeyBurnAddress, whichType, vSolutions))
        return false;
    CKeyID keyid = CKeyID(uint160(vSolutions[0]));

    std::ostringstream streamInfo;

    for (COutput& out : vPossibleCoins) {
        CTxDestination address;
        const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
        bool fValidAddress = ExtractDestination(scriptPubKey, address);

        if (!fValidAddress) continue;
        if (EncodeDestination(INFAddress) != EncodeDestination(address)) continue;
        //use coin with limit value 10k SIN
        if (out.tx->tx->vout[out.i].nValue / COIN >= Params().GetConsensus().nInfinityNodeVoteValue
            && out.tx->tx->vout[out.i].nValue / COIN < Params().GetConsensus().nInfinityNodeVoteValue*1000
            && out.nDepth >= 2) {
            CAmount nAmount = Params().GetConsensus().nInfinityNodeVoteValue*COIN;
            mapValue_t mapValue;
            bool fSubtractFeeFromAmount = false;
            bool fUseInstantSend=false;
            CCoinControl coin_control;
            coin_control.Select(COutPoint(out.tx->GetHash(), out.i));
            coin_control.destChange = INFAddress;

            streamInfo << ProposalId << vote;
            std::string strInfo = streamInfo.str();
            CScript script;
            script = GetScriptForBurn(keyid, streamInfo.str());

            CReserveKey reservekey(pwallet);
            CAmount nFeeRequired;
            CAmount curBalance = pwallet->GetBalance();

            std::vector<CRecipient> vecSend;
            int nChangePosRet = -1;
            CRecipient recipient = {script, nAmount, fSubtractFeeFromAmount};
            vecSend.push_back(recipient);

            results.push_back(Pair("Vote",streamInfo.str()));

            CTransactionRef tx;
            if (!pwallet->CreateTransaction(vecSend, tx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control, true, ALL_COINS, fUseInstantSend)) {
                if (!fSubtractFeeFromAmount && nAmount + nFeeRequired > curBalance)
                    strError = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
                throw JSONRPCError(RPC_WALLET_ERROR, strError);
            }
            CValidationState state;

            if (!pwallet->CommitTransaction(tx, std::move(mapValue), {}, {}, reservekey, g_connman.get(),
                            state, fUseInstantSend ? NetMsgType::TXLOCKREQUEST : NetMsgType::TX)) {
                strError = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
                throw JSONRPCError(RPC_WALLET_ERROR, strError);
            }

            break; //immediat
        }
    }

    return results;
}

UniValue mnsetup(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1)
        throw std::runtime_error(
            "mnsetup <vps-ip>\n"
            "\nAutomatically configure masternode.");

    std::string vpsip;
    if (request.params.size() >= 1) {
        vpsip = request.params[0].get_str();
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    std::shared_ptr<CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    CWallet* const pwallet = wallet.get();

    // generate masternode key
    CKey secret;
    secret.MakeNewKey(false);

    // find suitable collateral outputs
    std::vector<COutput> vPossibleCoins;
    LOCK2(cs_main, pwallet->cs_wallet);
    pwallet->AvailableCoins(vPossibleCoins, true, NULL, false, ONLY_MASTERNODE_COLLATERAL);

    int nCollatVout;
    char nCollatHash[65];
    bool foundCollat = false;
    for (COutput& out : vPossibleCoins) {
      if (!foundCollat) {
        strcpy(nCollatHash, out.tx->GetHash().ToString().c_str());
        nCollatVout = out.i;
        foundCollat = true;
      }
    }

    // find suitable burntx
    int burnVout;
    char burnTxid[65];
    bool foundBurn = false;

    for (map<uint256, CWalletTx>::const_iterator it = pwallet->mapWallet.begin(); it != pwallet->mapWallet.end(); ++it) {
      const uint256* txid = &(*it).first;
      const CWalletTx* pcoin = &(*it).second;
      for (unsigned int i = 0; i < pcoin->tx->vout.size(); i++) {
        if ((strstr(pcoin->tx->vout[i].scriptPubKey.ToString().c_str(),Params().GetConsensus().cBurnAddressPubKey)!=NULL) &&
          (pcoin->tx->vout[i].nValue == Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN ||
           pcoin->tx->vout[i].nValue == Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN ||
           pcoin->tx->vout[i].nValue == Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN)) {
           if (!foundBurn) {
             strcpy(burnTxid, txid->ToString().c_str());
             burnVout = i;
             foundBurn = true;
           }
        }
      }
    }

    if (foundCollat && foundBurn) {

       char mnconfig[224];
       memset(mnconfig,'\0',224);
       sprintf(mnconfig,"mn01 %s:%d %s %s %d %s %d\n", vpsip.c_str(), Params().GetDefaultPort(), EncodeSecret(secret).c_str(), nCollatHash, nCollatVout, burnTxid, burnVout);

       // parts taken from phore's masternode tool (https://github.com/phoreproject/Phore/pull/128)
       boost::filesystem::path pathMasternodeConfigFile = GetMasternodeConfigFile();
       boost::filesystem::ifstream streamConfig(pathMasternodeConfigFile);
       FILE* configFile = fopen(pathMasternodeConfigFile.string().c_str(), "w");
       std::string strHeader = "# Masternode config file\n"
                               "# Format: alias IP:port masternodeprivkey collateral_output_txid collateral_output_index burnfund_output_txid burnfund_output_index\n"
                               "# mn01 127.0.0.1:20980 7RVuQhi45vfazyVtskTRLBgNuSrYGecS5zj2xERaooFVnWKKjhS b7ed8c1396cf57ac78d756186b6022d3023fd2f1c338b7fbae42d342fdd7070a 0 563d9434e816b3e8ffc5347c6b8db07509de6068f6759f21a16be5d92b7e3111 1\n";
       fwrite(strHeader.c_str(), std::strlen(strHeader.c_str()), 1, configFile);
       fwrite(mnconfig, strlen(mnconfig), 1, configFile);
       fclose(configFile);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////////

    return "AUTOMNSETUP.";
}

// Dash
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "SIN",                "masternode",             &masternode,             {"command"}  },
    { "dash",               "masternodelist",         &masternodelist,         {"mode", "filter"}  },
    { "dash",               "masternodebroadcast",    &masternodebroadcast,    {"command"}  },
    { "SIN",                "mnsetup",                &mnsetup,                {}  },
    { "SIN",                "infinitynodeburnfund",   &infinitynodeburnfund,   {"amount"} },
    { "SIN",                "infinitynodeupdatemeta", &infinitynodeupdatemeta, {"owner_address","node_address","IP"} },
    { "SIN",                "infinitynode",           &infinitynode,           {"command"}  },
    { "SIN",                "infinitynodevote",       &infinitynodevote,       {"owner_address","proposalid","opinion"} }
};

void RegisterDashMasternodeRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
//
