// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <infinitynodeman.h>
#include <infinitynodersv.h>
#include <infinitynodemeta.h>

#include <util/system.h> //fMasterNode variable
#include <chainparams.h>
#include <key_io.h>
#include <script/standard.h>
#include <flat-database.h>
#include <util/strencodings.h>
#include <netbase.h>


CInfinitynodeMan infnodeman;

const std::string CInfinitynodeMan::SERIALIZATION_VERSION_STRING = "CInfinitynodeMan-Version-1";

struct CompareIntValue
{
    bool operator()(const std::pair<int, CInfinitynode*>& t1,
                    const std::pair<int, CInfinitynode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vinBurnFund < t2.second->vinBurnFund);
    }
};

struct CompareUnit256Value
{
    bool operator()(const std::pair<arith_uint256, CInfinitynode*>& t1,
                    const std::pair<arith_uint256, CInfinitynode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vinBurnFund < t2.second->vinBurnFund);
    }
};

struct CompareNodeScore
{
    bool operator()(const std::pair<arith_uint256, CInfinitynode*>& t1,
                    const std::pair<arith_uint256, CInfinitynode*>& t2) const
    {
        return (t1.first != t2.first) ? (t1.first < t2.first) : (t1.second->vinBurnFund < t2.second->vinBurnFund);
    }
};

CInfinitynodeMan::CInfinitynodeMan()
: cs(),
  mapInfinitynodes(),
  nLastScanHeight(0)
{}

void CInfinitynodeMan::Clear()
{
    LOCK(cs);
    mapInfinitynodes.clear();
    mapLastPaid.clear();
    nLastScanHeight = 0;
}

bool CInfinitynodeMan::Add(CInfinitynode &inf)
{
    LOCK(cs);
    if (Has(inf.vinBurnFund.prevout)) return false;
    mapInfinitynodes[inf.vinBurnFund.prevout] = inf;
    return true;
}

bool CInfinitynodeMan::AddUpdateLastPaid(CScript scriptPubKey, int nHeightLastPaid)
{
    LOCK(cs_LastPaid);
    auto it = mapLastPaid.find(scriptPubKey);
    if (it != mapLastPaid.end()) {
        if (mapLastPaid[scriptPubKey] < nHeightLastPaid) {
            mapLastPaid[scriptPubKey] = nHeightLastPaid;
        }
        return true;
    }
    mapLastPaid[scriptPubKey] = nHeightLastPaid;
    return true;
}

CInfinitynode* CInfinitynodeMan::Find(const COutPoint &outpoint)
{
    LOCK(cs);
    auto it = mapInfinitynodes.find(outpoint);
    return it == mapInfinitynodes.end() ? NULL : &(it->second);
}

bool CInfinitynodeMan::Get(const COutPoint& outpoint, CInfinitynode& infinitynodeRet)
{
    // Theses mutexes are recursive so double locking by the same thread is safe.
    LOCK(cs);
    auto it = mapInfinitynodes.find(outpoint);
    if (it == mapInfinitynodes.end()) {
        return false;
    }

    infinitynodeRet = it->second;
    return true;
}

bool CInfinitynodeMan::Has(const COutPoint& outpoint)
{
    LOCK(cs);
    return mapInfinitynodes.find(outpoint) != mapInfinitynodes.end();
}

bool CInfinitynodeMan::HasPayee(CScript scriptPubKey)
{
    LOCK(cs_LastPaid);
    return mapLastPaid.find(scriptPubKey) != mapLastPaid.end();
}

int CInfinitynodeMan::Count()
{
    LOCK(cs);
    return mapInfinitynodes.size();
}

std::string CInfinitynodeMan::ToString() const
{
    std::ostringstream info;

    info << "InfinityNode: " << (int)mapInfinitynodes.size() <<
            ", nLastScanHeight: " << (int)nLastScanHeight;

    return info.str();
}

void CInfinitynodeMan::CheckAndRemove(CConnman& connman)
{
    /*this function is called in InfinityNode thread and after sync of node*/
    LOCK2(cs, cs_main); //Make sure we also lock main

    LogPrintf("CInfinitynodeMan::CheckAndRemove -- at Height: %d, last build height: %d nodes\n", nCachedBlockHeight, nLastScanHeight);
    //first scan -- normaly, list is built in init.cpp
    if (nLastScanHeight == 0 && nCachedBlockHeight > Params().GetConsensus().nInfinityNodeBeginHeight) {
        buildInfinitynodeList(nCachedBlockHeight, Params().GetConsensus().nInfinityNodeBeginHeight);
        return;
    }

    //2nd scan and loop
    if (nCachedBlockHeight > nLastScanHeight && nLastScanHeight > 0)
    {
        LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::CheckAndRemove -- block height %d and lastScan %d\n", 
                   nCachedBlockHeight, nLastScanHeight);
        buildInfinitynodeList(nCachedBlockHeight, nLastScanHeight);
    }

    if (nBIGLastStmHeight + nBIGLastStmSize - nCachedBlockHeight < INF_MATURED_LIMIT){
        deterministicRewardStatement(10);
    }
    if (nMIDLastStmHeight + nMIDLastStmSize - nCachedBlockHeight < INF_MATURED_LIMIT){
        deterministicRewardStatement(5);
    }
    if (nLILLastStmHeight + nLILLastStmSize - nCachedBlockHeight < INF_MATURED_LIMIT){
        deterministicRewardStatement(1);
    }

    return;
}

int CInfinitynodeMan::getRoi(int nSinType, int totalNode)
{
     LOCK(cs);
     int nBurnAmount = 0;
     if (nSinType == 10) nBurnAmount = Params().GetConsensus().nMasternodeBurnSINNODE_10;
     if (nSinType == 5) nBurnAmount = Params().GetConsensus().nMasternodeBurnSINNODE_5;
     if (nSinType == 1) nBurnAmount = Params().GetConsensus().nMasternodeBurnSINNODE_1;

     float nReward = GetMasternodePayment(nCachedBlockHeight, nSinType) / COIN;
     float roi = nBurnAmount / ((720 / (float)totalNode) * nReward) ;
     return (int) roi;
}

bool CInfinitynodeMan::initialInfinitynodeList(int nBlockHeight)
{
    LOCK2(cs, cs_main); //Make sure we also lock main
    if(nBlockHeight < Params().GetConsensus().nInfinityNodeBeginHeight) return false;
    LogPrintf("CInfinitynodeMan::initialInfinitynodeList -- initial at height: %d, last scan height: %d\n", nBlockHeight, nLastScanHeight);
    return buildInfinitynodeList(nBlockHeight, Params().GetConsensus().nInfinityNodeBeginHeight);
}

bool CInfinitynodeMan::updateInfinitynodeList(int nBlockHeight)
{
    LOCK2(cs, cs_main); //Make sure we also lock main
    if (nLastScanHeight == 0) {
        LogPrintf("CInfinitynodeMan::updateInfinitynodeList -- update list for 1st scan at Height %d\n",nBlockHeight); 
        return buildInfinitynodeList(nBlockHeight, Params().GetConsensus().nInfinityNodeBeginHeight);
    }
    if(nBlockHeight < nLastScanHeight) return false;
    return buildInfinitynodeList(nBlockHeight, nLastScanHeight);
}

bool CInfinitynodeMan::buildInfinitynodeList(int nBlockHeight, int nLowHeight)
{
    if(nBlockHeight < Params().GetConsensus().nInfinityNodeBeginHeight){
        Clear();
        infnodersv.Clear();
        return true;
    }
    AssertLockHeld(cs);
    AssertLockHeld(cs_main); //Needed for index-dependent parts
    mapInfinitynodesNonMatured.clear();

    //first run, make sure that all variable is clear
    if (nLowHeight == Params().GetConsensus().nInfinityNodeBeginHeight){
        Clear();
        infnodersv.Clear();
        //first run in testnet, scan to block number 1
        if (Params().NetworkIDString() == CBaseChainParams::TESTNET) {nLowHeight = 1;}
    } else {
        nLowHeight = nLastScanHeight;
    }

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight)) {
        LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::buildInfinitynodeList -- can not read block hash\n");
        return false;
    }

    CBlockIndex* pindex;
    pindex = LookupBlockIndex(blockHash);
    CBlockIndex* prevBlockIndex = pindex;

    int nLastPaidScanDeepth = max(Params().GetConsensus().nLimitSINNODE_1, max(Params().GetConsensus().nLimitSINNODE_5, Params().GetConsensus().nLimitSINNODE_10));
    //at fork heigh, scan limit will change to 800 - each tier of SIN network will never go to this limit
    if (nBlockHeight >= 350000){nLastPaidScanDeepth=800;}
    //at begin of network
    if (nLastPaidScanDeepth > nBlockHeight) {nLastPaidScanDeepth = nBlockHeight - 1;}

    while (prevBlockIndex->nHeight >= nLowHeight)
    {
        CBlock blockReadFromDisk;
        if (ReadBlockFromDisk(blockReadFromDisk, prevBlockIndex, Params().GetConsensus()))
        {
            for (const CTransactionRef& tx : blockReadFromDisk.vtx) {
                //Not coinbase
                if (!tx->IsCoinBase()) {
                    for (unsigned int i = 0; i < tx->vout.size(); i++) {
                        const CTxOut& out = tx->vout[i];
                        std::vector<std::vector<unsigned char>> vSolutions;
                        txnouttype whichType;
                        const CScript& prevScript = out.scriptPubKey;
                        Solver(prevScript, whichType, vSolutions);
                        //Send to BurnAddress
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cBurnAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                            //Amount for InfnityNode
                            if (
                            ((Params().GetConsensus().nMasternodeBurnSINNODE_1 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN) ||
                            ((Params().GetConsensus().nMasternodeBurnSINNODE_5 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN) ||
                            ((Params().GetConsensus().nMasternodeBurnSINNODE_10 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN)
                            ) {
                                COutPoint outpoint(tx->GetHash(), i);
                                CInfinitynode inf(PROTOCOL_VERSION, outpoint);
                                inf.setHeight(prevBlockIndex->nHeight);
                                inf.setBurnValue(out.nValue);

                                if (vSolutions.size() == 2){
                                    std::string backupAddress(vSolutions[1].begin(), vSolutions[1].end());
                                    CTxDestination NodeAddress = DecodeDestination(backupAddress);
                                    if (IsValidDestination(NodeAddress)) {
                                        inf.setBackupAddress(backupAddress);
                                    }
                                }
                                //SINType
                                CAmount nBurnAmount = out.nValue / COIN + 1; //automaticaly round
                                inf.setSINType(nBurnAmount / 100000);
                                //Address payee: we known that there is only 1 input
                                const CTxIn& txin = tx->vin[0];
                                int index = txin.prevout.n;

                                CTransactionRef prevtx;
                                uint256 hashblock;
                                if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false)) {
                                    LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- PrevBurnFund tx is not in block.\n");
                                    return false;
                                }

                                CTxDestination addressBurnFund;
                                if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                    LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- False when extract payee from BurnFund tx.\n");
                                    return false;
                                }

                                inf.setCollateralAddress(EncodeDestination(addressBurnFund));
                                inf.setScriptPublicKey(prevtx->vout[index].scriptPubKey);

                                //we have all infos. Then add in map
                                if(prevBlockIndex->nHeight < pindex->nHeight - INF_MATURED_LIMIT) {
                                    //matured
                                    Add(inf);
                                } else {
                                    //non matured
                                    mapInfinitynodesNonMatured[inf.vinBurnFund.prevout] = inf;
                                }
                            }
                            //Amount for vote
                            if (out.nValue == Params().GetConsensus().nInfinityNodeVoteValue * COIN){
                                if (vSolutions.size() == 2){
                                    std::string voteOpinion(vSolutions[1].begin(), vSolutions[1].end());
                                    if(voteOpinion.length() == 9){
                                        std::string proposalID = voteOpinion.substr(0, 8);
                                        bool opinion = false;
                                        if( voteOpinion.substr(8, 1) == "1" ){opinion = true;}
                                        //Address payee: we known that there is only 1 input
                                        const CTxIn& txin = tx->vin[0];
                                        int index = txin.prevout.n;

                                        CTransactionRef prevtx;
                                        uint256 hashblock;
                                        if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false)) {
                                            LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- PrevBurnFund tx is not in block.\n");
                                            return false;
                                        }

                                        CTxDestination addressBurnFund;
                                        if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                            LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- False when extract payee from BurnFund tx.\n");
                                            return false;
                                        }

                                        CVote vote = CVote(proposalID, prevtx->vout[index].scriptPubKey, prevBlockIndex->nHeight, opinion);
                                        infnodersv.Add(vote);
                                    }
                                }
                            }
                        }
                        //Governance Vote Address
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cGovernanceAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                            //Amount for vote
                            if (out.nValue == Params().GetConsensus().nInfinityNodeVoteValue * COIN){
                                if (vSolutions.size() == 2){
                                    std::string voteOpinion(vSolutions[1].begin(), vSolutions[1].end());
                                    LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- Extract vote at height: %d.\n", prevBlockIndex->nHeight);
                                    if(voteOpinion.length() == 9){
                                        std::string proposalID = voteOpinion.substr(0, 8);
                                        bool opinion = false;
                                        if( voteOpinion.substr(8, 1) == "1" ){opinion = true;}
                                        //Address payee: we known that there is only 1 input
                                        const CTxIn& txin = tx->vin[0];
                                        int index = txin.prevout.n;

                                        CTransactionRef prevtx;
                                        uint256 hashblock;
                                        if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false)) {
                                            LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- PrevBurnFund tx is not in block.\n");
                                            return false;
                                        }
                                        CTxDestination addressBurnFund;
                                        if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                            LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- False when extract payee from BurnFund tx.\n");
                                            return false;
                                        }
                                        //we have all infos. Then add in map
                                        if(prevBlockIndex->nHeight < pindex->nHeight - INF_MATURED_LIMIT) {
                                            //matured
	                                        LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- Voter: %s, proposal: %s.\n", EncodeDestination(addressBurnFund), voteOpinion);
                                            CVote vote = CVote(proposalID, prevtx->vout[index].scriptPubKey, prevBlockIndex->nHeight, opinion);
                                            infnodersv.Add(vote);
                                        } else {
                                            //non matured
                                            LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- Non matured vote.\n");
                                        }
                                    }
                                }
                            }
                        }
                        //Amount to update Metadata
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cMetadataAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                            //Amount for UpdateMeta
                            if ( (Params().GetConsensus().nInfinityNodeUpdateMeta - 1) * COIN <= out.nValue
                                 && out.nValue <= (Params().GetConsensus().nInfinityNodeUpdateMeta) * COIN){
                                if (vSolutions.size() == 2){
                                    std::string metadata(vSolutions[1].begin(), vSolutions[1].end());
                                    string s;
                                    stringstream ss(metadata);
                                    int i=0;
                                    int check=0;
                                    std::string publicKeyString;
                                    CService service;
                                    std::string burnTxID;
                                    while (getline(ss, s,';')) {
                                        CTxDestination NodeAddress;
                                        //1st position: Node Address
                                        if (i==0) {
                                            publicKeyString = s;
                                            std::vector<unsigned char> tx_data = DecodeBase64(publicKeyString.c_str());
                                            CPubKey decodePubKey(tx_data.begin(), tx_data.end());
                                            if (decodePubKey.IsValid()) {check++;}
                                        }
                                        //2nd position: Node IP
                                        if (i==1 && Lookup(s.c_str(), service, 0, false)) {
                                            check++;
                                        }
                                        //3th position: 12 character from Infinitynode BurnTx
                                        if (i==2 && s.length() >= 16) {
                                            check++;
                                            burnTxID = s.substr(0, 16);
                                        }
                                        //Update node metadata if nHeight is bigger
                                        if (check == 3){
                                            //prevBlockIndex->nHeight
                                            const CTxIn& txin = tx->vin[0];
                                            int index = txin.prevout.n;

                                            CTransactionRef prevtx;
                                            uint256 hashblock;
                                            if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false)) {
                                                LogPrintf("CInfinitynodeMeta::metaScan -- PrevBurnFund tx is not in block.\n");
                                                return false;
                                            }

                                            CTxDestination addressBurnFund;
                                            if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                                LogPrintf("CInfinitynodeMeta::metaScan -- False when extract payee from BurnFund tx.\n");
                                                return false;
                                            }

                                            std::ostringstream streamInfo;
                                            streamInfo << EncodeDestination(addressBurnFund) << "-" << burnTxID;

                                            LogPrintf("CInfinitynodeMeta:: meta update: %s, %s, %s\n", 
                                                         streamInfo.str(), publicKeyString, service.ToString());
                                            int avtiveBK = 0;
                                            CMetadata meta = CMetadata(streamInfo.str(), publicKeyString, service, prevBlockIndex->nHeight, avtiveBK);
                                            infnodemeta.Add(meta);
                                        }
                                        i++;
                                    }
                                }
                            }
                        }
                        //Amount to Notification
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cNotifyAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                            //Amount for UpdateMeta
                            if ( (Params().GetConsensus().nInfinityNodeNotificationValue - 1) * COIN <= out.nValue
                                 && out.nValue <= (Params().GetConsensus().nInfinityNodeNotificationValue) * COIN){
                                if (vSolutions.size() == 2){
                                    std::string metadata(vSolutions[1].begin(), vSolutions[1].end());
                                    string s;
                                    stringstream ss(metadata);
                                    int i=0;
                                    int check=0;
                                    std::string burnTxID;
                                    while (getline(ss, s,';')) {
                                        //3th position: 12 character from Infinitynode BurnTx
                                        if (i==0 && s.length() >= 16) {
                                            check++;
                                            burnTxID = s.substr(0, 16);
                                        }
                                        if (check == 1){
                                            //Address payee: we known that there is only 1 input
                                            const CTxIn& txin = tx->vin[0];
                                            int index = txin.prevout.n;

                                            CTransactionRef prevtx;
                                            uint256 hashblock;
                                            if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false)) {
                                                LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- PrevBurnFund tx is not in block.\n");
                                                return false;
                                            }

                                            CTxDestination addressBurnFund;
                                            if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                                LogPrintf("CInfinitynodeMan::updateInfinityNodeInfo -- False when extract payee from BurnFund tx.\n");
                                                return false;
                                            }
                                            std::ostringstream streamInfo;
                                            streamInfo << EncodeDestination(addressBurnFund) << "-" << burnTxID;
                                            infnodemeta.setActiveBKAddress(streamInfo.str());
                                        }
                                    }
                                }
                            }//Amount for UpdateMeta
                        }
                    } //end loop for all output
                } else { //Coinbase tx => update mapLastPaid
                    if (prevBlockIndex->nHeight >= pindex->nHeight - nLastPaidScanDeepth){
                        //block payment value
                        CAmount nNodePaymentSINNODE_1 = GetMasternodePayment(prevBlockIndex->nHeight, 1);
                        CAmount nNodePaymentSINNODE_5 = GetMasternodePayment(prevBlockIndex->nHeight, 5);
                        CAmount nNodePaymentSINNODE_10 = GetMasternodePayment(prevBlockIndex->nHeight, 10);
                        //compare and update map
                        for (auto txout : blockReadFromDisk.vtx[0]->vout)
                        {
                            if (txout.nValue == nNodePaymentSINNODE_1 || txout.nValue == nNodePaymentSINNODE_5 ||
                                txout.nValue == nNodePaymentSINNODE_10)
                            {
                                AddUpdateLastPaid(txout.scriptPubKey, prevBlockIndex->nHeight);
                            }
                        }
                    }
                }
            }
        } else {
            LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::buildInfinitynodeList -- can not read block from disk\n");
            return false;
        }
        // continue with previous block
        prevBlockIndex = prevBlockIndex->pprev;
    }

    nLastScanHeight = nBlockHeight - INF_MATURED_LIMIT;
    updateLastPaid();

    fMapInfinitynodeUpdated = true;

    CFlatDB<CInfinitynodeMan> flatdb5("infinitynode.dat", "magicInfinityNodeCache");
    flatdb5.Dump(infnodeman);

    CFlatDB<CInfinitynodersv> flatdb6("infinitynodersv.dat", "magicInfinityRSV");
    flatdb6.Dump(infnodersv);

    CFlatDB<CInfinitynodeMeta> flatdb7("infinitynodemeta.dat", "magicInfinityMeta");
    flatdb7.Dump(infnodemeta);

    LogPrintf("CInfinitynodeMan::buildInfinitynodeList -- list infinity node was built from blockchain at Height: %s\n", nBlockHeight);
    return true;
}

bool CInfinitynodeMan::GetInfinitynodeInfo(std::string nodePublicKey, infinitynode_info_t& infInfoRet)
{
    CMetadata meta;
    if(!infnodemeta.Get(nodePublicKey, meta)){
        return false;
    }
    LOCK(cs);
    for (auto& infpair : mapInfinitynodes) {
        if (infpair.second.getMetaID() == meta.getMetaID()) {
            infInfoRet = infpair.second.GetInfo();
            return true;
        }
    }
    return false;
}

bool CInfinitynodeMan::GetInfinitynodeInfo(const COutPoint& outpoint, infinitynode_info_t& infInfoRet)
{
    LOCK(cs);
    auto it = mapInfinitynodes.find(outpoint);
    if (it == mapInfinitynodes.end()) {
        return false;
    }
    infInfoRet = it->second.GetInfo();
    return true;
}

void CInfinitynodeMan::updateLastPaid()
{
    AssertLockHeld(cs);

    if (mapInfinitynodes.empty())
        return;

    for (auto& infpair : mapInfinitynodes) {
        auto it = mapLastPaid.find(infpair.second.getScriptPublicKey());
        if (it != mapLastPaid.end()) {
            infpair.second.setLastRewardHeight(mapLastPaid[infpair.second.getScriptPublicKey()]);
        }
    }
}
/*TODO: optimisation this programme*/
bool CInfinitynodeMan::deterministicRewardStatement(int nSinType)
{
    int stm_height_temp = Params().GetConsensus().nInfinityNodeGenesisStatement;
    if (nSinType == 10) mapStatementBIG.clear();
    if (nSinType == 5) mapStatementMID.clear();
    if (nSinType == 1) mapStatementLIL.clear();

    LOCK(cs);
    while (stm_height_temp < nCachedBlockHeight)
    {
        int totalSinType = 0;
        for (auto& infpair : mapInfinitynodes) {
            if (infpair.second.getSINType() == nSinType && infpair.second.getHeight() < stm_height_temp && stm_height_temp <= infpair.second.getExpireHeight()){
                totalSinType = totalSinType + 1;
            }
        }

        //if no node of this type, increase to next height
        if (totalSinType == 0){stm_height_temp = stm_height_temp + 1;}

        if(nSinType == 10){mapStatementBIG[stm_height_temp] = totalSinType;}
        if(nSinType == 5){mapStatementMID[stm_height_temp] = totalSinType;}
        if(nSinType == 1){mapStatementLIL[stm_height_temp] = totalSinType;}
        //loop
        stm_height_temp = stm_height_temp + totalSinType;
        //we will out of loop this next step, but we can calculate the next STM now
        if(nCachedBlockHeight <=  stm_height_temp && stm_height_temp < nCachedBlockHeight + INF_MATURED_LIMIT){
            int totalSinTypeNextStm = 0;
            for (auto& infpair : mapInfinitynodes) {
                if (infpair.second.getSINType() == nSinType && infpair.second.getHeight() < stm_height_temp && stm_height_temp <= infpair.second.getExpireHeight()){
                    totalSinTypeNextStm = totalSinTypeNextStm + 1;
                }
            }
            if (nSinType == 10){mapStatementBIG[stm_height_temp] = totalSinTypeNextStm;}
            if (nSinType == 5){mapStatementMID[stm_height_temp] = totalSinTypeNextStm;}
            if (nSinType == 1){mapStatementLIL[stm_height_temp] = totalSinTypeNextStm;}
        }
    }
    return true;
}

std::pair<int, int> CInfinitynodeMan::getLastStatementBySinType(int nSinType)
{
    if (nSinType == 10) return std::make_pair(nBIGLastStmHeight, nBIGLastStmSize);
    else if (nSinType == 5) return std::make_pair(nMIDLastStmHeight, nMIDLastStmSize);
    else if (nSinType == 1) return std::make_pair(nLILLastStmHeight, nLILLastStmSize);
    else return std::make_pair(0, 0);
}

std::string CInfinitynodeMan::getLastStatementString() const
{
    std::ostringstream info;
    info << nCachedBlockHeight << " "
            << "BIG: [" << mapStatementBIG.size() << " / " << nBIGLastStmHeight << ":" << nBIGLastStmSize << "] - "
            << "MID: [" << mapStatementMID.size() << " / " << nMIDLastStmHeight << ":" << nMIDLastStmSize << "] - "
            << "LIL: [" << mapStatementLIL.size() << " / " << nLILLastStmHeight << ":" << nLILLastStmSize << "]";

    return info.str();
}

/**
* Rank = 0 when node is expired
* Rank > 0 node is not expired, order by nHeight and
*
* called in CheckAndRemove
*/
std::map<int, CInfinitynode> CInfinitynodeMan::calculInfinityNodeRank(int nBlockHeight, int nSinType, bool updateList, bool flagExtCall)
{
    if(!flagExtCall)  AssertLockHeld(cs);
    else LOCK(cs);

    std::vector<std::pair<int, CInfinitynode*> > vecCInfinitynodeHeight;
    std::map<int, CInfinitynode> retMapInfinityNodeRank;

    for (auto& infpair : mapInfinitynodes) {
        CInfinitynode inf = infpair.second;
        //reinitial Rank to 0 all nodes of nSinType
        if (inf.getSINType() == nSinType && updateList == true) infpair.second.setRank(0);
        //put valid node in vector
        if (inf.getSINType() == nSinType && inf.getExpireHeight() >= nBlockHeight && inf.getHeight() < nBlockHeight)
        {
            vecCInfinitynodeHeight.push_back(std::make_pair(inf.getHeight(), &infpair.second));
        }
    }

    // Sort them low to high
    sort(vecCInfinitynodeHeight.begin(), vecCInfinitynodeHeight.end(), CompareIntValue());
    //update Rank at nBlockHeight
    int rank=1;
    for (std::pair<int, CInfinitynode*>& s : vecCInfinitynodeHeight){
        auto it = mapInfinitynodes.find(s.second->vinBurnFund.prevout);
        if(updateList == true) it->second.setRank(rank);
        retMapInfinityNodeRank[rank] = *s.second;
        rank = rank + 1;
    }

    return retMapInfinityNodeRank;
}

/*
 * called in MN synced - just after download all last block
 */
void CInfinitynodeMan::calculAllInfinityNodesRankAtLastStm()
{
    LOCK(cs);
        calculInfinityNodeRank(nBIGLastStmHeight, 10, true);
        calculInfinityNodeRank(nMIDLastStmHeight, 5, true);
        calculInfinityNodeRank(nLILLastStmHeight, 1, true);
}

/*
 * @return 0 or nHeight of reward
 */
int CInfinitynodeMan::isPossibleForLockReward(std::string nodeOwner)
{
    LOCK(cs);

    CInfinitynode inf;
    bool found = false;
    for (auto& infpair : mapInfinitynodes) {
        if (infpair.second.collateralAddress == nodeOwner) {
            inf = infpair.second;
            found = true;
        }
    }

    //not candidate => false
    if(!found){
        LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- No, cannot find %s\n", nodeOwner);
        return 0;
    }
    else
    {
        int nNodeSINtype = inf.getSINType();
        int nLastStmBySINtype = 0;
        int nLastStmSizeBySINtype = 0;
        if (nNodeSINtype == 10) {nLastStmBySINtype = nBIGLastStmHeight; nLastStmSizeBySINtype = nBIGLastStmSize;}
        if (nNodeSINtype == 5) {nLastStmBySINtype = nMIDLastStmHeight; nLastStmSizeBySINtype = nMIDLastStmSize;}
        if (nNodeSINtype == 1) {nLastStmBySINtype = nLILLastStmHeight; nLastStmSizeBySINtype = nLILLastStmSize;}
        LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- info, SIN type: %d, Stm Height: %d, Stm size: %d, current Height: %d, node rank: %d\n",
             nNodeSINtype, nBIGLastStmHeight, nLastStmSizeBySINtype, nCachedBlockHeight, inf.getRank());
        //size of statement is not enough for call LockReward => false
        if(nLastStmSizeBySINtype <= Params().GetConsensus().nInfinityNodeCallLockRewardDeepth){
            LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- No, number node is not enough: %d, for SIN type: %d\n", nLastStmSizeBySINtype, nNodeSINtype);
            return 0;
        }
        else
        {
            //Case1: not receive reward in this Stm
            int nHeightReward = nLastStmBySINtype + inf.getRank() - 1;
            if(nCachedBlockHeight <= nHeightReward)
            {
                /*SIN TODO: use <= in next version and loop until N+5*/
                if((nHeightReward - nCachedBlockHeight) <= Params().GetConsensus().nInfinityNodeCallLockRewardDeepth){
                //if(nHeightReward == nCachedBlockHeight){
                    LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- Yes, Stm height: %d, reward height: %d, current height: %d\n", nLastStmBySINtype, nHeightReward, nCachedBlockHeight);
                    return nHeightReward;
                }
                else{
                    LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- No, Stm height: %d, reward height: %d, current height: %d\n", nLastStmBySINtype, nHeightReward, nCachedBlockHeight);
                    return 0;
                }
            }
            //Case2: received reward in this Stm
            else
            {
                //expired at end of this Stm => false
                if(inf.isRewardInNextStm(nLastStmBySINtype + nLastStmSizeBySINtype)){
                    LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- No, node expire in next STM: %d, expired height: %d\n", nLastStmBySINtype + nLastStmSizeBySINtype, inf.getExpireHeight());
                    return 0;
                }
                else
                {
                    //try to get rank for next Stm
                    int nextStmRank = 0;
                    std::map<int, CInfinitynode> mapInfinityNodeRank;
                    mapInfinityNodeRank = calculInfinityNodeRank(nLastStmBySINtype + nLastStmSizeBySINtype, nNodeSINtype, false);
                    for (std::pair<int, CInfinitynode> s : mapInfinityNodeRank){
                        if(s.second.getBurntxOutPoint() == inf.getBurntxOutPoint()){
                            nextStmRank = s.first;
                        }
                    }
                    int nHeightRewardNextStm = nLastStmBySINtype + nLastStmSizeBySINtype + nextStmRank - 1;
                    int call_temp = nHeightRewardNextStm - nCachedBlockHeight - Params().GetConsensus().nInfinityNodeCallLockRewardDeepth;
                    LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- call for LockReward in %d block, next STM reward height: %d, current height: %d, next rank: %d\n",
                                 call_temp, nHeightRewardNextStm, nCachedBlockHeight, nextStmRank);
                    /*SIN TODO: use <= in next version and loop until N+5*/
                    if((nHeightRewardNextStm - nCachedBlockHeight) <= Params().GetConsensus().nInfinityNodeCallLockRewardDeepth){
                        return nHeightRewardNextStm;
                    } else {
                        return 0;
                    }
                    //eturn (nHeightRewardNextStm - nCachedBlockHeight) <= Params().GetConsensus().nInfinityNodeCallLockRewardDeepth;
                    //return nHeightRewardNextStm == nCachedBlockHeight;
                }
            }
        }
    }
}


bool CInfinitynodeMan::deterministicRewardAtHeight(int nBlockHeight, int nSinType, CInfinitynode& infinitynodeRet)
{
    if(nBlockHeight < Params().GetConsensus().nInfinityNodeGenesisStatement) return false;
    //step1: copy mapStatement for nSinType
    std::map<int, int> mapStatementSinType = getStatementMap(nSinType);

    LOCK(cs);
    //step2: find last Statement for nBlockHeight;
    int nDelta = 1000; //big enough > number of 
    int lastStatement = 0;
    int lastStatementSize = 0;
    for(auto& stm : mapStatementSinType)
    {
        if (nBlockHeight == stm.first)
        {
                lastStatement = stm.first;
                lastStatementSize = stm.second;
        }
        if (nBlockHeight > stm.first && nDelta > (nBlockHeight -stm.first))
        {
            nDelta = nBlockHeight -stm.first;
            if(nDelta <= stm.second){
                lastStatement = stm.first;
                lastStatementSize = stm.second;
            }
        }
    }
    //return false if not found statement
    if (lastStatement == 0) return false;

    std::map<int, CInfinitynode> rankOfStatement = calculInfinityNodeRank(lastStatement, nSinType, false);
    if(rankOfStatement.empty()){
        LogPrintf("CInfinitynodeMan::deterministicRewardAtHeight -- can not calcul rank at %d\n", lastStatement);
        return false;
    }
    if((nBlockHeight < lastStatement) || (rankOfStatement.size() < (nBlockHeight - lastStatement + 1))){
        LogPrintf("CInfinitynodeMan::deterministicRewardAtHeight -- out of rang at %d\n", lastStatement);
        return false;
    }
    infinitynodeRet = rankOfStatement[nBlockHeight - lastStatement + 1];
    return true;
}

/*
 * update LastStm, Size and Rank of node if we are at switch Height
 */
void CInfinitynodeMan::updateLastStmHeightAndSize(int nBlockHeight, int nSinType)
{
    if(nBlockHeight < Params().GetConsensus().nInfinityNodeGenesisStatement) return;
    //step1: copy mapStatement for nSinType
    std::map<int, int> mapStatementSinType = getStatementMap(nSinType);

    LOCK(cs);
    //step2: find last Statement for nBlockHeight;
    int nDelta = 1000; //big enough > number of node by SIN type (Stm size). Delta is distant from Stm begin to last block
    int lastStatement = 0;
    int lastStatementSize = 0;
    for(auto& stm : mapStatementSinType)
    {
        if (nBlockHeight == stm.first)
        {
                LogPrintf("CInfinitynodeMan::isPossibleForLockReward -- SIN type: %d, switch to new Stm :%d at size: %d\n", nSinType, stm.first, stm.second);
                //we switch to new Stm ==> update rank
                lastStatement = stm.first;
                lastStatementSize = stm.second;
                calculInfinityNodeRank(nBlockHeight, nSinType, true);
        }
        if (nBlockHeight > stm.first && nDelta > (nBlockHeight -stm.first))
        {
            nDelta = nBlockHeight -stm.first;
            if(nDelta <= stm.second){
                lastStatement = stm.first;
                lastStatementSize = stm.second;
            }
        }
    }
    //return false if not found statement
    if (lastStatement == 0) return;

    if (nSinType == 10)
    {
        nBIGLastStmHeight = lastStatement;
        nBIGLastStmSize = lastStatementSize;
    }

    if (nSinType == 5)
    {
        nMIDLastStmHeight = lastStatement;
        nMIDLastStmSize = lastStatementSize;
    }

    if (nSinType == 1)
    {
        nLILLastStmHeight = lastStatement;
        nLILLastStmSize = lastStatementSize;
    }

}

bool CInfinitynodeMan::getScoreVector(const uint256& nBlockHash, int nSinType, int nBlockHeight, CInfinitynodeMan::score_pair_vec_t& vecScoresRet)
{
    vecScoresRet.clear();

    AssertLockHeld(cs);

    if (mapInfinitynodes.empty())
        return false;

    // calculate scores for SIN type 10
    for (auto& infpair : mapInfinitynodes) {
        CInfinitynode inf = infpair.second;
        if (inf.getSINType() == nSinType  && inf.getExpireHeight() >= nBlockHeight && inf.getHeight() < nBlockHeight) {
            vecScoresRet.push_back(std::make_pair(inf.CalculateScore(nBlockHash), &infpair.second));
        }
    }

    sort(vecScoresRet.rbegin(), vecScoresRet.rend(), CompareNodeScore());
    return !vecScoresRet.empty();
}

bool CInfinitynodeMan::getNodeScoreAtHeight(const COutPoint& outpoint, int nSinType, int nBlockHeight, int& nScoreRet)
{
    nScoreRet = -1;

    LOCK(cs);

    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrintf("CMasternodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    score_pair_vec_t vecScores;

    if (!getScoreVector(nBlockHash, nSinType, nBlockHeight, vecScores))
        return false;

    int nRank = 0;
    for (auto& scorePair : vecScores) {
        nRank++;
        if(scorePair.second->vinBurnFund.prevout == outpoint) {
            nScoreRet = nRank;
            return true;
        }
    }

    return false;
}

std::string CInfinitynodeMan::getVectorNodeRankAtHeight(const std::vector<COutPoint>  &vOutpoint, int nSinType, int nBlockHeight)
{
    std::string ret="";

    LOCK(cs);

    std::vector<std::pair<int, CInfinitynode*> > vecCInfinitynodeHeight;
    std::map<int, CInfinitynode> retMapInfinityNodeRank;

    for (auto& infpair : mapInfinitynodes) {
        CInfinitynode inf = infpair.second;
        //put valid node in vector
        if (inf.getSINType() == nSinType && inf.getExpireHeight() >= nBlockHeight && inf.getHeight() < nBlockHeight)
        {
            vecCInfinitynodeHeight.push_back(std::make_pair(inf.getHeight(), &infpair.second));
        }
    }

    // Sort them low to high
    sort(vecCInfinitynodeHeight.begin(), vecCInfinitynodeHeight.end(), CompareIntValue());
    //update Rank at nBlockHeight

    std::ostringstream streamInfo;
    for (const auto &outpoint : vOutpoint)
    {
        LogPrintf("CInfinityNodeLockReward::%s -- find rank for %s\n", __func__, outpoint.ToStringShort());
        int nRank = 1;
        for (std::pair<int, CInfinitynode*>& s : vecCInfinitynodeHeight){
            if(s.second->vinBurnFund.prevout == outpoint)
            {
                LogPrintf("CInfinityNodeLockReward::%s -- rank: %d\n", __func__, nRank);
                streamInfo << nRank << ";";
                break;
            }
            nRank++;
        }
    }

    ret = streamInfo.str();
    return ret;
}

void CInfinitynodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    nCachedBlockHeight = pindex->nHeight;
    updateLastStmHeightAndSize(nCachedBlockHeight, 10);
    updateLastStmHeightAndSize(nCachedBlockHeight, 5);
    updateLastStmHeightAndSize(nCachedBlockHeight, 1);
}
