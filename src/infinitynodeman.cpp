// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <infinitynodeman.h>
#include <infinitynodersv.h>
#include <infinitynodemeta.h>
#include <infinitynodepeer.h>

#include <util.h> //fMasterNode variable
#include <chainparams.h>
#include <key_io.h>
#include <script/standard.h>
#include <flat-database.h>
#include <utilstrencodings.h>
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
    mapInfinitynodesNonMatured.clear();
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

    CTxDestination addressBurnFund;
    ExtractDestination(scriptPubKey, addressBurnFund);
    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::AddUpdateLastPaid -- %s: %d\n", EncodeDestination(addressBurnFund), nHeightLastPaid);

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

int CInfinitynodeMan::CountEnabled()
{
    LOCK(cs);

    if (mapInfinitynodes.empty()) {
        return 0;
    }
    int i = 0;
    // calculate scores for SIN type 10
    for (auto& infpair : mapInfinitynodes) {
        CInfinitynode inf = infpair.second;
        if (inf.getExpireHeight() >= nLastScanHeight) {
            i++;
        }
    }
    return i;
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
    /*this function is called in InfinityNode thread*/
    LOCK(cs); //cs_main needs to be called by the parent function

    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::CheckAndRemove -- At Height: %d, last build height: %d nodes\n", nCachedBlockHeight, nLastScanHeight);

    if(nCachedBlockHeight == 0){
        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::CheckAndRemove -- Node is just retarted. Waiting for new block\n");
        return;
    }

    updateLastPaidList(nCachedBlockHeight, nCachedBlockHeight - Params().MaxReorganizationDepth());

    //optimisation memory
    std::map<CScript, int>::iterator itLP = mapLastPaid.begin();
    while(itLP != mapLastPaid.end()) {
        if (itLP->second < nCachedBlockHeight - Params().MaxReorganizationDepth() * 2) {
            mapLastPaid.erase(itLP++);
        } else {
            ++itLP;
        }
    }

    std::map<COutPoint, CInfinitynode>::iterator itNonMatured =  mapInfinitynodesNonMatured.begin();
    while(itNonMatured != mapInfinitynodesNonMatured.end()) {
        CInfinitynode inf = itNonMatured->second;
        if(inf.nHeight < nCachedBlockHeight - Params().MaxReorganizationDepth() * 2){
            mapInfinitynodesNonMatured.erase(itNonMatured++);
        } else {
            ++itNonMatured;
        }
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

//pindex->nHeight is a new block. But we build list only for matured block (sup than limit reorg)
bool CInfinitynodeMan::buildNonMaturedListFromBlock(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams)
{

    if (Params().NetworkIDString() == CBaseChainParams::MAIN) {
        if(pindex->nHeight < Params().GetConsensus().nInfinityNodeBeginHeight){
            mapInfinitynodesNonMatured.clear();
            return true;
        }
    } else {
        if (pindex->nHeight <= 1) {
            mapInfinitynodesNonMatured.clear();
        }
    }

    LOCK(cs);

    //update NON matured map
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction &tx = *(block.vtx[i]);
        //Not coinbase
        if (!tx.IsCoinBase()) {
                for (unsigned int i = 0; i < tx.vout.size(); i++) {
                        const CTxOut& out = tx.vout[i];
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
                                COutPoint outpoint(tx.GetHash(), i);
                                CInfinitynode inf(PROTOCOL_VERSION, outpoint);
                                inf.setHeight(pindex->nHeight);
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
                                const Coin& coin = view.AccessCoin(tx.vin[0].prevout);

                                CTxDestination addressBurnFund;
                                if(!ExtractDestination(coin.out.scriptPubKey, addressBurnFund)){
                                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateInfinityNodeInfo -- False when extract payee from BurnFund tx.\n");
                                    return false;
                                }

                                inf.setCollateralAddress(EncodeDestination(addressBurnFund));
                                inf.setScriptPublicKey(coin.out.scriptPubKey);

                                //we have all infos. Then add in mapNonMatured
                                if (mapInfinitynodesNonMatured.find(inf.vinBurnFund.prevout) != mapInfinitynodesNonMatured.end()) {
                                    //exist
                                    continue;
                                } else {
                                    //non existe
                                    mapInfinitynodesNonMatured[inf.vinBurnFund.prevout] = inf;
                                }
                            }
                        }
                        //Amount to update Metadata
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cMetadataAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                            //Amount for UpdateMeta
                            if ((Params().GetConsensus().nInfinityNodeUpdateMeta - 1) * COIN <= out.nValue && out.nValue <= (Params().GetConsensus().nInfinityNodeUpdateMeta) * COIN) {
                                if (vSolutions.size() == 2) {
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
                                        if (i==1) {
                                            if (Lookup(s.c_str(), service, 0, false, Params().NetworkIDString() == CBaseChainParams::REGTEST)) {
                                                check++;
                                            }
                                        }
                                        //3th position: 16 character from Infinitynode BurnTx
                                        if (i==2 && s.length() >= 16) {
                                            check++;
                                            burnTxID = s.substr(0, 16);
                                        }
                                        //Update node metadata if nHeight is bigger
                                        if (check == 3){
                                            //Address payee: we known that there is only 1 input
                                            const Coin& coin = view.AccessCoin(tx.vin[0].prevout);

                                            CTxDestination addressBurnFund;
                                            if(!ExtractDestination(coin.out.scriptPubKey, addressBurnFund)){
                                                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta::metaScan -- False when extract payee from BurnFund tx.\n");
                                                return false;
                                            }

                                            std::ostringstream streamInfo;
                                            streamInfo << EncodeDestination(addressBurnFund) << "-" << burnTxID;

                                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta:: meta update: %s, %s, %s\n", 
                                                         streamInfo.str(), publicKeyString, service.ToString());
                                            int avtiveBK = 0;
                                            CMetadata meta = CMetadata(streamInfo.str(), publicKeyString, service, pindex->nHeight, avtiveBK);
                                            infnodemeta.Add(meta);
                                        }
                                        i++;
                                    }
                                }
                            }
                        }
                }
        }
    }

    if(fReachedLastBlock){
        CFlatDB<CInfinitynodeMan> flatdb5("infinitynode.dat", "magicInfinityNodeCache");
        flatdb5.Dump(infnodeman);

        CFlatDB<CInfinitynodeMeta> flatdb7("infinitynodemeta.dat", "magicInfinityMeta");
        flatdb7.Dump(infnodemeta);
    }

    return true;
}

bool CInfinitynodeMan::updateFinalList(CBlockIndex* pindex)
{
    LOCK(cs);

    //move matured node to final list
    nLastScanHeight = pindex->nHeight - Params().MaxReorganizationDepth();

    for (auto& infpair : mapInfinitynodesNonMatured) {
        if(infpair.second.nHeight == nLastScanHeight) {
            CInfinitynode inf = infpair.second;
            Add(inf);
        }
    }

    nCachedBlockHeight = pindex->nHeight;

    bool updateStm = deterministicRewardStatement(10) && deterministicRewardStatement(5) && deterministicRewardStatement(1);

    if (updateStm){
                calculAllInfinityNodesRankAtLastStm();
                updateLastStmHeightAndSize(pindex->nHeight, 10);
                updateLastStmHeightAndSize(pindex->nHeight, 5);
                updateLastStmHeightAndSize(pindex->nHeight, 1);
                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::buildListFromBlock -- update Stm status: %d\n",updateStm);
    } else {
                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::buildListFromBlock -- update Stm false\n");
        return false;
    }
    return true;
}

bool CInfinitynodeMan::removeNonMaturedList(CBlockIndex* pindex)
{
    LOCK(cs);

    std::map<COutPoint, CInfinitynode>::iterator it =  mapInfinitynodesNonMatured.begin();
    while(it != mapInfinitynodesNonMatured.end()) {
        CInfinitynode inf = it->second;
        // Currently not used
        //COutPoint txOutPoint = it->first;
        if(inf.nHeight == pindex->nHeight){
            mapInfinitynodesNonMatured.erase(it++);
        } else {
            ++it;
        }
    }

    if(fReachedLastBlock){
        CFlatDB<CInfinitynodeMan> flatdb5("infinitynode.dat", "magicInfinityNodeCache");
        flatdb5.Dump(infnodeman);

        CFlatDB<CInfinitynodeMeta> flatdb7("infinitynodemeta.dat", "magicInfinityMeta");
        flatdb7.Dump(infnodemeta);
    }

    return true;
}

bool CInfinitynodeMan::buildInfinitynodeListFromGenesis(int nBlockHeight)
{
    Clear();
    infnodelrinfo.Clear();

    LOCK2(cs_main, cs);

    int nLowHeight = 1;

    while(nLowHeight <= nBlockHeight)
    {
        uint256 blockHash;
        if(!GetBlockHash(blockHash, nLowHeight)) {
            LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::buildInfinitynodeList -- can not get block hash at %d\n", nBlockHeight);
            return false;
        }

        CBlockIndex* pindex;
        pindex = LookupBlockIndex(blockHash);

        CBlock blockReadFromDisk;
        if (ReadBlockFromDisk(blockReadFromDisk, pindex, Params().GetConsensus()))
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
                                inf.setHeight(pindex->nHeight);
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
                                if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false, nullptr, false)) {
                                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateInfinityNodeInfo -- PrevBurnFund tx is not in block.\n");
                                    return false;
                                }

                                CTxDestination addressBurnFund;
                                if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateInfinityNodeInfo -- False when extract payee from BurnFund tx.\n");
                                    return false;
                                }

                                inf.setCollateralAddress(EncodeDestination(addressBurnFund));
                                inf.setScriptPublicKey(prevtx->vout[index].scriptPubKey);

                                //we have all infos. Then add in mapNonMatured
                                if (mapInfinitynodesNonMatured.find(inf.vinBurnFund.prevout) != mapInfinitynodesNonMatured.end()) {
                                    //exist
                                    continue;
                                } else {
                                    //non existe
                                    mapInfinitynodesNonMatured[inf.vinBurnFund.prevout] = inf;
                                }
                            }
                        }//end creation node

                        //Amount to update Metadata
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cMetadataAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                            //Amount for UpdateMeta
                            if ((Params().GetConsensus().nInfinityNodeUpdateMeta - 1) * COIN <= out.nValue && out.nValue <= (Params().GetConsensus().nInfinityNodeUpdateMeta) * COIN) {
                                if (vSolutions.size() == 2) {
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
                                        if (i==1) {
                                            if (Lookup(s.c_str(), service, 0, false, Params().NetworkIDString() == CBaseChainParams::REGTEST)) {
                                                check++;
                                            }
                                        }
                                        //3th position: 16 character from Infinitynode BurnTx
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
                                            if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false, nullptr, false)) {
                                                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta::metaScan -- PrevBurnFund tx is not in block.\n");
                                                return false;
                                            }

                                            CTxDestination addressBurnFund;
                                            if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta::metaScan -- False when extract payee from BurnFund tx.\n");
                                                return false;
                                            }

                                            std::ostringstream streamInfo;
                                            streamInfo << EncodeDestination(addressBurnFund) << "-" << burnTxID;

                                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta:: meta update: %s, %s, %s\n", 
                                                         streamInfo.str(), publicKeyString, service.ToString());
                                            int avtiveBK = 0;
                                            CMetadata meta = CMetadata(streamInfo.str(), publicKeyString, service, pindex->nHeight, avtiveBK);
                                            infnodemeta.Add(meta);
                                        }
                                        i++;
                                    }
                                }
                            }
                        }//end metadata

                        //LockReward
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cLockRewardAddress == EncodeDestination(CKeyID(uint160(vSolutions[0])))) {
                            if (vSolutions.size() != 2) {continue;}
                            std::string stringLRRegister(vSolutions[1].begin(), vSolutions[1].end());

                            std::string s;
                            stringstream ss(stringLRRegister);
                            //verify the height of registration info
                            int i=0;
                            int nRewardHeight = 0;
                            int nSINtype = 0;
                            std::string signature = "";
                            int *signerIndexes;
                            // Currently not used
                            //size_t N_SIGNERS = (size_t)Params().GetConsensus().nInfinityNodeLockRewardSigners;
                            int registerNbInfos = Params().GetConsensus().nInfinityNodeLockRewardSigners + 3;
                            signerIndexes = (int*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(int));

                            while (getline(ss, s,';')) {
                                if(i==0){nRewardHeight = atoi(s);}
                                if(i==1){nSINtype = atoi(s);}
                                if(i==2){signature = s;}
                                if(i>=3 && i < registerNbInfos){
                                    signerIndexes[i-3] = atoi(s);
                                }
                                i++;
                            }
                            free(signerIndexes);

                            //prevBlockIndex->nHeight
                            const CTxIn& txin = tx->vin[0];
                            int index = txin.prevout.n;

                            CTransactionRef prevtx;
                            uint256 hashblock;
                            if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false, nullptr, false)) {
                                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMeta::metaScan -- PrevBurnFund tx is not in block.\n");
                                return false;
                            }

                            //identify owner of tx
                            CLockRewardExtractInfo lrinfo(pindex->nHeight, nSINtype, nRewardHeight, prevtx->vout[index].scriptPubKey, stringLRRegister);
                            infnodelrinfo.Add(lrinfo);
                        }//end lockreward

                    } //end loop for all output
                } else { //Coinbase tx => update mapLastPaid

                }
            }
        } else {
            LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::buildInfinitynodeList -- can not read block from disk\n");
            return false;
        }

        //move matured node to final list
        nLastScanHeight = pindex->nHeight - Params().MaxReorganizationDepth();

        for (auto& infpair : mapInfinitynodesNonMatured) {
            if(infpair.second.nHeight == nLastScanHeight) {
                CInfinitynode inf = infpair.second;
                Add(inf);
            }
        }

        nCachedBlockHeight = pindex->nHeight;

        bool updateStm = deterministicRewardStatement(10) && deterministicRewardStatement(5) && deterministicRewardStatement(1);

        if (updateStm){
                calculAllInfinityNodesRankAtLastStm();
                updateLastStmHeightAndSize(pindex->nHeight, 10);
                updateLastStmHeightAndSize(pindex->nHeight, 5);
                updateLastStmHeightAndSize(pindex->nHeight, 1);
                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::buildListFromBlock -- update Stm status: %d\n",updateStm);
        } else {
                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::buildListFromBlock -- update Stm false\n");
            return false;
        }

        //next block
        nLowHeight = nLowHeight + 1;
    }
    return true;
}


bool CInfinitynodeMan::updateLastPaidList(int nBlockHeight, int nLowHeight)
{

    infnodersv.Clear();
    if (nLowHeight <= 0) nLowHeight = 1;

    LOCK2(cs_main, cs);
    LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::updateLastPaidList -- from %d to %d\n", nBlockHeight, nLowHeight);

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight)) {
        LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::updateLastPaidList -- can not get block hash at %d\n", nBlockHeight);
        return false;
    }

    CBlockIndex* pindex;
    pindex = LookupBlockIndex(blockHash);
    CBlockIndex* prevBlockIndex = pindex;

    int nLastPaidScanDeepth = max(Params().GetConsensus().nLimitSINNODE_1, max(Params().GetConsensus().nLimitSINNODE_5, Params().GetConsensus().nLimitSINNODE_10));
    //at fork heigh, scan limit will change to 800 - each tier of SIN network will never go to this limit
    if (nBlockHeight >= 350000) {
        nLastPaidScanDeepth = 800;
    }
    //at begin of network
    if (nLastPaidScanDeepth > nBlockHeight) {
        nLastPaidScanDeepth = nBlockHeight - 1;
    }

    //change nLowHeight to 1 ==> do full scan
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
                        //Governance Vote Address
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cGovernanceAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                            //Amount for vote
                            if (out.nValue == Params().GetConsensus().nInfinityNodeVoteValue * COIN){
                                if (vSolutions.size() == 2){
                                    std::string voteOpinion(vSolutions[1].begin(), vSolutions[1].end());
                                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastPaidList -- Extract vote at height: %d.\n", prevBlockIndex->nHeight);
                                    if(voteOpinion.length() == 9){
                                        std::string proposalID = voteOpinion.substr(0, 8);
                                        bool opinion = false;
                                        if( voteOpinion.substr(8, 1) == "1" ){opinion = true;}
                                        //Address payee: we known that there is only 1 input
                                        const CTxIn& txin = tx->vin[0];
                                        int index = txin.prevout.n;

                                        CTransactionRef prevtx;
                                        uint256 hashblock;
                                        if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false, nullptr, false)) {
                                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastPaidList -- PrevBurnFund tx is not in block.\n");
                                            return false;
                                        }
                                        CTxDestination addressBurnFund;
                                        if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastPaidList -- False when extract payee from BurnFund tx.\n");
                                            return false;
                                        }
                                        //we have all infos. Then add in map
                                        if(prevBlockIndex->nHeight < pindex->nHeight - Params().MaxReorganizationDepth()) {
                                            //matured
	                                        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastPaidList -- Voter: %s, proposal: %s.\n", EncodeDestination(addressBurnFund), voteOpinion);
                                            CVote vote = CVote(proposalID, prevtx->vout[index].scriptPubKey, prevBlockIndex->nHeight, opinion);
                                            infnodersv.Add(vote);
                                        } else {
                                            //non matured
                                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastPaidList -- Non matured vote.\n");
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else { //Coinbase tx => update mapLastPaid
                    if (prevBlockIndex->nHeight >= nLowHeight){
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
            LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::updateLastPaidList -- can not read block from disk\n");
            return false;
        }
        // continue with previous block
        prevBlockIndex = prevBlockIndex->pprev;
    }

    updateLastPaid();

    return true;
}

/*
 * LOCK (cs_main) before call this function
 */
bool CInfinitynodeMan::ExtractLockReward(int nBlockHeight, int depth, std::vector<CLockRewardExtractInfo>& vecLRRet)
{
    vecLRRet.clear();

    if(nBlockHeight < Params().GetConsensus().nInfinityNodeBeginHeight){
        return true;
    }

    AssertLockHeld(cs_main);

    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight)) {
        LogPrint(BCLog::INFINITYNODE, "CInfinityNodeLockReward::ExtractLockReward -- can not read block hash\n");
        return false;
    }

    CBlockIndex* pindex;
    pindex = LookupBlockIndex(blockHash);
    CBlockIndex* prevBlockIndex = pindex;

    //read back 55 blocks and find lockreward for height
    while (prevBlockIndex->nHeight >= (nBlockHeight - depth))
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

                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cLockRewardAddress == EncodeDestination(CKeyID(uint160(vSolutions[0])))) {
                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::ExtractLockReward -- block Height: %d, info size: %d\n", prevBlockIndex->nHeight, (int)vSolutions.size());
                            if (vSolutions.size() != 2) {continue;}
                            std::string stringLRRegister(vSolutions[1].begin(), vSolutions[1].end());

                            std::string s;
                            stringstream ss(stringLRRegister);
                            //verify the height of registration info
                            int i=0;
                            int nRewardHeight = 0;
                            int nSINtype = 0;
                            std::string signature = "";
                            int *signerIndexes;
                            // Currently not used
                            //size_t N_SIGNERS = (size_t)Params().GetConsensus().nInfinityNodeLockRewardSigners;
                            int registerNbInfos = Params().GetConsensus().nInfinityNodeLockRewardSigners + 3;
                            signerIndexes = (int*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(int));

                            while (getline(ss, s,';')) {
                                if(i==0){nRewardHeight = atoi(s);}
                                if(i==1){nSINtype = atoi(s);}
                                if(i==2){signature = s;}
                                if(i>=3 && i < registerNbInfos){
                                    signerIndexes[i-3] = atoi(s);
                                }
                                i++;
                            }

                            free(signerIndexes);

                            if(nRewardHeight != nBlockHeight +1){continue;}
                            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::ExtractLockReward -- LR: %s.\n", stringLRRegister);

                            const CTxIn& txin = tx->vin[0];
                            int index = txin.prevout.n;

                            CTransactionRef prevtx;
                            uint256 hashblock;
                            if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false, nullptr, false)) {
                                LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::ExtractLockReward -- PrevBurnFund tx is not in block.\n");
                                return false;
                            }

                            CLockRewardExtractInfo lrinfo(prevBlockIndex->nHeight, nSINtype, nRewardHeight, prevtx->vout[index].scriptPubKey, stringLRRegister);

                            vecLRRet.push_back(lrinfo);
                        }
                    }
                }
            }
        } else {
            LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::ExtractLockReward -- can not read block from disk\n");
            return false;
        }
        // continue with previous block
        prevBlockIndex = prevBlockIndex->pprev;
    }
    return true;
}

/*make sure that LOCK sc_main before call this function*/
bool CInfinitynodeMan::getLRForHeight(int height, std::vector<CLockRewardExtractInfo>& vecLockRewardRet)
{
    vecLockRewardRet.clear();
    return ExtractLockReward(height, Params().GetConsensus().nInfinityNodeCallLockRewardDeepth * 3, vecLockRewardRet);
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
    if(nSinType == 1) mapStatementLIL.clear();
    if(nSinType == 5) mapStatementMID.clear();
    if(nSinType == 10) mapStatementBIG.clear();


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

        /* @giaki3003 - We use STL insert here, which is around 20% faster with proper hinting */
        if (nSinType == 10) {
            std::map<int, int>::iterator it = mapStatementBIG.upper_bound(stm_height_temp);
            if (it == mapStatementBIG.begin() || (--it)->first < stm_height_temp) {
                mapStatementBIG.insert(it, make_pair(stm_height_temp, totalSinType));
            } else {
                it->second = totalSinType;
            }
        }
        
        if (nSinType == 5) {
            std::map<int, int>::iterator it = mapStatementMID.upper_bound(stm_height_temp);
            if (it == mapStatementMID.begin() || (--it)->first < stm_height_temp) {
                mapStatementMID.insert(it, make_pair(stm_height_temp, totalSinType));
            } else {
                it->second = totalSinType;
            }
        }
        
        if (nSinType == 1) {
            std::map<int, int>::iterator it = mapStatementLIL.upper_bound(stm_height_temp);
            if (it == mapStatementLIL.begin() || (--it)->first < stm_height_temp) {
                mapStatementLIL.insert(it, make_pair(stm_height_temp, totalSinType));
            } else {
                it->second = totalSinType;
            }
        }
        //loop
        stm_height_temp = stm_height_temp + totalSinType;
        //we will out of loop this next step, but we can calculate the next STM now
        if(nCachedBlockHeight <=  stm_height_temp && stm_height_temp < nCachedBlockHeight + Params().MaxReorganizationDepth()){
            int totalSinTypeNextStm = 0;
            for (auto& infpair : mapInfinitynodes) {
                if (infpair.second.getSINType() == nSinType && infpair.second.getHeight() < stm_height_temp && stm_height_temp <= infpair.second.getExpireHeight()){
                    totalSinTypeNextStm = totalSinTypeNextStm + 1;
                }
            }

            if (nSinType == 10) {
                std::map<int, int>::iterator it = mapStatementBIG.upper_bound(stm_height_temp);
                if (it == mapStatementBIG.begin() || (--it)->first < stm_height_temp) {
                    mapStatementBIG.insert(it, make_pair(stm_height_temp, totalSinTypeNextStm));
                } else {
                    it->second = totalSinTypeNextStm;
                }
            }

            if (nSinType == 5) {
                std::map<int, int>::iterator it = mapStatementMID.upper_bound(stm_height_temp);
                if (it == mapStatementMID.begin() || (--it)->first < stm_height_temp) {
                    mapStatementMID.insert(it, make_pair(stm_height_temp, totalSinTypeNextStm));
                } else {
                    it->second = totalSinTypeNextStm;
                }
            }

            if (nSinType == 1) {
                std::map<int, int>::iterator it = mapStatementLIL.upper_bound(stm_height_temp);
                if (it == mapStatementLIL.begin() || (--it)->first < stm_height_temp) {
                    mapStatementLIL.insert(it, make_pair(stm_height_temp, totalSinTypeNextStm));
                } else {
                    it->second = totalSinTypeNextStm;
                }
            }
        }
    }

    if(nSinType == 1) LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::deterministicRewardStatement -- build Stm size: %d\n", mapStatementLIL.size());
    if(nSinType == 5) LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::deterministicRewardStatement -- build Stm size: %d\n", mapStatementMID.size());
    if(nSinType == 10) LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::deterministicRewardStatement -- build Stm size: %d\n", mapStatementBIG.size());
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
int CInfinitynodeMan::isPossibleForLockReward(COutPoint burntx)
{
    LOCK(cs);

    CInfinitynode inf;
    if(!Get(infinitynodePeer.burntx, inf)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessBlock -- Can not identify mypeer in list: %s\n", infinitynodePeer.burntx.ToStringShort());
        return false;
    }
/*
    bool found = false;
    for (auto& infpair : mapInfinitynodes) {
        if (infpair.second.collateralAddress == nodeOwner) {
            inf = infpair.second;
            found = true;
        }
    }
*/

    //not candidate => false
    {
        int nNodeSINtype = inf.getSINType();
        int nLastStmBySINtype = 0;
        int nLastStmSizeBySINtype = 0;
        if (nNodeSINtype == 10) {nLastStmBySINtype = nBIGLastStmHeight; nLastStmSizeBySINtype = nBIGLastStmSize;}
        if (nNodeSINtype == 5) {nLastStmBySINtype = nMIDLastStmHeight; nLastStmSizeBySINtype = nMIDLastStmSize;}
        if (nNodeSINtype == 1) {nLastStmBySINtype = nLILLastStmHeight; nLastStmSizeBySINtype = nLILLastStmSize;}
        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::isPossibleForLockReward -- info, SIN type: %d, Stm Height: %d, Stm size: %d, current Height: %d, node rank: %d\n",
             nNodeSINtype, nBIGLastStmHeight, nLastStmSizeBySINtype, nCachedBlockHeight, inf.getRank());
        //size of statement is not enough for call LockReward => false
        if(nLastStmSizeBySINtype <= Params().GetConsensus().nInfinityNodeCallLockRewardDeepth){
            LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::isPossibleForLockReward -- No, number node is not enough: %d, for SIN type: %d\n", nLastStmSizeBySINtype, nNodeSINtype);
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
                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::isPossibleForLockReward -- Yes, Stm height: %d, reward height: %d, current height: %d\n", nLastStmBySINtype, nHeightReward, nCachedBlockHeight);
                    return nHeightReward;
                }
                else{
                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::isPossibleForLockReward -- No, Stm height: %d, reward height: %d, current height: %d\n", nLastStmBySINtype, nHeightReward, nCachedBlockHeight);
                    return 0;
                }
            }
            //Case2: received reward in this Stm
            else
            {
                //expired at end of this Stm => false
                if(inf.isRewardInNextStm(nLastStmBySINtype + nLastStmSizeBySINtype)){
                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::isPossibleForLockReward -- No, node expire in next STM: %d, expired height: %d\n", nLastStmBySINtype + nLastStmSizeBySINtype, inf.getExpireHeight());
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
                    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::isPossibleForLockReward -- call for LockReward in %d block, next STM reward height: %d, current height: %d, next rank: %d\n",
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
    if(nBlockHeight < Params().GetConsensus().nInfinityNodeGenesisStatement){
        return false;
    }
    //step1: copy mapStatement for nSinType
    std::map<int, int> mapStatementSinType = getStatementMap(nSinType);

    if(mapStatementSinType.size() == 0){
        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::deterministicRewardAtHeight -- we've just start node. map of Stm is not built yet\n");
        return false;
    }

    //LOCK(cs);
    //step2: find last Statement for nBlockHeight (user can enter nBlockHeight, so it may be in past, current or future)
    int nDelta = Params().getNodeDelta(nBlockHeight); //big enough > number of 
    int lastStatement = 0;
    int lastStatementSize = 0;
    bool fUpdateStm = false;
    int nNextStmHeight = 0;
    long unsigned int loop = 1;
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
            } else if (loop == mapStatementSinType.size() && nDelta > stm.second && (nDelta - stm.second) <= Params().MaxReorganizationDepth()) {
                //at end of loop
                //we are near the end of current Stm and
                //we try LR in next stm, but deterministicRewardStatement is not call, dont wait and try to update here
                fUpdateStm = true;
                nNextStmHeight = stm.first + stm.second;
            }
        } else if(nBlockHeight > stm.first && nDelta == (nBlockHeight -stm.first)){
            if (loop == mapStatementSinType.size()){
                //at end of loop
                fUpdateStm = true;
                nNextStmHeight = stm.first + stm.second;
            }
        }
        loop++;
        if(lastStatement > 0 || fUpdateStm == true){
            LogPrintf("CInfinitynodeMan::deterministicRewardAtHeight -- Height: %s, Stm height: %d, stm size: %d, Delta: %d, Need update:%d\n", nBlockHeight, stm.first, stm.second, nDelta, fUpdateStm);
        }
    }

    //receive update flag
    if(fUpdateStm){
        int totalSinTypeNextStm = 0;
        for (auto& infpair : mapInfinitynodes) {
            if (infpair.second.getSINType() == nSinType && infpair.second.getHeight() < nNextStmHeight && nNextStmHeight <= infpair.second.getExpireHeight()){
                totalSinTypeNextStm = totalSinTypeNextStm + 1;
            }
        }

        if (nSinType == 10){mapStatementBIG[nNextStmHeight] = totalSinTypeNextStm;}
        if (nSinType == 5){mapStatementMID[nNextStmHeight] = totalSinTypeNextStm;}
        if (nSinType == 1){mapStatementLIL[nNextStmHeight] = totalSinTypeNextStm;}

        lastStatement = nNextStmHeight;
        lastStatementSize = totalSinTypeNextStm;
    }

    //return false if not found statement
    if (lastStatement == 0){
        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::deterministicRewardAtHeight -- lastStatement not found: %d\n", lastStatement);
        return false;
    }

    std::map<int, CInfinitynode> rankOfStatement = calculInfinityNodeRank(lastStatement, nSinType, false);
    if(rankOfStatement.empty()){
        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::deterministicRewardAtHeight -- can not calculate rank at %d\n", lastStatement);
        return false;
    }
    if((nBlockHeight < lastStatement) || (rankOfStatement.size() < (nBlockHeight - lastStatement + 1))){
        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::deterministicRewardAtHeight -- out of range at %d\n", lastStatement);
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
    //LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastStmHeightAndSize -- SIN type: %d, Height: %d\n", nSinType, nBlockHeight);
    if(nBlockHeight < Params().GetConsensus().nInfinityNodeGenesisStatement) return;
    //step1: copy mapStatement for nSinType
    std::map<int, int> mapStatementSinType = getStatementMap(nSinType);

    LOCK(cs);
    //step2: find last Statement for nBlockHeight;
    int nDelta = Params().getNodeDelta(nBlockHeight); //big enough > number of node by SIN type (Stm size). Delta is distant from Stm begin to last block
    int lastStatement = 0;
    int lastStatementSize = 0;
    for(auto& stm : mapStatementSinType)
    {
        if (nBlockHeight == stm.first)
        {
                //LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastStmHeightAndSize -- SIN type: %d, switch to new Stm :%d at size: %d\n", nSinType, stm.first, stm.second);
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
    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::updateLastStmHeightAndSize -- SIN type: %d, Last Stm: %d, Size: %d\n", nSinType, lastStatement, lastStatementSize);
}

/*
 * get Vector score of all NON EXPIRED SINtype for given nBlockHash
 */
bool CInfinitynodeMan::getScoreVector(const uint256& nBlockHash, int nSinType, int nBlockHeight, CInfinitynodeMan::score_pair_vec_t& vecScoresRet)
{
    vecScoresRet.clear();

    AssertLockHeld(cs);

    if (mapInfinitynodes.empty()) {
        LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::getScoreVector -- Infinitynode map is empty.\n");
        return false;
    }

    // calculate scores for SIN type 10
    for (auto& infpair : mapInfinitynodes) {
        CInfinitynode inf = infpair.second;
        if (inf.getSINType() == nSinType  && inf.getExpireHeight() >= nBlockHeight && inf.getHeight() < nBlockHeight) {
            vecScoresRet.push_back(std::make_pair(inf.CalculateScore(nBlockHash), &infpair.second));
        }
    }

    sort(vecScoresRet.rbegin(), vecScoresRet.rend(), CompareNodeScore());
    LogPrint(BCLog::INFINITYMAN,"CInfinitynodeMan::getScoreVector -- %d scores calculed at height: %d, for SINType %d\n", vecScoresRet.size(), nBlockHeight, nSinType);
    return vecScoresRet.size() > 0;
}

/*
 * get score classement of given NODE SINtype
 */
bool CInfinitynodeMan::getNodeScoreAtHeight(const COutPoint& outpoint, int nSinType, int nBlockHeight, int& nScoreRet)
{
    nScoreRet = -1;

    LOCK(cs);

    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrint(BCLog::INFINITYMAN,"CMasternodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
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

bool CInfinitynodeMan::getTopNodeScoreAtHeight(int nSinType, int nBlockHeight, int nTop, std::vector<CInfinitynode>& vecInfRet)
{
    vecInfRet.clear();

    LOCK(cs);

    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, nBlockHeight)) {
        LogPrint(BCLog::INFINITYMAN,"CMasternodeMan::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, nBlockHeight);
        return false;
    }

    score_pair_vec_t vecScores;

    if (!getScoreVector(nBlockHash, nSinType, nBlockHeight, vecScores))
        return false;

    int count=0;
    for (auto& scorePair : vecScores) {
        if(count < nTop){
            vecInfRet.push_back(*scorePair.second);
        }
        count++;
    }

    return true;
}

/*
 * get Rank classement of a Vector of Node at given Height
 */
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
        LogPrint(BCLog::INFINITYMAN,"CInfinityNodeLockReward::%s -- find rank for %s\n", __func__, outpoint.ToStringShort());
        int nRank = 1;
        for (std::pair<int, CInfinitynode*>& s : vecCInfinitynodeHeight){
            if(s.second->vinBurnFund.prevout == outpoint)
            {
                LogPrint(BCLog::INFINITYMAN,"CInfinityNodeLockReward::%s -- rank: %d\n", __func__, nRank);
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
    //update the last Stm when new block connected
    {
        nCachedBlockHeight = pindex->nHeight;
        LogPrint(BCLog::INFINITYLOCK,"CInfinitynodeMan::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);
    }
}

void CInfinitynodeMan::UpdateChainActiveHeight(int number)
{
    nCachedBlockHeight = number;
}
