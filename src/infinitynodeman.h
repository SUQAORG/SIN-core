// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIN_INFINITYNODEMAN_H
#define SIN_INFINITYNODEMAN_H

#include <infinitynode.h>
#include <infinitynodelockinfo.h>


using namespace std;

class CInfinitynodeMan;
class CConnman;

extern CInfinitynodeMan infnodeman;

class CInfinitynodeMan
{
public:
    typedef std::pair<arith_uint256, CInfinitynode*> score_pair_t;
    typedef std::vector<score_pair_t> score_pair_vec_t;
    typedef std::pair<CScript, std::string> lockreward_pair_t; //how send LR and signature string
    typedef std::vector<lockreward_pair_t> lockreward_pair_vec_t;

    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
private:
    static const std::string SERIALIZATION_VERSION_STRING;

    // Keep track of current block height and first download block
    int nCachedBlockHeight;
    //
    bool fReachedLastBlock = false;

    // map to hold all INFs
    std::map<COutPoint, CInfinitynode> mapInfinitynodes;
    std::map<COutPoint, CInfinitynode> mapInfinitynodesNonMatured;

    // map to hold all reward statement
    std::map<int, int> mapStatementBIG;
    std::map<int, int> mapStatementMID;
    std::map<int, int> mapStatementLIL;
    int nBIGLastStmHeight;
    int nMIDLastStmHeight;
    int nLILLastStmHeight;
    int nBIGLastStmSize;
    int nMIDLastStmSize;
    int nLILLastStmSize;

    // map to hold payee and lastPaid Height
    std::map<CScript, int> mapLastPaid;
    mutable CCriticalSection cs_LastPaid;


public:

    CInfinitynodeMan();

    int64_t nLastScanHeight;//last verification from blockchain

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        LOCK(cs);
        std::string strVersion;
        if(ser_action.ForRead()) {
            READWRITE(strVersion);
        }
        else {
            strVersion = SERIALIZATION_VERSION_STRING;
            READWRITE(strVersion);
        }

        READWRITE(mapInfinitynodes);
        READWRITE(mapInfinitynodesNonMatured);
        READWRITE(mapLastPaid);
        READWRITE(nLastScanHeight);
        READWRITE(mapStatementBIG);
        READWRITE(mapStatementMID);
        READWRITE(mapStatementLIL);
        READWRITE(nBIGLastStmHeight);
        READWRITE(nMIDLastStmHeight);
        READWRITE(nLILLastStmHeight);
        READWRITE(nBIGLastStmSize);
        READWRITE(nMIDLastStmSize);
        READWRITE(nLILLastStmSize);

        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    std::string ToString() const;

    bool Add(CInfinitynode &inf);
    bool AddUpdateLastPaid(CScript scriptPubKey, int nHeightLastPaid);
    /// Find an entry
    CInfinitynode* Find(const COutPoint& outpoint);

    bool GetInfinitynodeInfo(std::string nodePublicKey, infinitynode_info_t& infInfoRet);
    bool GetInfinitynodeInfo(const COutPoint& outpoint, infinitynode_info_t& infInfoRet);

    /// Clear InfinityNode vector
    void Clear();
    /// Versions of Find that are safe to use from outside the class
    bool Get(const COutPoint& outpoint, CInfinitynode& infinitynodeRet);
    bool Has(const COutPoint& outpoint);
    bool HasPayee(CScript scriptPubKey);
    int Count();
    int CountEnabled();
    std::map<COutPoint, CInfinitynode> GetFullInfinitynodeMap() { LOCK(cs); return mapInfinitynodes; }
    std::map<COutPoint, CInfinitynode> GetFullInfinitynodeNonMaturedMap() { LOCK(cs); return mapInfinitynodesNonMatured; }
    std::map<int, int> getStatementMap(int nSinType){
        LOCK(cs);
        std::map<int, int> nullmap = {{0,0}};
        if(nSinType == 10) return mapStatementBIG;
        else if(nSinType == 5) return mapStatementMID;
        else if(nSinType == 1) return mapStatementLIL;
        else return nullmap;
    }
    int getLastStatement(int nSinType){
        LOCK(cs);
        if(nSinType == 10) return nBIGLastStmHeight;
        if(nSinType == 5) return nMIDLastStmHeight;
        if(nSinType == 1) return nLILLastStmHeight;
    }
    int getLastStatementSize(int nSinType){
        LOCK(cs);
        if(nSinType == 10) return nBIGLastStmSize;
        if(nSinType == 5) return nMIDLastStmSize;
        if(nSinType == 1) return nLILLastStmSize;
    }
    int getCacheHeightInf(){LOCK(cs); return nCachedBlockHeight;};

    void setSyncStatus(bool flag){LOCK(cs); fReachedLastBlock=flag;}
    bool isReachedLastBlock(){LOCK(cs); return fReachedLastBlock;}

    std::map<CScript, int> GetFullLastPaidMap() { return mapLastPaid; }
    int64_t getLastScan(){return nLastScanHeight;}
    int64_t getLastScanWithLimit(){return nLastScanHeight/* + INF_MATURED_LIMIT*/;} // We'll need to move this to functions who actually use it and match it with our max reorg depth
    //build DIN map by scan from nBlockHeight to nLowHeight
    bool updateLastPaidList(int nBlockHeight, int nLowHeight = 0); /* init this to zero for better compat with regtest/testnet/devnets */
    bool buildInfinitynodeListFromGenesis(int nBlockHeight);
    bool buildInfinitynodeList(int nBeginHeight, int nEndHeight);

    //build DIN map immediate when connect block
    bool buildNonMaturedListFromBlock(const CBlock& block, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams); //call in validation.cpp
    bool updateFinalList(CBlockIndex* pindex); // call when block is valid
    bool removeNonMaturedList(CBlockIndex* pindex); //call when block is invalid or disconnect

    void updateLastPaid();
    bool updateInfinitynodeList(int fromHeight);//call in init.cppp
    bool initialInfinitynodeList(int fromHeight);//call in init.cpp

    //LR read back
    bool ExtractLockReward(int nBlockHeight, int depth, std::vector<CLockRewardExtractInfo>& vecLRRet);
    bool getLRForHeight(int height, std::vector<CLockRewardExtractInfo>& vecLockRewardRet);

    //this function build the map of STM from genesis
    bool deterministicRewardStatement(int nSinType);
    bool deterministicRewardAtHeight(int nBlockHeight, int nSinType, CInfinitynode& infinitynodeRet);
    std::map<int, CInfinitynode> calculInfinityNodeRank(int nBlockHeight, int nSinType, bool updateList=false, bool flagExtCall = false);
    void calculAllInfinityNodesRankAtLastStm();
    std::pair<int, int> getLastStatementBySinType(int nSinType);
    std::string getLastStatementString() const;
    int getRoi(int nSinType, int totalNode);

    int isPossibleForLockReward(COutPoint burntx);
    bool getScoreVector(const uint256& nBlockHash, int nSinType, int nBlockHeight, CInfinitynodeMan::score_pair_vec_t& vecScoresRet);
    bool getNodeScoreAtHeight(const COutPoint& outpoint, int nSinType, int nBlockHeight, int& nRankRet);
    bool getTopNodeScoreAtHeight(int nSinType, int nBlockHeight, int nTop, std::vector<CInfinitynode>& vecInfRet);

    std::string getVectorNodeRankAtHeight(const std::vector<COutPoint>  &vOutpoint, int nSinType, int nBlockHeight);

    //this function update lastStm and size from UpdatedBlockTip and map
    void updateLastStmHeightAndSize(int nBlockHeight, int nSinType);
    void CheckAndRemove(CConnman& connman);
    /// This is dummy overload to be used for dumping/loading mncache.dat
    void CheckAndRemove() {}
    void UpdatedBlockTip(const CBlockIndex *pindex);
    void UpdateChainActiveHeight(int number);
};
#endif // SIN_INFINITYNODEMAN_H
