// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIN_INFINITYNODEMAN_H
#define SIN_INFINITYNODEMAN_H

#include <infinitynode.h>



using namespace std;

class CInfinitynodeMan;
class CConnman;

extern CInfinitynodeMan infnodeman;

class CInfinitynodeMan
{
public:

private:
    static const std::string SERIALIZATION_VERSION_STRING;

    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
    // Keep track of current block height
    int nCachedBlockHeight;

    static const int INF_BEGIN_HEIGHT = 165000;//user burnfund to create node
    static const int INF_BEGIN_REWARD = 200000;//network reward node owner with new algo

    // map to hole all INFs
    std::map<COutPoint, CInfinitynode> mapInfinitynodes;
    // map to hold payee and lastPaid Height
    std::map<CScript, int> mapLastPaid;
    mutable CCriticalSection cs_LastPaid;


public:

    CInfinitynodeMan();

    int64_t nLastScanHeight;//last verification from blockchain
    /// Add an entry

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
        READWRITE(mapLastPaid);
        READWRITE(nLastScanHeight);
        if(ser_action.ForRead() && (strVersion != SERIALIZATION_VERSION_STRING)) {
            Clear();
        }
    }

    std::string ToString() const;

    bool Add(CInfinitynode &mn);
    bool AddUpdateLastPaid(CScript scriptPubKey, int nHeightLastPaid);
    /// Find an entry
    CInfinitynode* Find(const COutPoint& outpoint);
    /// Clear InfinityNode vector
    void Clear();
    /// Versions of Find that are safe to use from outside the class
    bool Get(const COutPoint& outpoint, CInfinitynode& infinitynodeRet);
    bool Has(const COutPoint& outpoint);
    bool HasPayee(CScript scriptPubKey);
    int Count();
    std::map<COutPoint, CInfinitynode> GetFullInfinitynodeMap() { return mapInfinitynodes; }
    std::map<CScript, int> GetFullLastPaidMap() { return mapLastPaid; }
    int64_t getLastScan(){return nLastScanHeight;}

    bool buildInfinitynodeList(int nBlockHeight);
    bool buildListForBlock(int nBlockHeight);
    bool updateInfinitynodeList(int fromHeight);

    void CheckAndRemove(CConnman& connman);
    /// This is dummy overload to be used for dumping/loading mncache.dat
    void CheckAndRemove() {}
    void UpdatedBlockTip(const CBlockIndex *pindex);
};
#endif // SIN_INFINITYNODEMAN_H