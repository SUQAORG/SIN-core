// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 FXTC developers
// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FXTC_MASTERNODE_PAYMENTS_H
#define FXTC_MASTERNODE_PAYMENTS_H

#include <util/system.h>
#include <core_io.h>
#include <key.h>
#include <masternode.h>
#include <net_processing.h>
#include <util/strencodings.h>

class CMasternodePayments;
class CMasternodePaymentVote;
class CMasternodeBlockPayees;

static const int MNPAYMENTS_SIGNATURES_REQUIRED         = 6;
static const int MNPAYMENTS_SIGNATURES_TOTAL            = 30; // number of node will vote for block

//! minimum peer version that can receive and send masternode payment messages,
//  vote for masternode and be elected as a payment winner
// V1 - Last protocol version before update
// V2 - Newest protocol version
static const int MIN_MASTERNODE_PAYMENT_PROTO_VERSION_1 = 250000;
static const int MIN_MASTERNODE_PAYMENT_PROTO_VERSION_2 = 250000;

extern CCriticalSection cs_vecPayees;
extern CCriticalSection cs_mapMasternodeBlocks;
extern CCriticalSection cs_mapMasternodePayeeVotes;

extern CMasternodePayments mnpayments;

/// TODO: all 4 functions do not belong here really, they should be refactored/moved somewhere (main.cpp ?)
bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string &strErrorRet);
bool IsBlockPayeeValid(const CTransactionRef txNew, int nBlockHeight, CAmount blockReward, CBlockHeader pblock);
void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& txoutMasternodeRet, std::vector<CTxOut>& voutSuperblockRet);
std::string GetRequiredPaymentsString(int nBlockHeight);

class CMasternodePayee
{
private:
    CScript scriptPubKey;
    int sintype;
    std::vector<uint256> vecVoteHashes;

public:
    CMasternodePayee() :
        scriptPubKey(),
        sintype(),
        vecVoteHashes()
        {}

    CMasternodePayee(CScript payee, int sintypeIn, uint256 hashIn) :
        scriptPubKey(payee),
        sintype(sintypeIn),
        vecVoteHashes()
    {
        vecVoteHashes.push_back(hashIn);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(sintype);
        READWRITE(vecVoteHashes);
    }

    uint256 GetHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << scriptPubKey;
        ss << sintype;
        return ss.GetHash();
    }

    CScript GetPayee() { return scriptPubKey; }
    int GetSinType() { return sintype; }

    void AddVoteHash(uint256 hashIn) { vecVoteHashes.push_back(hashIn); }
    std::vector<uint256> GetVoteHashes() { return vecVoteHashes; }
    int GetVoteCount() { return vecVoteHashes.size(); }
};

// Keep track of votes for payees from masternodes
class CMasternodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<CMasternodePayee> vecPayees;

    CMasternodeBlockPayees() :
        nBlockHeight(0),
        vecPayees()
        {}
    CMasternodeBlockPayees(int nBlockHeightIn) :
        nBlockHeight(nBlockHeightIn),
        vecPayees()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBlockHeight);
        READWRITE(vecPayees);
    }

    void AddPayee(const CMasternodePaymentVote& vote);
    bool GetBestPayee(int sintype, CScript& payeeRet);
    bool HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq);

    bool IsTransactionValid(const CTransactionRef txNew);

    std::string GetRequiredPaymentsString();
};

// vote for the winning payment
class CMasternodePaymentVote
{
public:
    CTxIn vinMasternode;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;

    CMasternodePaymentVote() :
        vinMasternode(),
        nBlockHeight(0),
        payee(),
        vchSig()
        {}

    CMasternodePaymentVote(COutPoint outpointMasternode, int nBlockHeight, CScript payee) :
        vinMasternode(outpointMasternode),
        nBlockHeight(nBlockHeight),
        payee(payee),
        vchSig()
        {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vinMasternode);
        READWRITE(nBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        READWRITE(vchSig);
    }

    uint256 GetHash() const {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << *(CScriptBase*)(&payee);
        ss << nBlockHeight;
        ss << vinMasternode.prevout;
        return ss.GetHash();
    }

    bool Sign();
    bool CheckSignature(const CPubKey& pubKeyMasternode, int nValidationHeight, int &nDos);

    bool IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman);
    void Relay(CConnman& connman);

    bool IsVerified() { return !vchSig.empty(); }
    void MarkAsNotVerified() { vchSig.clear(); }

    std::string ToString() const;
};

//
// Masternode Payments Class
// Keeps track of who should get paid for which blocks
//
typedef std::pair<int, int> sintype_pair_t; // <int sintype, int inNetwork(0,1)>
typedef std::vector<sintype_pair_t> sintype_pair_vec_t;

class CMasternodePayments
{
private:
    // masternode count times nStorageCoeff payments blocks should be stored ...
    const float nStorageCoeff;
    // ... but at least nMinBlocksToStore (payments blocks)
    const int nMinBlocksToStore;

    // Keep track of current block height
    int nCachedBlockHeight;

public:
    std::map<uint256, CMasternodePaymentVote> mapMasternodePaymentVotes;
    std::map<int, CMasternodeBlockPayees> mapMasternodeBlocks;
    std::map<COutPoint, int> mapMasternodesLastVote;
    std::map<COutPoint, int> mapMasternodesDidNotVote;

    CMasternodePayments() : nStorageCoeff(1.25), nMinBlocksToStore(5000) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(mapMasternodePaymentVotes);
        READWRITE(mapMasternodeBlocks);
    }

    void Clear();

    bool AddPaymentVote(const CMasternodePaymentVote& vote);
    bool HasVerifiedPaymentVote(uint256 hashIn);
    bool ProcessBlock(int nBlockHeight, CConnman& connman);//SIN: add check can vote or not
    void CheckPreviousBlockVotes(int nPrevBlockHeight);

    void Sync(CNode* node, CConnman& connman);
    void RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman);
    void CheckAndRemove();

    bool GetBlockPayee(int nBlockHeight, int sintype, CScript& payee);
    bool IsTransactionValid(const CTransactionRef txNew, int nBlockHeight);
    bool IsScheduled(CMasternode& mn, int nNotBlockHeight);

    bool CanVote(COutPoint outMasternode, int nBlockHeight);//can vote for this MN or not

    int GetMinMasternodePaymentsProto();
    void ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& txoutMasternodeRet, sintype_pair_vec_t& vSinType);
    void FillNextBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& txoutMasternodeRet, sintype_pair_vec_t& vSinType);
    std::string ToString() const;

    int GetBlockCount() { return mapMasternodeBlocks.size(); }
    int GetVoteCount() { return mapMasternodePaymentVotes.size(); }

    bool IsEnoughData();
    int GetStorageLimit();

    void UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman);
	void NetworkDiagnostic(int nBlockHeight, int& nSINNODE_1Ret, int& nSINNODE_5Ret, int& nSINNODE_10Ret);
};

#endif // FXTC_MASTERNODE-PAYMENTS_H
