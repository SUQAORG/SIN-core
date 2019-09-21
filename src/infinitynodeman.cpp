// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <infinitynodeman.h>
#include <util.h> //fMasterNode variable
#include <chainparams.h>
#include <key_io.h>
#include <util.h>
#include <script/standard.h>


CInfinitynodeMan infnodeman;

const std::string CInfinitynodeMan::SERIALIZATION_VERSION_STRING = "CInfinitynodeMan-Version-1";

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

void CInfinitynodeMan::UpdatedBlockTip(const CBlockIndex *pindex)
{
    nCachedBlockHeight = pindex->nHeight;
    if(fMasterNode) {
        // normal wallet does not need to update this every block, doing update on rpc call should be enough
        /* SIN::TODO - update last paid for all infinitynode */
        //UpdateLastPaid(pindex);
    }
}

void CInfinitynodeMan::CheckAndRemove(CConnman& connman)
{
    /*this function is called in PrivateSend thread and after sync of node*/
    LOCK(cs);
    if (nCachedBlockHeight > nLastScanHeight)
    {
        LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMan::CheckAndRemove -- block height %d and lastScan %d\n", 
                   nCachedBlockHeight, nLastScanHeight);
        nLastScanHeight = nCachedBlockHeight;
    }
}

bool CInfinitynodeMan::buildInfinitynodeList(int nBlockHeight, int nLowHeight)
{
    assert(nBlockHeight > nLowHeight);
    //first run, make sure that all variable is clear
    if (nLowHeight == INF_BEGIN_HEIGHT){
        Clear();
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
    while (prevBlockIndex->nHeight >= nLowHeight)
    {
        CBlock blockReadFromDisk;
        if (ReadBlockFromDisk(blockReadFromDisk, prevBlockIndex, Params().GetConsensus()))
        {
            for (const CTransactionRef& tx : blockReadFromDisk.vtx) {
                if (!tx->IsCoinBase() && (prevBlockIndex->nHeight < pindex->nHeight - Params().MaxReorganizationDepth())) {
                    bool fBurnFundTx = false;
                    for (unsigned int i = 0; i < tx->vout.size(); i++) {
                        const CTxOut& out = tx->vout[i];
                        if (
                            ((Params().GetConsensus().nMasternodeBurnSINNODE_1 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN) ||
                            ((Params().GetConsensus().nMasternodeBurnSINNODE_5 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN) ||
                            ((Params().GetConsensus().nMasternodeBurnSINNODE_10 - 1) * COIN < out.nValue && out.nValue <= Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN)
                        ) {
                            std::vector<std::vector<unsigned char>> vSolutions;
                            txnouttype whichType;
                            const CScript& prevScript = out.scriptPubKey;
                            Solver(prevScript, whichType, vSolutions);
                            if (Params().GetConsensus().cBurnAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                            {
                                fBurnFundTx = true;
                                COutPoint outpoint(tx->GetHash(), i);
                                CInfinitynode inf(PROTOCOL_VERSION, outpoint);
                                inf.setHeight(prevBlockIndex->nHeight);
                                inf.setBurnValue(out.nValue);
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
                                //we have all infos. Then add in map
                                Add(inf);
                            }
                        }
                    }
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
    LOCK(cs);
    {
        nLastScanHeight = pindex->nHeight;
        updateLastPaid();
    }
    LogPrintf("CInfinitynodeMan::buildInfinitynodeList -- list infinity node was built from blockchian and has %d nodes\n", Count());
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
