// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <infinitynode.h>
#include <key_io.h>
#include <messagesigner.h>
#include <script/standard.h>
#include <timedata.h>

#include <shutdown.h>

#include <util/system.h>
#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif // ENABLE_WALLET

#include <boost/lexical_cast.hpp>

CInfinitynode::CInfinitynode() :
    infinitynode_info_t{PROTOCOL_VERSION, GetAdjustedTime()}
{}

CInfinitynode::CInfinitynode(const CInfinitynode& other) :
    infinitynode_info_t{other}
{}

CInfinitynode::CInfinitynode(int nProtocolVersionIn, COutPoint outpointBurnFund) :
    infinitynode_info_t{nProtocolVersionIn, GetAdjustedTime(), outpointBurnFund}
{}

infinitynode_info_t CInfinitynode::GetInfo()
{
    infinitynode_info_t info{*this};
    return info;
}
/*
bool CInfinitynode::IsValidNetAddr()
{
    return IsValidNetAddr(metadataService);
}
*/
bool CInfinitynode::IsValidNetAddr(CService addrIn)
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ||
            (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

bool CInfinitynode::IsValidStateForAutoStart(int metadataHeight)
{
    return (metadataHeight > 0);
}

arith_uint256 CInfinitynode::CalculateScore(const uint256& blockHash)
{
    // Deterministically calculate a "score" for a Masternode based on any given (block)hash
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vinBurnFund.prevout << blockHash;
    return UintToArith256(ss.GetHash());
}
