// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <arith_uint256.h>
#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <test/bignum.h>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

std::string COutPoint::ToStringShort() const
{
    return strprintf("%s-%u", hash.ToString().substr(0,64), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn, int nRoundsIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
    nRounds = nRoundsIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

std::string CMutableTransaction::ToString() const
{
    std::string str;
    str += strprintf("CMutableTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (unsigned int i = 0; i < vin.size(); i++)
        str += "    " + vin[i].ToString() + "\n";
    for (unsigned int i = 0; i < vout.size(); i++)
        str += "    " + vout[i].ToString() + "\n";
    return str;
}


uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */
CTransaction::CTransaction() : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), hash{}, m_witness_hash{} {}
CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        nValueOut += tx_out.nValue;
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
    }
    return nValueOut;
}

// Dash
double CTransaction::ComputePriority(double dPriorityInputs, unsigned int nTxSize) const
{
    nTxSize = CalculateModifiedSize(nTxSize);
    if (nTxSize == 0) return 0.0;

    return dPriorityInputs / nTxSize;
}

unsigned int CTransaction::CalculateModifiedSize(unsigned int nTxSize) const
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    if (nTxSize == 0)
        nTxSize = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    for (std::vector<CTxIn>::const_iterator it(vin.begin()); it != vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}
//

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        vin.size(),
        vout.size(),
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}

CAmount CTxOut::GetValueWithInterest(int outputBlockHeight, int valuationHeight) const
{
    return GetInterest(nValue, outputBlockHeight, valuationHeight, scriptPubKey.GetTermDepositReleaseBlock());
}

#define BLOCKSPERDAY 720
static int THIRTYDAYS=BLOCKSPERDAY*30;
static int ONEYEAR=BLOCKSPERDAY*365;
static int ONEYEARPLUS1=ONEYEAR+1;
static int TWOYEARS=ONEYEAR*2;
static int THREEMONTHS=THIRTYDAYS*3;

static uint64_t rateTable[BLOCKSPERDAY*365+1];
static uint64_t bonusTable[BLOCKSPERDAY*365+1];

CAmount getBonusForAmount(int periods, CAmount theAmount)
{
    // dont accept negative timespan/amounts
    if (periods <= 0 || theAmount <= 0)
	return 0;

    CBigNum amount256(theAmount);
    CBigNum rate256(bonusTable[periods]);
    CBigNum rate0256(bonusTable[0]);
    CBigNum result=(amount256*rate256)/rate0256;
    return result.getuint64()-theAmount;
}

CAmount getRateForAmount(int periods, CAmount theAmount)
{
    // dont accept negative timespan/amounts
    if (periods <= 0 || theAmount <= 0)
        return 0;

    CBigNum amount256(theAmount);
    CBigNum rate256(rateTable[periods]);
    CBigNum rate0256(rateTable[0]);
    CBigNum result=(amount256*rate256)/rate0256;
    return  result.getuint64()-theAmount;
}

std::string initRateTable()
{
    std::string str;

    rateTable[0]  = 1;
    rateTable[0]  = rateTable[0]  << 62;
    bonusTable[0] = 1;
    bonusTable[0] = bonusTable[0] << 58;

    for(int i=1;i<ONEYEARPLUS1;i++){
        rateTable[i]  = rateTable[i-1]  + (rateTable[i-1]  >> 22);
        bonusTable[i] = bonusTable[i-1] + (bonusTable[i-1] >> 20);
        str += strprintf("%d %x %x\n",i,rateTable[i], bonusTable[i]);
    }

    for(int i=0;i<ONEYEAR;i++)
        str += strprintf("rate: %d %d %d\n",i,getRateForAmount(i,COIN*100),getBonusForAmount(i,COIN*100));

    return str;
}

CAmount GetInterest(CAmount nValue, int outputBlockHeight, int valuationHeight, int maturationBlock)
{
    if(maturationBlock >= 500000000 || outputBlockHeight<0 || outputBlockHeight>=170000 || valuationHeight<0 || valuationHeight<outputBlockHeight)
        return nValue;

    int blocks=0;

    if(maturationBlock>0)
        blocks=std::min(THIRTYDAYS,maturationBlock-outputBlockHeight);

    CAmount standardInterest=getRateForAmount(blocks, nValue);

    CAmount bonusAmount=0;
    if(outputBlockHeight<THREEMONTHS)
        bonusAmount=getBonusForAmount(blocks, nValue);

    CAmount interestAmount=standardInterest+bonusAmount;

    CAmount termDepositAmount=0;

    if(maturationBlock>0){
        int term=std::min(THIRTYDAYS,maturationBlock-outputBlockHeight);
        if(term < BLOCKSPERDAY*1) interestAmount = 0;
    }

    return nValue+interestAmount+termDepositAmount;
}
