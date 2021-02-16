// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 FXTC developers
// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>

#define NEVER 2000000000

//Useful for devnets

bool CheckProof(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;


    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow)
        return false; //error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false; //error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520159231 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Guardian 27/06/18 One football pitch of forest lost every second in 2017";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

int CChainParams::getNodeDelta(int nHeight) const {
    if (nHeight > nDeltaChangeHeight) {
        return 2000;
    } else {
        return 1000;
    }
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMasternodePaymentsStartBlock = 50;
        consensus.nMasternodeCollateralMinimum = 10000;
        consensus.nMasternodeBurnSINNODE_1 = 100000;
        consensus.nMasternodeBurnSINNODE_5 = 500000;
        consensus.nMasternodeBurnSINNODE_10 = 1000000;
        consensus.nLimitSINNODE_1=375;
        consensus.nLimitSINNODE_5=375;
        consensus.nLimitSINNODE_10=375;
        consensus.nInstantSendKeepLock = 24;
        consensus.nInfinityNodeBeginHeight=160000; //masternode code
        consensus.nInfinityNodeGenesisStatement=250000; // begin point for new reward algo
        consensus.nInfinityNodeUpdateMeta=25;
        consensus.nInfinityNodeVoteValue=100;
        consensus.nInfinityNodeNotificationValue=1;
        consensus.nInfinityNodeCallLockRewardDeepth=50;
        consensus.nInfinityNodeCallLockRewardLoop=10; //in number of blocks
        consensus.nInfinityNodeLockRewardTop=16; //in number
        consensus.nInfinityNodeLockRewardSigners=4; //in number
        consensus.nInfinityNodeLockRewardSINType=10; //in number
        consensus.nInfinityNodeExpireTime=262800;//720*365 days = 1 year
        consensus.nSchnorrActivationHeight = 1350000; // wait for active

        /*Previously used as simple constants in validation */
        consensus.nINActivationHeight = 170000; // Activation of IN payments, should also be the same as nInfinityNodeBeginHeight in primitives/block.cpp
        consensus.nINEnforcementHeight = 178000; // Enforcement of IN payments
        consensus.nDINActivationHeight = 550000; // Activation of DIN 1.0 payments, and new dev fee address.

        consensus.nBudgetPaymentsStartBlock = 365 * 1440 * 5; // 1 common year
        consensus.nBudgetPaymentsCycleBlocks = 10958; // weekly
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 86400; // 1 day

        consensus.nSuperblockStartBlock = 365 * 1440 * 5; // 1 common year
        consensus.nSuperblockCycle = 10958; // weekly

        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.BIP16Exception = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = NEVER;
        consensus.BIP34Hash = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.powLimit = uint256S("0fffff0000000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 3600;
        consensus.nPowTargetSpacing = 120;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.devAddressPubKey = "841e6bf56b99a59545da932de2efb23ab93b4f44";
        consensus.devAddress = "SZLafuDjnjqh2tAfTrG9ZAGzbP8HkzNXvB";
        consensus.devAddress2PubKey = "c07290a27153f8adaf01e6f5817405a32f569f61";
        consensus.devAddress2 = "Seqa1ndWyNUU51MSg7hgThSrdfFxfodise";
        consensus.cBurnAddressPubKey = "ebaf5ec74cb2e2342dfda0229111738ff4dc742d";
        consensus.cBurnAddress = "SinBurnAddress123456789SuqaXbx3AMC";
        consensus.cMetadataAddress = "SinBurnAddressForMetadataXXXXEU2mj";
        consensus.cNotifyAddress = "SinBurnAddressForNotifyXXXXXc42TcT";
        consensus.cLockRewardAddress = "SinBurnAddressForLockRewardXTbeffB";
        consensus.cGovernanceAddress = "SinBurnAddressGovernanceVoteba5vkQ";
        strSporkPubKey = "0449434681D96595AC04470E5613475D259489CAA79C260814D22D4F29F7361D84A85F1F535F7B11F51B87F4E7B8E168AA68747A6E7465DCF34ABDD25570430573";

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = NEVER;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = NEVER;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = NEVER;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf8;
        pchMessageStart[1] = 0xdd;
        pchMessageStart[2] = 0xd4;
        pchMessageStart[3] = 0xb8;
        nDefaultPort = 20970;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1533029778, 1990615403, 0x1f00ffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("000032bd27c65ec42967b7854a49df222abdfae8d9350a61083af8eab2a25e03"));
        assert(genesis.hashMerkleRoot == uint256S("c3555790e3804130514a674f3374b451dce058407dad6b9e82e191e198012680"));

        vSeeds.push_back("seederdns.sinovate.org"); //SIN dns seeder
        vSeeds.push_back("seederdns.suqa.org"); //SIN dns seeder


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,191);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        nPoolMaxTransactions = 10;
        nFulfilledRequestExpireTime = 60*60; // fulfilled requests expire in 1 hour

        checkpointData = {
            {
                { 0     , uint256S("0x000032bd27c65ec42967b7854a49df222abdfae8d9350a61083af8eab2a25e03")},
                { 100000, uint256S("0x00000000001e01fb192b33bc90a19fb4bd99bc4973ea2f766e4670ce5acb60bd")},
                { 200000, uint256S("0x75f01eea029358a280b65b5d7e9ea3c4987a153cd1c702747ae88d811ada7c13")},
                { 300000, uint256S("0xe0f5ecb094c6a26b3b57a259b9d4efa9903b8bae6f3194effd50c1c633c30e05")},
                { 400000, uint256S("0x130bd010d1c8bc52637660938bfbea90f2ff6aadcb562d62ea838f2130d2dc83")},
                { 500000, uint256S("0x9c642efedac61f56aabed01972cc5648def5a5a4c7373289f427895304d93d9a")},
                { 550001, uint256S("0x3ad39235119d78fa2c2dd33343bedf88fccac6a6659f1baf9fa200a1b6d256c9")}, // DIN fork block
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 7ba8d1850a54bdc3fa8863609ca44976217b59bf619f81c93d0a0c99622f1750
            /* nTime    */ 1598428702,
            /* nTxCount */ 1568986,
            /* dTxRate  */ 0.017159050970158,
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = true;
        nMaxReorganizationDepth = 55; // 55 at 2 minute block timespan is +/- 120 minutes/2h.
        nMinReorganizationPeers = 3;
        nDeltaChangeHeight = 617000; // height at which we change node deltas


        consensus.lwmaStartHeight = 262000;
        consensus.lwmaAveragingWindow = 96;    
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMasternodePaymentsStartBlock = 50;
        consensus.nMasternodeCollateralMinimum = 10;
        consensus.nMasternodeBurnSINNODE_1 = 100000;
        consensus.nMasternodeBurnSINNODE_5 = 500000;
        consensus.nMasternodeBurnSINNODE_10 = 1000000;
        consensus.nLimitSINNODE_1=6;
        consensus.nLimitSINNODE_5=6;
        consensus.nLimitSINNODE_10=6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nInfinityNodeBeginHeight=100;
        consensus.nInfinityNodeGenesisStatement=110;// begin point for new reward algo
        consensus.nInfinityNodeUpdateMeta=5;
        consensus.nInfinityNodeNotificationValue=1;
        consensus.nInfinityNodeCallLockRewardDeepth=12;
        consensus.nInfinityNodeCallLockRewardLoop=5; //next LR will be in 5 blocks
        consensus.nInfinityNodeLockRewardTop=20; //top 20 nodes will build Musig in number
        consensus.nInfinityNodeLockRewardSigners=3; //number of signers paticiple Musig
        consensus.nInfinityNodeLockRewardSINType=10; //in number
        consensus.nInfinityNodeExpireTime=5040;
        consensus.nSchnorrActivationHeight = 1350000; // wait for active

        /*Previously used as simple constants in validation */
        consensus.nINActivationHeight = 100; //  Activation of IN 0.1 payments, should also be the same as nInfinityNodeBeginHeight in primitives/block.cpp
        consensus.nINEnforcementHeight = 120; // Enforcement of IN payments
        consensus.nDINActivationHeight = 2880; // Activation of DIN 1.0 payments, and new dev fee address

        consensus.nBudgetPaymentsStartBlock = 365 * 1440; // 1 common year
        consensus.nBudgetPaymentsCycleBlocks = 10958; // weekly
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 86400; // 1 day
        consensus.nSuperblockStartBlock = 365 * 1440; // 1 common year
        consensus.nSuperblockCycle = 10958; // weekly
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.BIP16Exception = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = 8388608;
        consensus.BIP34Hash = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 8388608;
        consensus.BIP66Height = 8388608;
        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 3600;
        consensus.nPowTargetSpacing = 120;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.devAddressPubKey = "841e6bf56b99a59545da932de2efb23ab93b4f44";
        consensus.devAddress = "SZLafuDjnjqh2tAfTrG9ZAGzbP8HkzNXvB";
        consensus.devAddress2PubKey = "c07290a27153f8adaf01e6f5817405a32f569f61";
        consensus.devAddress2 = "STEkkU29v5rjb6CMUdGciF1e4STZ6jx7aq";
        consensus.cBurnAddress = "SinBurnAddress123456789SuqaXbx3AMC";
        consensus.cBurnAddressPubKey = "ebaf5ec74cb2e2342dfda0229111738ff4dc742d";
        consensus.cMetadataAddress = "SinBurnAddressForMetadataXXXXEU2mj";
        consensus.cNotifyAddress = "SinBurnAddressForNotifyXXXXXc42TcT";
        consensus.cLockRewardAddress = "SinBurnAddressForLockRewardXTbeffB";
        consensus.cGovernanceAddress = "SinBurnAddressGovernanceVoteba5vkQ";
        strSporkPubKey = "0454E1B43ECCAC17E50402370477455BE34593E272CA9AE0DF04F6F3D423D1366D017822C77990A3D8DD980C60D3692C9B6D7DFD75F683F7056C1E97E82BD94DBE";

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = NEVER;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = NEVER;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = NEVER;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xb8;
        pchMessageStart[1] = 0xfd;
        pchMessageStart[2] = 0xf4;
        pchMessageStart[3] = 0xd8;
        nPruneAfterHeight = 1000;
        nFulfilledRequestExpireTime = 60*60;

        genesis = CreateGenesisBlock(1457163389, 2962201989, 0x1f00ffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
        // assert(genesis.hashMerkleRoot == uint256S("0000000000000000000000000000000000000000000000000000000000000000"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.push_back("testnetseeder.suqa.org"); //Testnet SIN dns seeder
        
        nDefaultPort = 20980;

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,191);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        nPoolMaxTransactions = 3;

        checkpointData = {
        };

        chainTxData = ChainTxData{
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
        nMaxReorganizationDepth = 14; // 5 at 2 minute block timespan is +/- 10 minutes.
        nMinReorganizationPeers = 3;
        nDeltaChangeHeight = 0; // height at which we change node deltas

        consensus.lwmaStartHeight = 150;
        consensus.lwmaAveragingWindow = 96;
    }
};

/**
 * FinalNet
 */
class CFinalNetParams : public CChainParams {
public:
    CFinalNetParams() {
        strNetworkID = "final";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nMasternodePaymentsStartBlock = 50;
        consensus.nMasternodeCollateralMinimum = 10;
        consensus.nMasternodeBurnSINNODE_1 = 100000;
        consensus.nMasternodeBurnSINNODE_5 = 500000;
        consensus.nMasternodeBurnSINNODE_10 = 1000000;
        consensus.nLimitSINNODE_1=6;
        consensus.nLimitSINNODE_5=6;
        consensus.nLimitSINNODE_10=6;
        consensus.nInstantSendKeepLock = 24;
        consensus.nInfinityNodeBeginHeight=100;
        consensus.nInfinityNodeGenesisStatement=110;
        consensus.nInfinityNodeUpdateMeta=5;
        consensus.nInfinityNodeNotificationValue=1;
        consensus.nInfinityNodeCallLockRewardDeepth=5;
        consensus.nInfinityNodeCallLockRewardLoop=2; //in number of blocks
        consensus.nInfinityNodeLockRewardTop=5; //in number
        consensus.nInfinityNodeLockRewardSigners=2; //number of signers paticiple Musig
        consensus.nInfinityNodeLockRewardSINType=1; //in number
        consensus.nInfinityNodeExpireTime=5040;
        consensus.nSchnorrActivationHeight = 1350000; // wait for active

        /*Previously used as simple constants in validation */
        consensus.nINActivationHeight = 170000; // Activation of IN payment enforcement, should also be the same as nSinHeightMainnet in primitives/block.cpp
        consensus.nINEnforcementHeight = 178000; // Enforcement of IN payments
        consensus.nDINActivationHeight = 99999999; // Placeholder, need to choose a fork block.

        consensus.nBudgetPaymentsStartBlock = 365 * 1440; // 1 common year
        consensus.nBudgetPaymentsCycleBlocks = 10958; // weekly
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 86400; // 1 day
        consensus.nSuperblockStartBlock = 365 * 1440; // 1 common year
        consensus.nSuperblockCycle = 10958; // weekly
        consensus.nGovernanceMinQuorum = 10;
        consensus.nGovernanceFilterElements = 20000;
        consensus.BIP16Exception = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP34Height = 8388608;
        consensus.BIP34Hash = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 8388608;
        consensus.BIP66Height = 8388608;
        consensus.powLimit = uint256S("0000ffff00000000000000000000000000000000000000000000000000000000");
        consensus.nPowTargetTimespan = 3600;
        consensus.nPowTargetSpacing = 120;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.devAddressPubKey = "841e6bf56b99a59545da932de2efb23ab93b4f44";
        consensus.devAddress = "SZLafuDjnjqh2tAfTrG9ZAGzbP8HkzNXvB";
        consensus.devAddress2PubKey = "413395a3a8fedfc2a06f645ad40151412d414544";
        consensus.devAddress2 = "STEkkU29v5rjb6CMUdGciF1e4STZ6jx7aq";
        consensus.cBurnAddress = "SinBurnAddress123456789SuqaXbx3AMC";
        consensus.cBurnAddressPubKey = "ebaf5ec74cb2e2342dfda0229111738ff4dc742d";
        consensus.cMetadataAddress = "SinBurnAddressForMetadataXXXXEU2mj";
        consensus.cNotifyAddress = "SinBurnAddressForNotifyXXXXXc42TcT";
        consensus.cLockRewardAddress = "SinBurnAddressForLockRewardXTbeffB";
        consensus.cGovernanceAddress = "SinBurnAddressGovernanceVoteba5vkQ";
        strSporkPubKey = "0454E1B43ECCAC17E50402370477455BE34593E272CA9AE0DF04F6F3D423D1366D017822C77990A3D8DD980C60D3692C9B6D7DFD75F683F7056C1E97E82BD94DBE";

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = NEVER;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = NEVER;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = NEVER;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = NEVER;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0000000000000000000000000000000000000000000000000000000000000000");

        pchMessageStart[0] = 0xfe;
        pchMessageStart[1] = 0xfd;
        pchMessageStart[2] = 0xf4;
        pchMessageStart[3] = 0xd8;
        nPruneAfterHeight = 1000;
        nFulfilledRequestExpireTime = 60*60;

        genesis = CreateGenesisBlock(1558117000, 91643, 0x1f00ffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
        // assert(genesis.hashMerkleRoot == uint256S("0000000000000000000000000000000000000000000000000000000000000000"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("178.128.230.114");
        vSeeds.emplace_back("178.62.226.114");
        nDefaultPort = 20990;

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,191);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        nPoolMaxTransactions = 3;

        checkpointData = {
        };

        chainTxData = ChainTxData{
        };

        /* enable fallback fee on FinalNet */
        m_fallback_fee_enabled = true;
        nMaxReorganizationDepth = 5; // 5 at 2 minute block timespan is +/- 10 minutes.
        nMinReorganizationPeers = 3;
        nDeltaChangeHeight = 0; // height at which we change node deltas

        consensus.lwmaStartHeight = 260000;
        consensus.lwmaAveragingWindow = 96;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nMasternodeMinimumConfirmations = 15;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nInfinityNodeBeginHeight=100;
        consensus.nInfinityNodeGenesisStatement=110;
        consensus.nInfinityNodeUpdateMeta=5;
        consensus.nInfinityNodeNotificationValue=1;
        consensus.nInfinityNodeCallLockRewardDeepth=5;
        consensus.nInfinityNodeCallLockRewardLoop=2; //in number of blocks
        consensus.nInfinityNodeLockRewardTop=5; //in number
        consensus.nInfinityNodeLockRewardSigners=2; //number of signers paticiple Musig
        consensus.nInfinityNodeLockRewardSINType=1; //in number
        consensus.nInfinityNodeExpireTime=5040;
        consensus.nSchnorrActivationHeight = 1350000; // wait for active
        consensus.nMasternodeBurnSINNODE_1 = 100000;
        consensus.nMasternodeBurnSINNODE_5 = 500000;
        consensus.nMasternodeBurnSINNODE_10 = 1000000;
        consensus.nMasternodeCollateralMinimum = 10000;

        /*Previously used as simple constants in validation */
        consensus.nINActivationHeight = 5000; // Activation of IN payment enforcement, should also be the same as nSinHeightMainnet in primitives/block.cpp
        consensus.nINEnforcementHeight = 5500; // Enforcement of IN payments
        consensus.nDINActivationHeight = 60000000; // Placeholder, need to choose a fork block.

        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351;
        consensus.BIP66Height = 1251;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;
        consensus.devAddress2PubKey = "d63bf3a5822bb2f7ac9ced84ae2c1f319c4253e2";
        consensus.devAddress2 = "n13iidFw2jiVVoz86ouMqv31x7oEe5V4Wm";
        consensus.devAddressPubKey = "d63bf3a5822bb2f7ac9ced84ae2c1f319c4253e2";
        consensus.devAddress = "n13iidFw2jiVVoz86ouMqv31x7oEe5V4Wm";
        consensus.cBurnAddressPubKey = "76a9142be2e66836eda517af05e5b628eb9fedefcd669b88ac";
        consensus.cBurnAddress = "mjX1AbMEHU14PmHjG2wtSvoydnJ6RxYwC2";
        consensus.cMetadataAddress = "mueP7L3nMXdshqPEMZ3L5wJumKqhq5dFpm";
        consensus.cNotifyAddress = "mobk9h9A3QLYKsKw9xWSC4bqYSUsqEwnpk";
        consensus.cLockRewardAddress = "n3NZ5A6WKiKRMZWu4b1WiHxJjgjza1RMRk";
        consensus.cGovernanceAddress = "mgmp6o3V4z3kU83QFbNrdtRKGFS6T9yQyB";
        strSporkPubKey = "0454E1B43ECCAC17E50402370477455BE34593E272CA9AE0DF04F6F3D423D1366D017822C77990A3D8DD980C60D3692C9B6D7DFD75F683F7056C1E97E82BD94DBE";

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 3, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x1cf45e8c265c41a6c29e40a285cd635924c7658e2334c19829c3722777cd4823"));
        assert(genesis.hashMerkleRoot == uint256S("0x2fa6ca3a7c3115918d274574d4016a660e9d9dec86ea984d8815b68e956bb24a"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;


        checkpointData = {
        };

        chainTxData = ChainTxData{
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
        nMaxReorganizationDepth = 5; // 5 at 2 minute block timespan is +/- 10 minutes.
        nMinReorganizationPeers = 3;
        nDeltaChangeHeight = 0; // height at which we change node deltas

        consensus.lwmaStartHeight = 260000;
        consensus.lwmaAveragingWindow = 96;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::FINALNET)
        return std::unique_ptr<CChainParams>(new CFinalNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
