// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 FXTC developers
// Copyright (c) 2018-2019 SUQA developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>

#define NEVER 2000000000

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
        consensus.nMasternodePaymentsIncreaseBlock = 50;
        consensus.nMasternodePaymentsIncreasePeriod = 365 * 1440; // 1 common year
        consensus.nMasternodeCollateralMinimum = 10;
		consensus.nMasternodeBurnSINNODE_1 = 1;
		consensus.nMasternodeBurnSINNODE_5 = 5;
		consensus.nMasternodeBurnSINNODE_10 = 15;
		
        consensus.nInstantSendKeepLock = 24;

        consensus.nBudgetPaymentsStartBlock = 365 * 1440; // 1 common year
        consensus.nBudgetPaymentsCycleBlocks = 10958; // weekly
        consensus.nBudgetPaymentsWindowBlocks = 100;
        consensus.nBudgetProposalEstablishingTime = 86400; // 1 day

        consensus.nSuperblockStartBlock = 365 * 1440; // 1 common year
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
        consensus.cBurnAddress = "SinBurnAddress123456789SuqaXbx3AMC";
        consensus.cBurnAddressPubKey = "ebaf5ec74cb2e2342dfda0229111738ff4dc742d";
		strSporkPubKey = "045EB51EB748C6EB7A53531DF71BE998F3E77F4AFF801978D4AED543F21E224E49E10D679E8A99A001E93ADE704F761F2B8822D967F19DC3B50603797F344CBB58";

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

        vSeeds.push_back("suqaexplorer.com");
        vSeeds.push_back("139.59.139.105");
        vSeeds.push_back("104.248.133.94");
        vSeeds.push_back("104.248.17.3");
        vSeeds.push_back("46.101.152.7");
        vSeeds.push_back("46.101.227.238");
        vSeeds.push_back("209.97.153.68");
        vSeeds.push_back("159.89.194.138");

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
                { 0, consensus.hashGenesisBlock }
            }
        };

        chainTxData = ChainTxData{
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = true;
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
        consensus.nMasternodePaymentsIncreaseBlock = 50;
        consensus.nMasternodePaymentsIncreasePeriod = 365 * 1440; // 1 common year
        consensus.nMasternodeCollateralMinimum = 10;
		consensus.nMasternodeBurnSINNODE_1 = 1;
		consensus.nMasternodeBurnSINNODE_5 = 5;
		consensus.nMasternodeBurnSINNODE_10 = 15;
        consensus.nInstantSendKeepLock = 24;
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
        consensus.cBurnAddress = "ScK6eotHEke2CjU9XaJvXLCRhfa3qAUars";
        consensus.cBurnAddressPubKey = "a4befe81854e3101ac29c71b462edaea3ba73f30";
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

        vSeeds.emplace_back("178.128.230.114");
        vSeeds.emplace_back("178.62.226.114");
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

        nPoolMaxTransactions = 2;

        checkpointData = {
        };

        chainTxData = ChainTxData{
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
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
	consensus.devAddressPubKey = "841e6bf56b99a59545da932de2efb23ab93b4f44";

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

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        // assert(consensus.hashGenesisBlock == uint256S("0000000000000000000000000000000000000000000000000000000000000000"));
        // assert(genesis.hashMerkleRoot == uint256S("0000000000000000000000000000000000000000000000000000000000000000"));

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
