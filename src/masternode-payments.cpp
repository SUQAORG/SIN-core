// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 FXTC developers
// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <activemasternode.h>
#include <masternode-payments.h>
#include <masternode-sync.h>
#include <masternodeman.h>
#include <messagesigner.h>
#include <netfulfilledman.h>
#include <netmessagemaker.h>
#include <spork.h>
#include <util/system.h>
#include <script/standard.h>
#include <key_io.h>

#include <boost/lexical_cast.hpp>

/** Object for who's going to get paid on which blocks */
CMasternodePayments mnpayments;

CCriticalSection cs_vecPayees;
CCriticalSection cs_mapMasternodeBlocks;
CCriticalSection cs_mapMasternodePaymentVotes;

/**
* IsBlockValueValid
*
*   Determine if coinbase outgoing created money is the correct value
*
*   Why is this needed?
*   - In Dash some blocks are superblocks, which output much higher amounts of coins
*   - Otherblocks are 10% lower in outgoing value, so in total, no extra coins are created
*   - When non-superblocks are detected, the normal schedule should be maintained
*/

bool IsBlockValueValid(const CBlock& block, int nBlockHeight, CAmount blockReward, std::string &strErrorRet)
{
    strErrorRet = "";

    bool isBlockRewardValueMet = (block.vtx[0]->GetValueOut() <= blockReward);
    if(fDebug) LogPrintf("block.vtx[0]->GetValueOut() %lld <= blockReward %lld\n", block.vtx[0]->GetValueOut(), blockReward);

    // we are still using budgets, but we have no data about them anymore,
    // all we know is predefined budget cycle and window

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if(nBlockHeight < consensusParams.nSuperblockStartBlock) {
        int nOffset = nBlockHeight % consensusParams.nBudgetPaymentsCycleBlocks;
        if(nBlockHeight >= consensusParams.nBudgetPaymentsStartBlock &&
            nOffset < consensusParams.nBudgetPaymentsWindowBlocks) {
            // NOTE: make sure SPORK_13_OLD_SUPERBLOCK_FLAG is disabled when 12.1 starts to go live
            if(masternodeSync.IsSynced() && !sporkManager.IsSporkActive(SPORK_13_OLD_SUPERBLOCK_FLAG)) {
                // no budget blocks should be accepted here, if SPORK_13_OLD_SUPERBLOCK_FLAG is disabled
                LogPrint(BCLog::GOBJECT, "IsBlockValueValid -- Client synced but budget spork is disabled, checking block value against block reward\n");
                if(!isBlockRewardValueMet) {
                    strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, budgets are disabled",
                                            nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
                }
                return isBlockRewardValueMet;
            }
            LogPrint(BCLog::GOBJECT, "IsBlockValueValid -- WARNING: Skipping budget block value checks, accepting block\n");
            // TODO: reprocess blocks to make sure they are legit?
            return true;
        }
        // LogPrint(BCLog::GOBJECT, "IsBlockValueValid -- Block is not in budget cycle window, checking block value against block reward\n");
        if(!isBlockRewardValueMet) {
            strErrorRet = strprintf("coinbase pays too much at height %d (actual=%d vs limit=%d), exceeded block reward, block is not in budget cycle window",
                                    nBlockHeight, block.vtx[0]->GetValueOut(), blockReward);
        }
        return isBlockRewardValueMet;
    }

    // superblocks started
    // removed

    // it MUST be a regular block
    return isBlockRewardValueMet;
}

bool IsBlockPayeeValid(const CTransactionRef txNew, int nBlockHeight, CAmount blockReward, CBlockHeader pblock)
{
    if(!masternodeSync.IsSynced()) {
        //there is no budget data to use to check anything, let's just accept the longest chain
        if(fDebug) LogPrintf("IsBlockPayeeValid -- WARNING: Client not synced, skipping block payee checks\n");
        return true;
    }

    // we are still using budgets, but we have no data about them anymore,
    // we can only check masternode payments

    const Consensus::Params& consensusParams = Params().GetConsensus();

    if(nBlockHeight < consensusParams.nSuperblockStartBlock) {
		LogPrintf("IsBlockPayeeValid -- Superblock is not started\n");
        if(mnpayments.IsTransactionValid(txNew, nBlockHeight)) {
            LogPrintf("IsBlockPayeeValid -- Valid masternode payment at height %d: %s\n", nBlockHeight, txNew->ToString());
            return true;
        }

        int nOffset = nBlockHeight % consensusParams.nBudgetPaymentsCycleBlocks;
        if(nBlockHeight >= consensusParams.nBudgetPaymentsStartBlock &&
            nOffset < consensusParams.nBudgetPaymentsWindowBlocks) {
            if(!sporkManager.IsSporkActive(SPORK_13_OLD_SUPERBLOCK_FLAG)) {
                // no budget blocks should be accepted here, if SPORK_13_OLD_SUPERBLOCK_FLAG is disabled
                LogPrint(BCLog::GOBJECT, "IsBlockPayeeValid -- ERROR: Client synced but budget spork is disabled and masternode payment is invalid\n");
                return false;
            }
            // NOTE: this should never happen in real, SPORK_13_OLD_SUPERBLOCK_FLAG MUST be disabled when 12.1 starts to go live
            LogPrint(BCLog::GOBJECT, "IsBlockPayeeValid -- WARNING: Probably valid budget block, have no data, accepting\n");
            // TODO: reprocess blocks to make sure they are legit?
            return true;
        }

        if(sporkManager.IsSporkActive(SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT)) {
                LogPrintf("IsBlockPayeeValid -- ERROR: Invalid masternode payment detected at height %d: %s\n", nBlockHeight, txNew->ToString());
                return false;
        }

        LogPrintf("IsBlockPayeeValid -- WARNING: Masternode payment enforcement is disabled, accepting any payee\n");
        return true;
    }

    // IF THIS ISN'T A SUPERBLOCK OR SUPERBLOCK IS INVALID, IT SHOULD PAY A MASTERNODE DIRECTLY
    if(mnpayments.IsTransactionValid(txNew, nBlockHeight)) {
        LogPrint(BCLog::MNPAYMENTS, "IsBlockPayeeValid -- Valid masternode payment at height %d: %s\n", nBlockHeight, txNew->ToString());
        return true;
    }

    if(sporkManager.IsSporkActive(SPORK_8_MASTERNODE_PAYMENT_ENFORCEMENT)) {
        LogPrintf("IsBlockPayeeValid -- ERROR: Invalid masternode payment detected at height %d: %s\n", nBlockHeight, txNew->ToString());
        return false;
    }

    LogPrintf("IsBlockPayeeValid -- WARNING: Masternode payment enforcement is disabled, accepting any payee\n");
    return true;
}

void FillBlockPayments(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& txoutMasternodeRet, std::vector<CTxOut>& voutSuperblockRet)
{
	int fSINNODE_1 = 0; int fSINNODE_5 = 0; int fSINNODE_10 = 0;
    sintype_pair_vec_t vSinType;

    // FILL BLOCK PAYEE WITH MASTERNODE PAYMENT OTHERWISE
	mnpayments.NetworkDiagnostic(nBlockHeight, fSINNODE_1, fSINNODE_5, fSINNODE_10);
	LogPrintf("FillBlockPayments -- SIN type in network, height: %d, LILSIN: %d MIDSIN: %d BIGSIN:  %d\n", nBlockHeight, fSINNODE_1, fSINNODE_5, fSINNODE_10);
    vSinType.clear();
	vSinType.push_back(std::make_pair(CMasternode::SinType::SINNODE_1, fSINNODE_1));
	vSinType.push_back(std::make_pair(CMasternode::SinType::SINNODE_5, fSINNODE_5));
	vSinType.push_back(std::make_pair(CMasternode::SinType::SINNODE_10, fSINNODE_10));
    mnpayments.FillBlockPayee(txNew, nBlockHeight, blockReward, txoutMasternodeRet, vSinType);
	for (auto txoutMasternode : txoutMasternodeRet) {
		LogPrint(BCLog::MNPAYMENTS, "FillBlockPayments -- nBlockHeight %d blockReward %lld txoutMasternodeRet %s txNew %s\n",
                            nBlockHeight, blockReward, txoutMasternode.ToString(), txNew.ToString());
	}

    mnpayments.NetworkDiagnostic(nBlockHeight + 1, fSINNODE_1, fSINNODE_5, fSINNODE_10);
	LogPrintf("FillBlockPayments -- SIN type in network, height: %d, LILSIN: %d MIDSIN: %d BIGSIN:  %d\n", nBlockHeight + 1, fSINNODE_1, fSINNODE_5, fSINNODE_10);
    vSinType.clear();
    vSinType.push_back(std::make_pair(CMasternode::SinType::SINNODE_1, fSINNODE_1));
	vSinType.push_back(std::make_pair(CMasternode::SinType::SINNODE_5, fSINNODE_5));
	vSinType.push_back(std::make_pair(CMasternode::SinType::SINNODE_10, fSINNODE_10));
    mnpayments.FillNextBlockPayee(txNew, nBlockHeight + 1, blockReward, txoutMasternodeRet, vSinType);
	for (auto txoutMasternode : txoutMasternodeRet) {
		LogPrint(BCLog::MNPAYMENTS, "FillBlockPayments -- nBlockHeight %d blockReward %lld txoutMasternodeRet %s txNew %s\n",
                            nBlockHeight + 1, blockReward, txoutMasternode.ToString(), txNew.ToString());
	}
}

std::string GetRequiredPaymentsString(int nBlockHeight)
{
    // OTHERWISE, PAY MASTERNODE
    return mnpayments.GetRequiredPaymentsString(nBlockHeight);
}

void CMasternodePayments::Clear()
{
    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);
    mapMasternodeBlocks.clear();
    mapMasternodePaymentVotes.clear();
}

bool CMasternodePayments::CanVote(COutPoint outMasternode, int nBlockHeight)
{
    LOCK(cs_mapMasternodePaymentVotes);

    if (mapMasternodesLastVote.count(outMasternode) && mapMasternodesLastVote[outMasternode] == nBlockHeight) {
        return false;
    }

    //record this masternode voted
    mapMasternodesLastVote[outMasternode] = nBlockHeight;
    return true;
}

/**
*   FillBlockPayee
*
*   Fill Masternode ONLY payment block
*/

void CMasternodePayments::FillBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& txoutMasternodeRet, sintype_pair_vec_t& vSinType)
{
    // make sure it's not filled yet
    txoutMasternodeRet.clear();

    CScript payee;
	for (auto& sintype : vSinType) {
		CAmount masternodePayment = GetMasternodePayment(nBlockHeight, sintype.first);
		if (sintype.second == 1) {
			if(!mnpayments.GetBlockPayee(nBlockHeight, sintype.first, payee)) {
				// no masternode detected/voted from network...
				int nCount = 0;
				masternode_info_t mnInfo;
				if(!mnodeman.GetNextMasternodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) { //this call is always false by SINNODE_UNKNOWN ==> no paid for local miner vote
					LogPrintf("CMasternodePayments::FillBlockPayee -- Failed to detect masternode to pay\n");
					continue;
				}
				// fill payee with locally calculated winner and hope for the best
				payee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());
			}

			// split reward between miner ...
			txNew.vout[0].nValue -= masternodePayment;
			// ... and masternode
			txoutMasternodeRet.push_back(CTxOut(masternodePayment, payee));
			txNew.vout.push_back(CTxOut(masternodePayment, payee));

			CTxDestination address1;
			ExtractDestination(payee, address1);
			std::string address2 = EncodeDestination(address1);

			LogPrintf("CMasternodePayments::FillBlockPayee -- Masternode payment %lld to %s with SIN type %d\n", masternodePayment, address2, sintype.first);
		}else{
			txNew.vout[0].nValue -= masternodePayment;
			CTxDestination burnDestination =  DecodeDestination(Params().GetConsensus().cBurnAddress);
			CScript burnAddressScript = GetScriptForDestination(burnDestination);
			txNew.vout.push_back(CTxOut(masternodePayment, burnAddressScript));
			LogPrintf("CMasternodePayments::FillBlockPayee -- Burn coin %lld for SIN type %d\n", masternodePayment, sintype.first);
		}
	}
	return;
}

void CMasternodePayments::FillNextBlockPayee(CMutableTransaction& txNew, int nBlockHeight, CAmount blockReward, std::vector<CTxOut>& txoutMasternodeRet, sintype_pair_vec_t& vSinType)
{
    // make sure it's not filled yet
    txoutMasternodeRet.clear();

    CScript payee;
	for (auto& sintype : vSinType) {
        CAmount masternodePayment = 0;
        if (CMasternode::SinType::SINNODE_1 == sintype.first) {
            masternodePayment = Params().GetConsensus().nMasternodeBurnSINNODE_1;
        }
        if (CMasternode::SinType::SINNODE_5 == sintype.first) {
            masternodePayment = Params().GetConsensus().nMasternodeBurnSINNODE_5;
        }
        if (CMasternode::SinType::SINNODE_10 == sintype.first) {
            masternodePayment = Params().GetConsensus().nMasternodeBurnSINNODE_10;
        }
		if (sintype.second == 1) {
			if(!mnpayments.GetBlockPayee(nBlockHeight, sintype.first, payee)) {
				// no masternode detected/voted from network...
				int nCount = 0;
				masternode_info_t mnInfo;
				if(!mnodeman.GetNextMasternodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo)) { //this call is always false by SINNODE_UNKNOWN ==> no paid for local miner vote
					LogPrintf("CMasternodePayments::FillBlockPayee -- Failed to detect masternode to pay\n");
					continue;
				}
				// fill payee with locally calculated winner and hope for the best
				payee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());
			}
			// split reward between miner ...
			txNew.vout[0].nValue -= masternodePayment;
			// ... and masternode
			txoutMasternodeRet.push_back(CTxOut(masternodePayment, payee));
			txNew.vout.push_back(CTxOut(masternodePayment, payee));

			CTxDestination address1;
			ExtractDestination(payee, address1);
			std::string address2 = EncodeDestination(address1);

			LogPrintf("CMasternodePayments::FillBlockPayee -- Masternode payment %lld to %s with SIN type %d\n", masternodePayment, address2, sintype.first);
		}else{
			txNew.vout[0].nValue -= masternodePayment;
			CTxDestination burnDestination =  DecodeDestination(Params().GetConsensus().cBurnAddress);
			CScript burnAddressScript = GetScriptForDestination(burnDestination);
			txNew.vout.push_back(CTxOut(masternodePayment, burnAddressScript));
			LogPrintf("CMasternodePayments::FillBlockPayee -- Burn coin %lld for SIN type %d\n", masternodePayment, sintype.first);
		}
	}
	return;
}

int CMasternodePayments::GetMinMasternodePaymentsProto() {
    return sporkManager.IsSporkActive(SPORK_10_MASTERNODE_PAY_UPDATED_NODES)
            ? MIN_MASTERNODE_PAYMENT_PROTO_VERSION_2
            : MIN_MASTERNODE_PAYMENT_PROTO_VERSION_1;
}

void CMasternodePayments::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all Dash specific functionality

    if (strCommand == NetMsgType::MASTERNODEPAYMENTSYNC) { //Masternode Payments Request Sync

        // Ignore such requests until we are fully synced.
        // We could start processing this after masternode list is synced
        // but this is a heavy one so it's better to finish sync first.
        if (!masternodeSync.IsSynced()) return;

        int nCountNeeded;
        vRecv >> nCountNeeded;

        if(netfulfilledman.HasFulfilledRequest(pfrom->addr, NetMsgType::MASTERNODEPAYMENTSYNC)) {
            LOCK(cs_main);
            // Asking for the payments list multiple times in a short period of time is no good
            LogPrintf("MASTERNODEPAYMENTSYNC -- peer already asked me for the list, peer=%d\n", pfrom->GetId());
            Misbehaving(pfrom->GetId(), 20);
            return;
        }
        netfulfilledman.AddFulfilledRequest(pfrom->addr, NetMsgType::MASTERNODEPAYMENTSYNC);

        Sync(pfrom, connman);
        LogPrintf("MASTERNODEPAYMENTSYNC -- Sent Masternode payment votes to peer %d\n", pfrom->GetId());

    } else if (strCommand == NetMsgType::MASTERNODEPAYMENTVOTE) { // Masternode Payments Vote for the Winner

        CMasternodePaymentVote vote;
        vRecv >> vote;

        if(pfrom->nVersion < GetMinMasternodePaymentsProto()) return;

        uint256 nHash = vote.GetHash();

        pfrom->setAskFor.erase(nHash);

        // TODO: clear setAskFor for MSG_MASTERNODE_PAYMENT_BLOCK too

        // Ignore any payments messages until masternode list is synced
        if(!masternodeSync.IsMasternodeListSynced()) return;

        {
            LOCK(cs_mapMasternodePaymentVotes);
            if(mapMasternodePaymentVotes.count(nHash)) {
                //LogPrint(BCLog::MNPAYMENTS, "MASTERNODEPAYMENTVOTE -- hash=%s, nHeight=%d seen\n", nHash.ToString(), nCachedBlockHeight);
                return;
            }

            // Avoid processing same vote multiple times
            mapMasternodePaymentVotes[nHash] = vote;
            // but first mark vote as non-verified,
            // AddPaymentVote() below should take care of it if vote is actually ok
            mapMasternodePaymentVotes[nHash].MarkAsNotVerified();
        }

        int nFirstBlock = nCachedBlockHeight - GetStorageLimit();
        if(vote.nBlockHeight < nFirstBlock || vote.nBlockHeight > nCachedBlockHeight+20) {
            //LogPrint(BCLog::MNPAYMENTS, "MASTERNODEPAYMENTVOTE -- vote out of range: nFirstBlock=%d, nBlockHeight=%d, nHeight=%d\n", nFirstBlock, vote.nBlockHeight, nCachedBlockHeight);
            return;
        }

        std::string strError = "";
        if(!vote.IsValid(pfrom, nCachedBlockHeight, strError, connman)) {
            LogPrint(BCLog::MNPAYMENTS, "MASTERNODEPAYMENTVOTE -- invalid message, error: %s\n", strError);
            return;
        }

        if(!CanVote(vote.vinMasternode.prevout, vote.nBlockHeight)) {
            LogPrintf("MASTERNODEPAYMENTVOTE -- masternode already voted, masternode=%s\n", vote.vinMasternode.prevout.ToStringShort());
            return;
        }

        masternode_info_t mnInfo;
        if(!mnodeman.GetMasternodeInfo(vote.vinMasternode.prevout, mnInfo)) {
            // mn was not found, so we can't check vote, some info is probably missing
            LogPrintf("MASTERNODEPAYMENTVOTE -- masternode is missing %s\n", vote.vinMasternode.prevout.ToStringShort());
            mnodeman.AskForMN(pfrom, vote.vinMasternode.prevout, connman);
            return;
        }

        int nDos = 0;
        if(!vote.CheckSignature(mnInfo.pubKeyMasternode, nCachedBlockHeight, nDos)) {
            if(nDos) {
                LOCK(cs_main);
                LogPrintf("MASTERNODEPAYMENTVOTE -- ERROR: invalid signature\n");
                Misbehaving(pfrom->GetId(), nDos);
            } else {
                // only warn about anything non-critical (i.e. nDos == 0) in debug mode
                LogPrint(BCLog::MNPAYMENTS, "MASTERNODEPAYMENTVOTE -- WARNING: invalid signature\n");
            }
            // Either our info or vote info could be outdated.
            // In case our info is outdated, ask for an update,
            mnodeman.AskForMN(pfrom, vote.vinMasternode.prevout, connman);
            // but there is nothing we can do if vote info itself is outdated
            // (i.e. it was signed by a mn which changed its key),
            // so just quit here.
            return;
        }

        CTxDestination address1;
        ExtractDestination(vote.payee, address1);
        std::string address2 = EncodeDestination(address1);

        //LogPrint(BCLog::MNPAYMENTS, "MASTERNODEPAYMENTVOTE -- vote: address=%s, nBlockHeight=%d, nHeight=%d, prevout=%s, hash=%s new\n",
        //            address2, vote.nBlockHeight, nCachedBlockHeight, vote.vinMasternode.prevout.ToStringShort(), nHash.ToString());

        if(AddPaymentVote(vote)){
            vote.Relay(connman);
            masternodeSync.BumpAssetLastTime("MASTERNODEPAYMENTVOTE");
        }
    }
}

bool CMasternodePaymentVote::Sign()
{
    std::string strError;
    std::string strMessage = vinMasternode.prevout.ToStringShort() +
                boost::lexical_cast<std::string>(nBlockHeight) +
                ScriptToAsmStr(payee);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, activeMasternode.keyMasternode)) {
        LogPrintf("CMasternodePaymentVote::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(activeMasternode.pubKeyMasternode, vchSig, strMessage, strError)) {
        LogPrintf("CMasternodePaymentVote::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CMasternodePayments::GetBlockPayee(int nBlockHeight, int sintype, CScript& payee)
{
    if(mapMasternodeBlocks.count(nBlockHeight)){
        return mapMasternodeBlocks[nBlockHeight].GetBestPayee(sintype, payee);
    }

    return false;
}

void CMasternodePayments::NetworkDiagnostic(int nBlockHeight, int& nSINNODE_1Ret, int& nSINNODE_5Ret, int& nSINNODE_10Ret)
{
	nSINNODE_1Ret = 0; nSINNODE_5Ret = 0; nSINNODE_10Ret = 0;
	CScript payee;

	if(mapMasternodeBlocks.count(nBlockHeight) && mapMasternodeBlocks[nBlockHeight].GetBestPayee(CMasternode::SinType::SINNODE_1, payee)){
		nSINNODE_1Ret = 1;
	}

	if(mapMasternodeBlocks.count(nBlockHeight) && mapMasternodeBlocks[nBlockHeight].GetBestPayee(CMasternode::SinType::SINNODE_5, payee)){
		nSINNODE_5Ret = 1;
	}

	if(mapMasternodeBlocks.count(nBlockHeight) && mapMasternodeBlocks[nBlockHeight].GetBestPayee(CMasternode::SinType::SINNODE_10, payee)){
		nSINNODE_10Ret = 1;
	}
}


// Is this masternode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 blocks of votes
bool CMasternodePayments::IsScheduled(CMasternode& mn, int nNotBlockHeight)
{
    LOCK(cs_mapMasternodeBlocks);

    if(!masternodeSync.IsMasternodeListSynced()) return false;

    CScript mnpayee;
    mnpayee = GetScriptForDestination(mn.pubKeyCollateralAddress.GetID());

    CScript payee;
    for (int64_t h = nCachedBlockHeight; h <= nCachedBlockHeight + 8; h++){
        if(h == nNotBlockHeight) continue;
        if(mapMasternodeBlocks.count(h) && mapMasternodeBlocks[h].GetBestPayee(mn.GetSinTypeInt() ,payee) && mnpayee == payee) {
            return true;
        }
    }

    return false;
}

bool CMasternodePayments::AddPaymentVote(const CMasternodePaymentVote& vote)
{
    LOCK(cs_main);

    uint256 blockHash = uint256();
    if(!GetBlockHash(blockHash, vote.nBlockHeight - 101)) return false;

    if(HasVerifiedPaymentVote(vote.GetHash())) return false;

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    mapMasternodePaymentVotes[vote.GetHash()] = vote;

    if(!mapMasternodeBlocks.count(vote.nBlockHeight)) {
       CMasternodeBlockPayees blockPayees(vote.nBlockHeight);
       mapMasternodeBlocks[vote.nBlockHeight] = blockPayees;
    }

    mapMasternodeBlocks[vote.nBlockHeight].AddPayee(vote);

    return true;
}

bool CMasternodePayments::HasVerifiedPaymentVote(uint256 hashIn)
{
    LOCK(cs_mapMasternodePaymentVotes);
    std::map<uint256, CMasternodePaymentVote>::iterator it = mapMasternodePaymentVotes.find(hashIn);
    return it != mapMasternodePaymentVotes.end() && it->second.IsVerified();
}

void CMasternodeBlockPayees::AddPayee(const CMasternodePaymentVote& vote)
{
    LOCK(cs_vecPayees);

    for (auto& payee : vecPayees) {
        if (payee.GetPayee() == vote.payee) {
            payee.AddVoteHash(vote.GetHash());
            return;
        }
    }

    CMasternode* pmn = mnodeman.Find(vote.vinMasternode.prevout);
    if(pmn == NULL){
        LogPrintf("MASTERNODEPAYMENTVOTE -- masternode is unknown %s\n", vote.vinMasternode.prevout.ToStringShort());
        return;
    }

    if (pmn->GetSinTypeInt() == -1){
        LOCK(cs_main);
        pmn->Check();
    }

    CMasternodePayee payeeNew(vote.payee, pmn->GetSinTypeInt(), vote.GetHash());
    vecPayees.push_back(payeeNew);
}

bool CMasternodeBlockPayees::GetBestPayee(int sintype, CScript& payeeRet)
{
    LOCK(cs_vecPayees);

    if(!vecPayees.size()) {
        LogPrint(BCLog::MNPAYMENTS, "CMasternodeBlockPayees::GetBestPayee -- ERROR: couldn't find any payee\n");
        return false;
    }

    int nVotes = -1;
    CMasternodePayee payeetmp;
    for (auto& payee : vecPayees) {
        //first candidate OR not the same vote
        if (payee.GetVoteCount() > nVotes && payee.GetSinType() == sintype) {
            nVotes = payee.GetVoteCount();

            payeeRet = payee.GetPayee();
            payeetmp = payee;
        }
        //found someone with the same vote
        if (payee.GetVoteCount() == nVotes && payee.GetSinType() == sintype) {
            if (UintToArith256(payee.GetHash()) > UintToArith256(payeetmp.GetHash())){
                 payeeRet = payee.GetPayee();
                 payeetmp = payee;
            }
        }
    }

    return (nVotes > -1);
}

bool CMasternodeBlockPayees::HasPayeeWithVotes(const CScript& payeeIn, int nVotesReq)
{
    LOCK(cs_vecPayees);

    for (auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= nVotesReq && payee.GetPayee() == payeeIn) {
            return true;
        }
    }

    return false;
}

bool CMasternodeBlockPayees::IsTransactionValid(const CTransactionRef txNew)
{
    LOCK(cs_vecPayees);

    int nMaxSignatures = 0;
    std::string strPayeesPossible = "";
	std::string strPayeesInTx = "";

    //require at least MNPAYMENTS_SIGNATURES_REQUIRED signatures
    for (auto& payee : vecPayees) {
        if (payee.GetVoteCount() >= nMaxSignatures) {
            nMaxSignatures = payee.GetVoteCount();
        }
    }
	LogPrintf("CMasternodeBlockPayees::IsTransactionValid -- nMaxSignatures: %d\n", nMaxSignatures);
    // if we don't have at least MNPAYMENTS_SIGNATURES_REQUIRED signatures on a payee, approve whichever is the longest chain
    if(nMaxSignatures < MNPAYMENTS_SIGNATURES_REQUIRED) return true;

	int counterNodePayment = 0;
	CScript burnfundScript;
	burnfundScript << OP_DUP << OP_HASH160 << ParseHex(Params().GetConsensus().cBurnAddressPubKey) << OP_EQUALVERIFY << OP_CHECKSIG;

	int txIndex = 0;
	for (auto txout : txNew->vout) {
		txIndex ++;
		if (3 <= txIndex && txIndex <=5) {
			if ( txout.scriptPubKey == burnfundScript ) {
				counterNodePayment ++;
			} else {
				for (auto& payee : vecPayees) {
					CAmount nMasternodePayment = GetMasternodePayment(nBlockHeight, payee.GetSinType());
					if (payee.GetPayee() == txout.scriptPubKey && (nMasternodePayment == txout.nValue || payee.GetVoteCount() >= (MNPAYMENTS_SIGNATURES_REQUIRED - 1))){
						LogPrintf("CMasternodeBlockPayees::IsTransactionValid -- Found required payment\n");
						counterNodePayment ++;
					}

					CTxDestination address1;
					ExtractDestination(payee.GetPayee(), address1);
					std::string address2 = EncodeDestination(address1);

					if(strPayeesPossible == "") {
						strPayeesPossible = strprintf("%s(%d)",address2, payee.GetSinType());
					} else {
						strPayeesPossible = strprintf("%s,%s(%d)",strPayeesPossible, address2, payee.GetSinType());
					}
				}
			}
			//extraction list 3 payment in Coinbase Tx
			CTxDestination addressTx1;
			ExtractDestination(txout.scriptPubKey, addressTx1);
			std::string addressTx2 = EncodeDestination(addressTx1);

			if(strPayeesInTx == "") {
				strPayeesInTx = addressTx2;
			} else {
				strPayeesInTx += "," + addressTx2;
			}
		}
	}
	LogPrintf("CMasternodeBlockPayees::IsTransactionValid -- 3 payments in coinbaseTx: %s\n", strPayeesInTx);
	if ( counterNodePayment == 3 ) {
		LogPrintf("CMasternodeBlockPayees::IsTransactionValid -- 3 payments are validated\n");
		return true;
	} else {
		LogPrintf("CMasternodeBlockPayees::IsTransactionValid -- ERROR: Missing required payment, possible payees: '%s'\n", strPayeesPossible);
		return false;
	}
}

std::string CMasternodeBlockPayees::GetRequiredPaymentsString()
{
    LOCK(cs_vecPayees);

    std::string strRequiredPayments = "Unknown";

    for (auto& payee : vecPayees)
    {
        CTxDestination address1;
        ExtractDestination(payee.GetPayee(), address1);
        std::string address2 = EncodeDestination(address1);

        if (strRequiredPayments != "Unknown") {
            strRequiredPayments += ", " + address2 + "(" + boost::lexical_cast<std::string>(payee.GetSinType()) + ")" + ":" + boost::lexical_cast<std::string>(payee.GetVoteCount());
        } else {
            strRequiredPayments = address2 + "(" + boost::lexical_cast<std::string>(payee.GetSinType()) + ")" + ":" + boost::lexical_cast<std::string>(payee.GetVoteCount());
        }
    }

    return strRequiredPayments;
}

std::string CMasternodePayments::GetRequiredPaymentsString(int nBlockHeight)
{
    LOCK(cs_mapMasternodeBlocks);

    if(mapMasternodeBlocks.count(nBlockHeight)){
        return mapMasternodeBlocks[nBlockHeight].GetRequiredPaymentsString();
    }

    return "Unknown";
}

bool CMasternodePayments::IsTransactionValid(const CTransactionRef txNew, int nBlockHeight)
{
    LOCK(cs_mapMasternodeBlocks);

    if(mapMasternodeBlocks.count(nBlockHeight)){
        return mapMasternodeBlocks[nBlockHeight].IsTransactionValid(txNew);
    }

    return true;
}

void CMasternodePayments::CheckAndRemove()
{
    if(!masternodeSync.IsBlockchainSynced()) return;

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    int nLimit = GetStorageLimit();

    std::map<uint256, CMasternodePaymentVote>::iterator it = mapMasternodePaymentVotes.begin();
    while(it != mapMasternodePaymentVotes.end()) {
        CMasternodePaymentVote vote = (*it).second;

        if(nCachedBlockHeight - vote.nBlockHeight > nLimit) {
            LogPrint(BCLog::MNPAYMENTS, "CMasternodePayments::CheckAndRemove -- Removing old Masternode payment: nBlockHeight=%d\n", vote.nBlockHeight);
            mapMasternodePaymentVotes.erase(it++);
            mapMasternodeBlocks.erase(vote.nBlockHeight);
        } else {
            ++it;
        }
    }
}

bool CMasternodePaymentVote::IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman)
{
    masternode_info_t mnInfo;

    if(!mnodeman.GetMasternodeInfo(vinMasternode.prevout, mnInfo)) {
        strError = strprintf("Unknown Masternode: prevout=%s", vinMasternode.prevout.ToStringShort());
        // Only ask if we are already synced and still have no idea about that Masternode
        if(masternodeSync.IsMasternodeListSynced()) {
            mnodeman.AskForMN(pnode, vinMasternode.prevout, connman);
        }

        return false;
    }

    int nMinRequiredProtocol;
    if(nBlockHeight >= nValidationHeight) {
        // new votes must comply SPORK_10_MASTERNODE_PAY_UPDATED_NODES rules
        nMinRequiredProtocol = mnpayments.GetMinMasternodePaymentsProto();
    } else {
        // allow non-updated masternodes for old blocks
        nMinRequiredProtocol = MIN_MASTERNODE_PAYMENT_PROTO_VERSION_1;
    }

    if(mnInfo.nProtocolVersion < nMinRequiredProtocol) {
        strError = strprintf("Masternode protocol is too old: nProtocolVersion=%d, nMinRequiredProtocol=%d", mnInfo.nProtocolVersion, nMinRequiredProtocol);
        return false;
    }

    // Only masternodes should try to check masternode rank for old votes - they need to pick the right winner for future blocks.
    // Regular clients (miners included) need to verify masternode rank for future block votes only.
    if(!fMasterNode && nBlockHeight < nValidationHeight) return true;

    int nRank;

    if(!mnodeman.GetMasternodeRank(vinMasternode.prevout, nRank, nBlockHeight - 101, nMinRequiredProtocol)) {
        LogPrint(BCLog::MNPAYMENTS, "CMasternodePaymentVote::IsValid -- Can't calculate rank for masternode %s\n",
                    vinMasternode.prevout.ToStringShort());
        return false;
    }

    if(nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        // It's common to have masternodes mistakenly think they are in the top 10
        // We don't want to print all of these messages in normal mode, debug mode should print though
        strError = strprintf("Masternode is not in the top %d (%d)", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        // Only ban for new mnw which is out of bounds, for old mnw MN list itself might be way too much off
        if(nRank > MNPAYMENTS_SIGNATURES_TOTAL*2 && nBlockHeight > nValidationHeight) {
            LOCK(cs_main);
            strError = strprintf("Masternode is not in the top %d (%d)", MNPAYMENTS_SIGNATURES_TOTAL*2, nRank);
            LogPrintf("CMasternodePaymentVote::IsValid -- Error: %s\n", strError);
            Misbehaving(pnode->GetId(), 20);
        }
        // Still invalid however
        return false;
    }

    return true;
}

CMasternode::SinType GetSinType(CAmount burnValue)
{

    if ((Params().GetConsensus().nMasternodeBurnSINNODE_1 - 1) * COIN < burnValue && burnValue <= Params().GetConsensus().nMasternodeBurnSINNODE_1 * COIN) {
        return CMasternode::SinType::SINNODE_1;
    }

    if ((Params().GetConsensus().nMasternodeBurnSINNODE_5 -1) * COIN < burnValue &&  burnValue <= Params().GetConsensus().nMasternodeBurnSINNODE_5 * COIN) {
        return CMasternode::SinType::SINNODE_5;
    }

    if ((Params().GetConsensus().nMasternodeBurnSINNODE_10 - 1) * COIN < burnValue && burnValue <= Params().GetConsensus().nMasternodeBurnSINNODE_10 * COIN) {
        return CMasternode::SinType::SINNODE_10;
    }

    return CMasternode::SinType::SINNODE_UNKNOWN;
}

bool CMasternodePayments::ProcessBlock(int nBlockHeight, CConnman& connman)
{
    // DETERMINE IF WE SHOULD BE VOTING FOR THE NEXT PAYEE

    if(fLiteMode || !fMasterNode) return false;

    // We have little chances to pick the right winner if winners list is out of sync
    // but we have no choice, so we'll try. However it doesn't make sense to even try to do so
    // if we have not enough data about masternodes.
    if(!masternodeSync.IsMasternodeListSynced()) return false;

    int nRank;

    if (!mnodeman.GetMasternodeRank(activeMasternode.outpoint, nRank, nBlockHeight - 101, GetMinMasternodePaymentsProto())) {
        LogPrint(BCLog::MNPAYMENTS, "CMasternodePayments::ProcessBlock -- Unknown Masternode\n");
        return false;
    }

    if (nRank > MNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint(BCLog::MNPAYMENTS, "CMasternodePayments::ProcessBlock -- Masternode not in the top %d (%d)\n", MNPAYMENTS_SIGNATURES_TOTAL, nRank);
        return false;
    }

    CAmount nBurnFundValue = 0;
    Coin coin;
    if(!GetUTXOCoin(activeMasternode.burntx, coin)) {
        nBurnFundValue = 0;
    } else {
        nBurnFundValue = coin.out.nValue;
    }
    CMasternode::SinType vSinType = GetSinType(nBurnFundValue); //find my sinType
    // LOCATE THE NEXT MASTERNODE WHICH SHOULD BE PAID
    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    int nCount = 0;
    masternode_info_t mnInfo;

    if (!mnodeman.GetNextMasternodeInQueueForPayment(nBlockHeight, true, nCount, mnInfo, vSinType)) { //vote for the same sintype
        LogPrintf("CMasternodePayments::ProcessBlock -- ERROR: Failed to find masternode to pay\n");
        return false;
    }

    CScript payee = GetScriptForDestination(mnInfo.pubKeyCollateralAddress.GetID());
    CMasternodePaymentVote voteNew(activeMasternode.outpoint, nBlockHeight, payee);

    // SIGN MESSAGE TO NETWORK WITH OUR MASTERNODE KEYS
    if (voteNew.Sign()) {
        if (AddPaymentVote(voteNew)) {
            voteNew.Relay(connman);
            return true;
        }
    }

    return false;
}

void CMasternodePayments::CheckPreviousBlockVotes(int nPrevBlockHeight)
{
    if (!masternodeSync.IsWinnersListSynced()) return;

    std::string debugStr;

    debugStr += strprintf("CMasternodePayments::CheckPreviousBlockVotes -- nPrevBlockHeight=%d, expected voting MNs:\n", nPrevBlockHeight);

    CMasternodeMan::rank_pair_vec_t mns;
    if (!mnodeman.GetMasternodeRanks(mns, nPrevBlockHeight - 101, GetMinMasternodePaymentsProto())) {
        debugStr += "CMasternodePayments::CheckPreviousBlockVotes -- GetMasternodeRanks failed\n";
        LogPrint(BCLog::MNPAYMENTS, "%s\n", debugStr);
        return;
    }

    LOCK2(cs_mapMasternodeBlocks, cs_mapMasternodePaymentVotes);

    bool voteForSinType1 = false;
    bool voteForSinType5 = false;
    bool voteForSinType10 = false;

    for (int i = 0; i < MNPAYMENTS_SIGNATURES_TOTAL && i < (int)mns.size(); i++) {
        auto mn = mns[i];
        CScript payee;
        bool found = false;
        int voteSinType = -1;

        if (mapMasternodeBlocks.count(nPrevBlockHeight)) {
            for (auto &p : mapMasternodeBlocks[nPrevBlockHeight].vecPayees) {
                for (auto &voteHash : p.GetVoteHashes()) {
                    if (!mapMasternodePaymentVotes.count(voteHash)) {
                        debugStr += strprintf("CMasternodePayments::CheckPreviousBlockVotes --   could not find vote %s\n",
                                              voteHash.ToString());
                        continue;
                    }
                    auto vote = mapMasternodePaymentVotes[voteHash];
                    if (vote.vinMasternode.prevout == mn.second.vin.prevout) {
                        payee = vote.payee;
                        voteSinType = p.GetSinType();
                        found = true;
                        if ( voteSinType == 1 ) voteForSinType1 = true;
                        if ( voteSinType == 5 ) voteForSinType5 = true;
                        if ( voteSinType == 10 ) voteForSinType10 = true;
                        break;
                    }
                }
            }
        }

        if (!found) {
            debugStr += strprintf("CMasternodePayments::CheckPreviousBlockVotes --   %s - no vote received\n",
                                  mn.second.vin.prevout.ToStringShort());
            mapMasternodesDidNotVote[mn.second.vin.prevout]++;
            continue;
        }

        CTxDestination address1;
        ExtractDestination(payee, address1);
        std::string address2 = EncodeDestination(address1);

        debugStr += strprintf("CMasternodePayments::CheckPreviousBlockVotes --   %s - voted for %s type %d\n",
                              mn.second.vin.prevout.ToStringShort(), address2, voteSinType);
    }

    if ( !voteForSinType1 || !voteForSinType5 || !voteForSinType10 )
    {
        debugStr += strprintf("CMasternodePayments::CheckPreviousBlockVotes --   +++++++++++ TRY TO GET NEW VOTE ++++++++\n");
    } else {
        debugStr += strprintf("CMasternodePayments::CheckPreviousBlockVotes --   +++++++++++ VOTE OK ++++++++\n");
    }

    debugStr += "CMasternodePayments::CheckPreviousBlockVotes -- Masternodes which missed a vote in the past:\n";
    for (auto it : mapMasternodesDidNotVote) {
        debugStr += strprintf("CMasternodePayments::CheckPreviousBlockVotes --   %s: %d\n", it.first.ToStringShort(), it.second);
    }

    LogPrint(BCLog::MNPAYMENTS, "Height: %d \n%s\n", nPrevBlockHeight, debugStr);
}

void CMasternodePaymentVote::Relay(CConnman& connman)
{
    // Do not relay until fully synced
    if(!masternodeSync.IsSynced()) {
        LogPrint(BCLog::MNPAYMENTS, "CMasternodePayments::Relay -- won't relay until fully synced\n");
        return;
    }

    CInv inv(MSG_MASTERNODE_PAYMENT_VOTE, GetHash());
    connman.RelayInv(inv);
}

bool CMasternodePaymentVote::CheckSignature(const CPubKey& pubKeyMasternode, int nValidationHeight, int &nDos)
{
    // do not ban by default
    nDos = 0;

    std::string strMessage = vinMasternode.prevout.ToStringShort() +
                boost::lexical_cast<std::string>(nBlockHeight) +
                ScriptToAsmStr(payee);

    std::string strError = "";
    if (!CMessageSigner::VerifyMessage(pubKeyMasternode, vchSig, strMessage, strError)) {
        // Only ban for future block vote when we are already synced.
        // Otherwise it could be the case when MN which signed this vote is using another key now
        // and we have no idea about the old one.
        if(masternodeSync.IsMasternodeListSynced() && nBlockHeight > nValidationHeight) {
            nDos = 20;
            return error("CMasternodePaymentVote::CheckSignature -- Got bad Masternode payment signature, masternode=%s, error: %s", vinMasternode.prevout.ToStringShort().c_str(), strError);
        }
    }

    return true;
}

std::string CMasternodePaymentVote::ToString() const
{
    std::ostringstream info;

    info << vinMasternode.prevout.ToStringShort() <<
            ", " << nBlockHeight <<
            ", " << ScriptToAsmStr(payee) <<
            ", " << (int)vchSig.size();

    return info.str();
}

// Send only votes for future blocks, node should request every other missing payment block individually
void CMasternodePayments::Sync(CNode* pnode, CConnman& connman)
{
    LOCK(cs_mapMasternodeBlocks);

    if(!masternodeSync.IsWinnersListSynced()) return;

    int nInvCount = 0;

    for (int h = nCachedBlockHeight; h < nCachedBlockHeight + 20; h++) {
        if(mapMasternodeBlocks.count(h)) {
            for (auto& payee : mapMasternodeBlocks[h].vecPayees) {
                std::vector<uint256> vecVoteHashes = payee.GetVoteHashes();
                for (auto& hash : vecVoteHashes) {
                    if(!HasVerifiedPaymentVote(hash)) continue;
                    pnode->PushInventory(CInv(MSG_MASTERNODE_PAYMENT_VOTE, hash));
                    nInvCount++;
                }
            }
        }
    }

    LogPrintf("CMasternodePayments::Sync -- Sent %d votes to peer %d\n", nInvCount, pnode->GetId());
    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::SYNCSTATUSCOUNT, MASTERNODE_SYNC_MNW, nInvCount));
}

// Request low data/unknown payment blocks in batches directly from some node instead of/after preliminary Sync.
void CMasternodePayments::RequestLowDataPaymentBlocks(CNode* pnode, CConnman& connman)
{
    if(!masternodeSync.IsMasternodeListSynced()) return;

    LOCK2(cs_main, cs_mapMasternodeBlocks);

    std::vector<CInv> vToFetch;
    int nLimit = GetStorageLimit();

    const CBlockIndex *pindex = chainActive.Tip();

    while(nCachedBlockHeight - pindex->nHeight < nLimit) {
        if(!mapMasternodeBlocks.count(pindex->nHeight)) {
            // We have no idea about this block height, let's ask
            vToFetch.push_back(CInv(MSG_MASTERNODE_PAYMENT_BLOCK, pindex->GetBlockHash()));
            // We should not violate GETDATA rules
            if(vToFetch.size() == MAX_INV_SZ) {
                LogPrintf("CMasternodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d blocks\n", pnode->GetId(), MAX_INV_SZ);
                connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::GETDATA, vToFetch));
                // Start filling new batch
                vToFetch.clear();
            }
        }
        if(!pindex->pprev) break;
        pindex = pindex->pprev;
    }

    std::map<int, CMasternodeBlockPayees>::iterator it = mapMasternodeBlocks.begin();

    while(it != mapMasternodeBlocks.end()) {
        int nTotalVotes = 0;
        bool fFound = false;
        for (auto& payee : it->second.vecPayees) {
            if(payee.GetVoteCount() >= MNPAYMENTS_SIGNATURES_REQUIRED) {
                fFound = true;
                break;
            }
            nTotalVotes += payee.GetVoteCount();
        }
        // A clear winner (MNPAYMENTS_SIGNATURES_REQUIRED+ votes) was found
        // or no clear winner was found but there are at least avg number of votes
        if(fFound || nTotalVotes >= (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED)/2) {
            // so just move to the next block
            ++it;
            continue;
        }
        // DEBUG
        DBG (
            // Let's see why this failed
            for (auto& payee : it->second.vecPayees) {
                CTxDestination address1;
                ExtractDestination(payee.GetPayee(), address1);
                CBitcoinAddress address2(address1);
                printf("payee %s votes %d\n", address2.ToString().c_str(), payee.GetVoteCount());
            }
            printf("block %d votes total %d\n", it->first, nTotalVotes);
        )
        // END DEBUG
        // Low data block found, let's try to sync it
        uint256 hash;
        if(GetBlockHash(hash, it->first)) {
            vToFetch.push_back(CInv(MSG_MASTERNODE_PAYMENT_BLOCK, hash));
        }
        // We should not violate GETDATA rules
        if(vToFetch.size() == MAX_INV_SZ) {
            LogPrintf("CMasternodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d payment blocks\n", pnode->GetId(), MAX_INV_SZ);
            connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::GETDATA, vToFetch));
            // Start filling new batch
            vToFetch.clear();
        }
        ++it;
    }
    // Ask for the rest of it
    if(!vToFetch.empty()) {
        LogPrintf("CMasternodePayments::SyncLowDataPaymentBlocks -- asking peer %d for %d payment blocks\n", pnode->GetId(), vToFetch.size());
        connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::GETDATA, vToFetch));
    }
}

std::string CMasternodePayments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << (int)mapMasternodePaymentVotes.size() <<
            ", Blocks: " << (int)mapMasternodeBlocks.size();

    return info.str();
}

bool CMasternodePayments::IsEnoughData()
{
    float nAverageVotes = (MNPAYMENTS_SIGNATURES_TOTAL + MNPAYMENTS_SIGNATURES_REQUIRED) / 2;
    int nStorageLimit = GetStorageLimit();
    return GetBlockCount() > nStorageLimit && GetVoteCount() > nStorageLimit * nAverageVotes;
}

int CMasternodePayments::GetStorageLimit()
{
    return std::max(int(mnodeman.size() * nStorageCoeff), nMinBlocksToStore);
}

void CMasternodePayments::UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman)
{
    if(!pindex) return;

    nCachedBlockHeight = pindex->nHeight;
    LogPrint(BCLog::MNPAYMENTS, "CMasternodePayments::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);

    int nFutureBlock = nCachedBlockHeight + 10;

    CheckPreviousBlockVotes(nFutureBlock - 1);
    ProcessBlock(nFutureBlock, connman);
}
