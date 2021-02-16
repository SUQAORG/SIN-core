// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <infinitynodelockreward.h>
#include <infinitynodeman.h>
#include <infinitynodepeer.h>
#include <infinitynodemeta.h>
#include <messagesigner.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <utilstrencodings.h>

#include <secp256k1.h>
#include <secp256k1_schnorr.h>
#include <secp256k1_musig.h>
#include <base58.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <consensus/validation.h>
#include <wallet/coincontrol.h>
#include <utilmoneystr.h>
#include <core_io.h>

#include <boost/lexical_cast.hpp>

/** Object for who's going to get paid on which blocks */
CInfinityNodeLockReward inflockreward;

namespace
{
/* Global secp256k1_context object used for verification. */
secp256k1_context* secp256k1_context_musig = nullptr;
} // namespace

/*************************************************************/
/***** CLockRewardRequest ************************************/
/*************************************************************/
CLockRewardRequest::CLockRewardRequest()
{}

CLockRewardRequest::CLockRewardRequest(int Height, COutPoint outpoint, int sintype, int loop){
    nRewardHeight = Height;
    burnTxIn = CTxIn(outpoint);
    nSINtype = sintype;
    nLoop = loop;
}

bool CLockRewardRequest::Sign(const CKey& keyInfinitynode, const CPubKey& pubKeyInfinitynode)
{
    std::string strError;
    std::string strSignMessage;

    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + burnTxIn.ToString()
                             + boost::lexical_cast<std::string>(nSINtype)
                             + boost::lexical_cast<std::string>(nLoop);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keyInfinitynode)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardRequest::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardRequest::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CLockRewardRequest::CheckSignature(CPubKey& pubKeyInfinitynode, int &nDos) const
{
    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + burnTxIn.ToString()
                             + boost::lexical_cast<std::string>(nSINtype)
                             + boost::lexical_cast<std::string>(nLoop);
    std::string strError = "";

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardRequest::CheckSignature -- Got bad Infinitynode LockReward signature, ID=%s, error: %s\n", 
                    burnTxIn.prevout.ToStringShort(), strError);
        nDos = 20;
        return false;
    }
    return true;
}

bool CLockRewardRequest::IsValid(CNode* pnode, int nValidationHeight, std::string& strError, CConnman& connman) const
{
    CInfinitynode inf;
    LOCK(infnodeman.cs);
    if(!infnodeman.deterministicRewardAtHeight(nRewardHeight, nSINtype, inf)){
        strError = strprintf("Cannot find candidate for Height of LockRequest: %d and SINtype: %d\n", nRewardHeight, nSINtype);
        return false;
    }

    if(inf.vinBurnFund != burnTxIn){
        strError = strprintf("Node %s is not a Candidate for height: %d, SIN type: %d\n", burnTxIn.prevout.ToStringShort(), nRewardHeight, nSINtype);
        return false;
    }

    int nDos = 0;
    CMetadata meta = infnodemeta.Find(inf.getMetaID());
    if(meta.getMetadataHeight() == 0){
        strError = strprintf("Metadata of my peer is not found: %d\n", inf.getMetaID());
        return false;
    }
    //dont check nHeight of metadata here. Candidate can be paid event the metadata is not ready for Musig. Because his signature is not onchain

    std::string metaPublicKey = meta.getMetaPublicKey();
    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
    CPubKey pubKey(tx_data.begin(), tx_data.end());

    if(!CheckSignature(pubKey, nDos)){
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), nDos);
        strError = strprintf("ERROR: invalid signature of Infinitynode: %s, MetadataID: %s,  PublicKey: %s\n", 
            burnTxIn.prevout.ToStringShort(), inf.getMetaID(), metaPublicKey);

        return false;
    }

    return true;
}

void CLockRewardRequest::Relay(CConnman& connman)
{

    CInv inv(MSG_LOCKREWARD_INIT, GetHash());
    connman.RelayInv(inv);
}

/*************************************************************/
/***** CLockRewardCommitment *********************************/
/*************************************************************/
CLockRewardCommitment::CLockRewardCommitment()
{}

CLockRewardCommitment::CLockRewardCommitment(uint256 nRequest, int inHeight, COutPoint myPeerBurnTxIn, CKey key){
    vin=(CTxIn(myPeerBurnTxIn));
    random = key;
    pubkeyR = key.GetPubKey();
    nHashRequest = nRequest;
    nRewardHeight = inHeight;
}

bool CLockRewardCommitment::Sign(const CKey& keyInfinitynode, const CPubKey& pubKeyInfinitynode)
{
    std::string strError;
    std::string strSignMessage;

    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + nHashRequest.ToString() + vin.prevout.ToString();

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keyInfinitynode)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardCommitment::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardCommitment::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CLockRewardCommitment::CheckSignature(CPubKey& pubKeyInfinitynode, int &nDos)
{
    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + nHashRequest.ToString() + vin.prevout.ToString();
    std::string strError = "";

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardCommitment::CheckSignature -- Got bad Infinitynode LockReward signature, error: %s\n", strError);
        nDos = 10;
        return false;
    }
    return true;
}

void CLockRewardCommitment::Relay(CConnman& connman)
{

    CInv inv(MSG_INFCOMMITMENT, GetHash());
    connman.RelayInv(inv);
}

/*************************************************************/
/***** CGroupSigners         *********************************/
/*************************************************************/
CGroupSigners::CGroupSigners()
{}

CGroupSigners::CGroupSigners(COutPoint myPeerBurnTxIn, uint256 nRequest, int group, int inHeight, std::string signers){
    vin=(CTxIn(myPeerBurnTxIn));
    nHashRequest = nRequest;
    nGroup = group;
    signersId = signers;
    nRewardHeight = inHeight;
}

bool CGroupSigners::Sign(const CKey& keyInfinitynode, const CPubKey& pubKeyInfinitynode)
{
    std::string strError;
    std::string strSignMessage;

    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + nHashRequest.ToString() + vin.prevout.ToString()
                             + signersId + boost::lexical_cast<std::string>(nGroup);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keyInfinitynode)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardCommitment::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CLockRewardCommitment::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CGroupSigners::CheckSignature(CPubKey& pubKeyInfinitynode, int &nDos)
{
    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + nHashRequest.ToString() + vin.prevout.ToString()
                             + signersId + boost::lexical_cast<std::string>(nGroup);
    std::string strError = "";

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CGroupSigners::CheckSignature -- Got bad Infinitynode CGroupSigners signature, error: %s\n", strError);
        nDos = 10;
        return false;
    }
    return true;
}

void CGroupSigners::Relay(CConnman& connman)
{

    CInv inv(MSG_INFLRGROUP, GetHash());
    connman.RelayInv(inv);
}

/*************************************************************/
/***** CMusigPartialSignLR   *********************************/
/*************************************************************/
CMusigPartialSignLR::CMusigPartialSignLR()
{}

CMusigPartialSignLR::CMusigPartialSignLR(COutPoint myPeerBurnTxIn, uint256 nGroupSigners, int inHeight, unsigned char *cMusigPartialSign){
    vin=(CTxIn(myPeerBurnTxIn));
    nHashGroupSigners = nGroupSigners;
    vchMusigPartialSign = std::vector<unsigned char>(cMusigPartialSign, cMusigPartialSign + 32);
    nRewardHeight = inHeight;
}

bool CMusigPartialSignLR::Sign(const CKey& keyInfinitynode, const CPubKey& pubKeyInfinitynode)
{
    std::string strError;
    std::string strSignMessage;

    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + nHashGroupSigners.ToString() + vin.prevout.ToString()
                             + EncodeBase58(vchMusigPartialSign);

    if(!CMessageSigner::SignMessage(strMessage, vchSig, keyInfinitynode)) {
        LogPrint(BCLog::INFINITYLOCK,"CMusigPartialSignLR::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CMusigPartialSignLR::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CMusigPartialSignLR::CheckSignature(CPubKey& pubKeyInfinitynode, int &nDos)
{
    std::string strMessage = boost::lexical_cast<std::string>(nRewardHeight) + nHashGroupSigners.ToString() + vin.prevout.ToString()
                             + EncodeBase58(vchMusigPartialSign);
    std::string strError = "";

    if(!CMessageSigner::VerifyMessage(pubKeyInfinitynode, vchSig, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CMusigPartialSignLR::CheckSignature -- Got bad Infinitynode CGroupSigners signature, error: %s\n", strError);
        nDos = 10;
        return false;
    }
    return true;
}

void CMusigPartialSignLR::Relay(CConnman& connman)
{

    CInv inv(MSG_INFLRMUSIG, GetHash());
    connman.RelayInv(inv);
}
/*************************************************************/
/***** CInfinityNodeLockReward *******************************/
/*************************************************************/
void CInfinityNodeLockReward::Clear()
{
    LOCK(cs);
    mapLockRewardRequest.clear();
    mapLockRewardCommitment.clear();
    mapLockRewardGroupSigners.clear();
    mapSigners.clear();
    mapPartialSign.clear();
}

bool CInfinityNodeLockReward::AlreadyHave(const uint256& hash)
{
    LOCK(cs);
    return mapLockRewardRequest.count(hash) ||
           mapLockRewardCommitment.count(hash) ||
           mapLockRewardGroupSigners.count(hash) ||
           mapPartialSign.count(hash)
           ;
}

bool CInfinityNodeLockReward::AddLockRewardRequest(const CLockRewardRequest& lockRewardRequest)
{
    AssertLockHeld(cs);
    //if we hash this request => don't add it
    if(mapLockRewardRequest.count(lockRewardRequest.GetHash())) return false;
    if(lockRewardRequest.nLoop == 0){
        mapLockRewardRequest.insert(make_pair(lockRewardRequest.GetHash(), lockRewardRequest));
    } else if (lockRewardRequest.nLoop > 0){
        //new request from candidate, so remove old requrest
        RemoveLockRewardRequest(lockRewardRequest);
        mapLockRewardRequest.insert(make_pair(lockRewardRequest.GetHash(), lockRewardRequest));
    }
    return true;
}

bool CInfinityNodeLockReward::GetLockRewardRequest(const uint256& reqHash, CLockRewardRequest& lockRewardRequestRet)
{
    LOCK(cs);
    std::map<uint256, CLockRewardRequest>::iterator it = mapLockRewardRequest.find(reqHash);
    if(it == mapLockRewardRequest.end()) return false;
    lockRewardRequestRet = it->second;
    return true;
}

void CInfinityNodeLockReward::RemoveLockRewardRequest(const CLockRewardRequest& lockRewardRequest)
{
    AssertLockHeld(cs);

    std::map<uint256, CLockRewardRequest>::iterator itRequest = mapLockRewardRequest.begin();
    while(itRequest != mapLockRewardRequest.end()) {
        if(itRequest->second.nRewardHeight == lockRewardRequest.nRewardHeight
            && itRequest->second.burnTxIn == lockRewardRequest.burnTxIn
            && itRequest->second.nSINtype == lockRewardRequest.nSINtype
            && itRequest->second.nLoop < lockRewardRequest.nLoop)
        {
            mapLockRewardRequest.erase(itRequest++);
        }else{
            ++itRequest;
        }
    }
}

bool CInfinityNodeLockReward::AddCommitment(const CLockRewardCommitment& commitment)
{
    AssertLockHeld(cs);

    if(mapLockRewardCommitment.count(commitment.GetHash())) return false;
        mapLockRewardCommitment.insert(make_pair(commitment.GetHash(), commitment));
    return true;
}

bool CInfinityNodeLockReward::GetLockRewardCommitment(const uint256& reqHash, CLockRewardCommitment& commitmentRet)
{
    LOCK(cs);
    std::map<uint256, CLockRewardCommitment>::iterator it = mapLockRewardCommitment.find(reqHash);
    if(it == mapLockRewardCommitment.end()) return false;
    commitmentRet = it->second;
    return true;
}

bool CInfinityNodeLockReward::AddGroupSigners(const CGroupSigners& gs)
{
    AssertLockHeld(cs);

    if(mapLockRewardGroupSigners.count(gs.GetHash())) return false;
        mapLockRewardGroupSigners.insert(make_pair(gs.GetHash(), gs));
    return true;
}

bool CInfinityNodeLockReward::GetGroupSigners(const uint256& reqHash, CGroupSigners& gSigners)
{
    LOCK(cs);
    std::map<uint256, CGroupSigners>::iterator it = mapLockRewardGroupSigners.find(reqHash);
    if(it == mapLockRewardGroupSigners.end()) return false;
    gSigners = it->second;
    return true;
}

bool CInfinityNodeLockReward::AddMusigPartialSignLR(const CMusigPartialSignLR& ps)
{
    AssertLockHeld(cs);

    if(mapPartialSign.count(ps.GetHash())) {
        return false;
    }
    mapPartialSign.insert(make_pair(ps.GetHash(), ps));
    
    return true;
}

bool CInfinityNodeLockReward::GetMusigPartialSignLR(const uint256& psHash, CMusigPartialSignLR& ps)
{
    LOCK(cs);
    std::map<uint256, CMusigPartialSignLR>::iterator it = mapPartialSign.find(psHash);
    if(it == mapPartialSign.end()) return false;
    ps = it->second;
    return true;
}

/*
 * STEP 1: get a new LockRewardRequest, check it and send verify message
 *
 * STEP 1.1 check LockRewardRequest is valid or NOT
 * - the nHeight of request cannot be lower than current height
 * - the nHeight of request cannot so far in future ( currentHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth + 2)
 * - the LockRewardRequest must be valid
 *   + from (nHeight, SINtype) => find candidate => candidate is not expired at height of reward
 *   + CTxIn of request and CTxIn of candidate must be identical
 *   + Find publicKey of Candidate in metadata and check the signature in request
 */
bool CInfinityNodeLockReward::CheckLockRewardRequest(CNode* pfrom, const CLockRewardRequest& lockRewardRequestRet, CConnman& connman, int nBlockHeight)
{
    AssertLockHeld(cs);
    //not too far in future and not inferior than current Height
    if(lockRewardRequestRet.nRewardHeight > nBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth + 2
        || lockRewardRequestRet.nRewardHeight < nBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRequest -- LockRewardRequest for invalid height: %d, current height: %d\n",
            lockRewardRequestRet.nRewardHeight, nBlockHeight);
        return false;
    }

    std::string strError = "";
    if(!lockRewardRequestRet.IsValid(pfrom, nBlockHeight, strError, connman)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRequest -- LockRewardRequest is invalid. ERROR: %s\n",strError);
        return false;
    }

    return true;
}

/*
 * STEP 1: new LockRewardRequest is OK, check mypeer is a TopNode for LockRewardRequest
 *
 * STEP 1.2 send VerifyRequest
 */

bool CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest(CNode* pfrom, const CLockRewardRequest& lockRewardRequestRet, CConnman& connman)
{
    // only Infinitynode will answer the verify LockRewardCandidate
    if(fLiteMode || !fInfinityNode) {return false;}

    AssertLockHeld(cs);

    //1.2.3 verify LockRequest
    //get InfCandidate from request. In fact, this step can not false because it is checked in CheckLockRewardRequest
    CInfinitynode infCandidate;
    if(!infnodeman.Get(lockRewardRequestRet.burnTxIn.prevout, infCandidate)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Cannot identify candidate in list\n");
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 20);
        return false;
    }

    //LockRewardRequest of expired candidate is relayed => ban it
    if(infCandidate.getExpireHeight() < lockRewardRequestRet.nRewardHeight || infCandidate.getExpireHeight() < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Candidate is expired\n", infCandidate.getBurntxOutPoint().ToStringShort());
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 10);
        return false;
    }

    CMetadata metaCandidate = infnodemeta.Find(infCandidate.getMetaID());
    if(metaCandidate.getMetadataHeight() == 0){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Cannot get metadata of candidate %s\n", infCandidate.getBurntxOutPoint().ToStringShort());
        return false;
    }

    if(lockRewardRequestRet.nRewardHeight < metaCandidate.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
        int nWait = metaCandidate.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - lockRewardRequestRet.nRewardHeight;
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- metadata is not ready for Musig(wait %d blocks).\n", nWait);
        return false;
    }

    //step 1.2.1: chech if mypeer is good candidate to make Musig
    CInfinitynode infRet;
    if(!infnodeman.Get(infinitynodePeer.burntx, infRet)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Cannot identify mypeer in list: %s\n", infinitynodePeer.burntx.ToStringShort());
        return false;
    }

    int nScore;
    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType; //mypeer must be this SINtype, if not, score is NULL

    if(!infnodeman.getNodeScoreAtHeight(infinitynodePeer.burntx, nSINtypeCanLockReward, lockRewardRequestRet.nRewardHeight - 101, nScore)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Can't calculate score for Infinitynode %s\n",
                    infinitynodePeer.burntx.ToStringShort());
        return false;
    }

    //step 1.2.2: if my score is in Top, i will verify that candidate is online at IP
    //Iam in TopNode => im not expire at Height
    if(nScore <= Params().GetConsensus().nInfinityNodeLockRewardTop) {
        //step 2.1: verify node which send the request is online at IP in metadata
        //SendVerifyRequest()
        //step 2.2: send commitment
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Iam in TopNode. Sending a VerifyRequest to candidate\n");
    } else {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Iam NOT in TopNode. Do nothing!\n");
        return false;
    }

    //1.2.4 check if Ive connected to candidate or not
    std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();
    CService addr = metaCandidate.getService();
    CAddress add = CAddress(addr, NODE_NETWORK);

    bool fconnected = false;
    std::string connectionType = "";
    CNode* pnodeCandidate = NULL;

    for (auto* pnode : vNodesCopy)
    {
        if (pnode->addr.ToStringIP() == add.ToStringIP()){
            fconnected = true;
            pnodeCandidate = pnode;
            connectionType = "exist connection";
        }
    }
    // looped through all nodes, release them
    connman.ReleaseNodeVector(vNodesCopy);

    if(!fconnected){
        CNode* pnode = connman.OpenNetworkConnection(add, false, nullptr, NULL, false, false, false, true);
        if(pnode == NULL) {
            //TODO: dont send commitment when we can not verify node
            //we comeback in next version
            //LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- can't connect to node to verify it, addr=%s\n", addr.ToString());
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- can't connect to node to verify it, addr=%s. Relay commitment!\n", addr.ToString());
            int nRewardHeight = lockRewardRequestRet.nRewardHeight;
            uint256 hashLR = lockRewardRequestRet.GetHash();
            //step 3.3 send commitment
            if(!SendCommitment(hashLR, nRewardHeight, connman)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- Cannot send commitment\n");
                return false;
            }
            //return here and ignore all line bellow because pnode is NULL
            return true;
        }
        fconnected = true;
        pnodeCandidate = pnode;
        connectionType = "direct connection";
    }

    //step 1.2.5 send VerifyRequest.
    // for some reason, IP of candidate is not good in metadata => just return false and dont ban this node
    CVerifyRequest vrequest(addr, infinitynodePeer.burntx, lockRewardRequestRet.burnTxIn.prevout,
                            lockRewardRequestRet.nRewardHeight, lockRewardRequestRet.GetHash());

    std::string strMessage = strprintf("%s%s%d%s", infinitynodePeer.burntx.ToString(), lockRewardRequestRet.burnTxIn.prevout.ToString(),
                                       vrequest.nBlockHeight, lockRewardRequestRet.GetHash().ToString());

    if(!CMessageSigner::SignMessage(strMessage, vrequest.vchSig1, infinitynodePeer.keyInfinitynode)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- SignMessage() failed\n");
        return false;
    }

    std::string strError;

    if(!CMessageSigner::VerifyMessage(infinitynodePeer.pubKeyInfinitynode, vrequest.vchSig1, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    //1.2.6 send verify request
    //connection can be openned but, immediately close because full slot by client.
    //so, we need to check version to make sure that connection is OK
    if(fconnected && pnodeCandidate->GetSendVersion() >= MIN_INFINITYNODE_PAYMENT_PROTO_VERSION){
    //if(fconnected) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- verifying node use %s nVersion: %d, addr=%s, Sig1 :%d\n",
                    connectionType, pnodeCandidate->GetSendVersion(), addr.ToString(), vrequest.vchSig1.size());
        connman.PushMessage(pnodeCandidate, CNetMsgMaker(pnodeCandidate->GetSendVersion()).Make(NetMsgType::INFVERIFY, vrequest));
    } else {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- cannot connect to candidate: %d, node version: %d\n",
                   fconnected, pnodeCandidate->GetSendVersion());
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- TODO: we can add CVerifyRequest in vector and try again later.\n");
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- TODO: But probably that candidate is disconnected in network.\n");
    }

    return true;
}

/*
 * STEP 2: I am candidate and i get a VerifyRequest message, check and try to answer the message'owner
 *
 * check:
 * - VerifyRequest was sent from Top Node
 * - Signature of VerifyRequest is correct
 * answer:
 * - create the 2nd signature - my signature and send back to node
 * processVerifyRequestReply:
 * - check 2nd signature
 */
//TODO: ban pnode if false
bool CInfinityNodeLockReward::SendVerifyReply(CNode* pnode, CVerifyRequest& vrequest, CConnman& connman)
{
    // only Infinitynode will answer the verify requrest
    if(fLiteMode || !fInfinityNode) {return false;}

    AssertLockHeld(cs);

    //step 2.0 get publicKey of sender and check signature
    //not too far in future and not inferior than current Height
    if(vrequest.nBlockHeight > nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth + 2
        || vrequest.nBlockHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- VerifyRequest for invalid height: %d, current height: %d\n",
            vrequest.nBlockHeight, nCachedBlockHeight);
        return false;
    }

    infinitynode_info_t infoInf;
    if(!infnodeman.GetInfinitynodeInfo(vrequest.vin1.prevout, infoInf)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- Cannot find sender from list %s\n");
        //someone try to send a VerifyRequest to me but not in DIN => so ban it
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    if(infoInf.nExpireHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- VerifyRequest was sent from expired node. Ban it!\n", vrequest.vin1.prevout.ToStringShort());
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 10);
        return false;
    }

    CMetadata metaSender = infnodemeta.Find(infoInf.metadataID);
    if (metaSender.getMetadataHeight() == 0){
        //for some reason, metadata is not updated, do nothing
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- Cannot find sender from list %s\n");
        return false;
    }

    if(vrequest.nBlockHeight < metaSender.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
        int nWait = metaSender.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - vrequest.nBlockHeight;
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- metadata of sender is not ready for Musig (wait %d blocks).\n", nWait);
        return false;
    }

    std::string metaPublicKey = metaSender.getMetaPublicKey();
    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
    CPubKey pubKey(tx_data.begin(), tx_data.end());

    std::string strError;
    std::string strMessage = strprintf("%s%s%d%s", vrequest.vin1.prevout.ToString(), vrequest.vin2.prevout.ToString(),
                                       vrequest.nBlockHeight, vrequest.nHashRequest.ToString());
    if(!CMessageSigner::VerifyMessage(pubKey, vrequest.vchSig1, strMessage, strError)) {
        //sender is in DIN and metadata is correct but sign is KO => so ban it
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- VerifyMessage() failed, error: %s, message: \n", strError, strMessage);
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    //step 2.1 check if sender in Top and SINtype = nInfinityNodeLockRewardSINType (skip this step for now)
    int nScore;
    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType; //mypeer must be this SINtype, if not, score is NULL

    if(!infnodeman.getNodeScoreAtHeight(vrequest.vin1.prevout, nSINtypeCanLockReward, vrequest.nBlockHeight - 101, nScore)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- Can't calculate score for Infinitynode %s\n",
                    infinitynodePeer.burntx.ToStringShort());
        return false;
    }

    //sender in TopNode => he is not expired at Height
    if(nScore <= Params().GetConsensus().nInfinityNodeLockRewardTop) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- Someone in TopNode send me a VerifyRequest. Answer him now...\n");
    } else {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- Someone NOT in TopNode send me a VerifyRequest. Banned!\n");
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 10);
        return false;
    }

    //step 2.2 sign a new message and send it back to sender
    vrequest.addr = infinitynodePeer.service;
    std::string strMessage2 = strprintf("%s%d%s%s%s", vrequest.addr.ToString(false), vrequest.nBlockHeight, vrequest.nHashRequest.ToString(),
        vrequest.vin1.prevout.ToStringShort(), vrequest.vin2.prevout.ToStringShort());

    if(!CMessageSigner::SignMessage(strMessage2, vrequest.vchSig2, infinitynodePeer.keyInfinitynode)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- SignMessage() failed\n");
        return false;
    }

    if(!CMessageSigner::VerifyMessage(infinitynodePeer.pubKeyInfinitynode, vrequest.vchSig2, strMessage2, strError)) {
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendVerifyReply -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    connman.PushMessage(pnode, CNetMsgMaker(pnode->GetSendVersion()).Make(NetMsgType::INFVERIFY, vrequest));
    return true;
}

/*
 * STEP 3: check return VerifyRequest, if it is OK then
 * - send the commitment
 * - disconect node
 */
bool CInfinityNodeLockReward::CheckVerifyReply(CNode* pnode, CVerifyRequest& vrequest, CConnman& connman)
{
    // only Infinitynode will answer the verify requrest
    if(fLiteMode || !fInfinityNode) {return false;}

    AssertLockHeld(cs);

    //not too far in future and not inferior than current Height
    if(vrequest.nBlockHeight > nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth + 2
        || vrequest.nBlockHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckVerifyReply -- VerifyRequest for invalid height: %d, current height: %d\n",
            vrequest.nBlockHeight, nCachedBlockHeight);
        return false;
    }

    //step 3.1 Sig1 from me => grant that request is good. Dont need to check other info or ban bad node
    std::string strMessage = strprintf("%s%s%d%s", infinitynodePeer.burntx.ToString(), vrequest.vin2.prevout.ToString(), vrequest.nBlockHeight, vrequest.nHashRequest.ToString());
    std::string strError;
    if(!CMessageSigner::VerifyMessage(infinitynodePeer.pubKeyInfinitynode, vrequest.vchSig1, strMessage, strError)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckVerifyReply -- VerifyMessage(Sig1) failed, error: %s\n", strError);
        return false;
    }

    //step 3.2 Sig2 from Candidate
    std::string strMessage2 = strprintf("%s%d%s%s%s", vrequest.addr.ToString(false), vrequest.nBlockHeight, vrequest.nHashRequest.ToString(),
        vrequest.vin1.prevout.ToStringShort(), vrequest.vin2.prevout.ToStringShort());

    infinitynode_info_t infoInf;
    if(!infnodeman.GetInfinitynodeInfo(vrequest.vin2.prevout, infoInf)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckVerifyReply -- Cannot find sender from list %s\n");
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    CMetadata metaCandidate = infnodemeta.Find(infoInf.metadataID);
    if (metaCandidate.getMetadataHeight() == 0){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckVerifyReply -- Cannot find sender from list %s\n");
        return false;
    }
    //dont check nHeight of metadata here. Candidate can be paid event the metadata is not ready for Musig. Because his signature is not onchain

    std::string metaPublicKey = metaCandidate.getMetaPublicKey();
    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
    CPubKey pubKey(tx_data.begin(), tx_data.end());

    if(!CMessageSigner::VerifyMessage(pubKey, vrequest.vchSig2, strMessage2, strError)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckVerifyReply -- VerifyMessage(Sig2) failed, error: %s\n", strError);
        return false;
    }

    int nRewardHeight = vrequest.nBlockHeight;
    //step 3.3 send commitment
    if(!SendCommitment(vrequest.nHashRequest, nRewardHeight, connman)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckVerifyReply -- Cannot send commitment\n");
        return false;
    }

    return true;
}

/*
 * STEP 4: Commitment
 *
 * STEP 4.1 create/send/relay commitment
 * control if i am candidate and how many commitment receive to decide MuSig workers
 */
bool CInfinityNodeLockReward::SendCommitment(const uint256& reqHash, int nRewardHeight, CConnman& connman)
{
    if(fLiteMode || !fInfinityNode) return false;

    AssertLockHeld(cs);

    CKey secret;
    secret.MakeNewKey(true);

    CLockRewardCommitment commitment(reqHash, nRewardHeight, infinitynodePeer.burntx, secret);
    if(commitment.Sign(infinitynodePeer.keyInfinitynode, infinitynodePeer.pubKeyInfinitynode)) {
        if(AddCommitment(commitment)){
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::SendCommitment -- Send my commitment %s for height %d, LockRequest %s\n",
                      commitment.GetHash().ToString(), commitment.nRewardHeight, reqHash.ToString());
            commitment.Relay(connman);
            return true;
        }
    }
    return false;
}

/*
 * STEP 4: Commitment
 *
 * STEP 4.2 check commitment
 * check:
 *   - from Topnode, for good rewardHeight, signer from DIN
 */
bool CInfinityNodeLockReward::CheckCommitment(CNode* pnode, const CLockRewardCommitment& commitment)
{
    if(fLiteMode || !fInfinityNode) return false;

    AssertLockHeld(cs);

    //not too far in future and not inferior than current Height
    if(commitment.nRewardHeight > nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth + 2
        || commitment.nRewardHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- commitment invalid for height: %d, current height: %d\n",
            commitment.nRewardHeight, nCachedBlockHeight);
        return false;
    }


    infinitynode_info_t infoInf;
    if(!infnodeman.GetInfinitynodeInfo(commitment.vin.prevout, infoInf)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- Cannot find sender from list %s\n");
        //someone try to send a VerifyRequest to me but not in DIN => so ban it
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    if(infoInf.nExpireHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- VerifyRequest was sent from expired node. Ban it!\n", commitment.vin.prevout.ToStringShort());
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 10);
        return false;
    }

    CMetadata metaSender = infnodemeta.Find(infoInf.metadataID);
    if (metaSender.getMetadataHeight() == 0){
        //for some reason, metadata is not updated, do nothing
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- Cannot find sender from list %s\n");
        return false;
    }

    if(commitment.nRewardHeight < metaSender.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
        int nWait = metaSender.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - commitment.nRewardHeight;
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- metadata of sender is not ready for Musig (wait %d blocks).\n", nWait);
        return false;
    }

    std::string metaPublicKey = metaSender.getMetaPublicKey();
    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
    CPubKey pubKey(tx_data.begin(), tx_data.end());

    std::string strError;
    std::string strMessage = strprintf("%d%s%s", commitment.nRewardHeight, commitment.nHashRequest.ToString(),
                                       commitment.vin.prevout.ToString());
    if(!CMessageSigner::VerifyMessage(pubKey, commitment.vchSig, strMessage, strError)) {
        //sender is in DIN and metadata is correct but sign is KO => so ban it
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- VerifyMessage() failed, error: %s, message: \n", strError, strMessage);
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    //step 2.1 check if sender in Top and SINtype = nInfinityNodeLockRewardSINType (skip this step for now)
    int nScore;
    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType; //mypeer must be this SINtype, if not, score is NULL

    if(!infnodeman.getNodeScoreAtHeight(commitment.vin.prevout, nSINtypeCanLockReward, commitment.nRewardHeight - 101, nScore)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- Can't calculate score for Infinitynode %s\n",
                    infinitynodePeer.burntx.ToStringShort());
        return false;
    }

    //sender in TopNode => he is not expired at Height
    if(nScore <= Params().GetConsensus().nInfinityNodeLockRewardTop) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- Someone in TopNode send me a Commitment. Processing commitment...\n");
    } else {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckCommitment -- Someone NOT in TopNode send me a Commitment. Banned!\n");
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 10);
        return false;
    }

    return true;
}

void CInfinityNodeLockReward::AddMySignersMap(const CLockRewardCommitment& commitment)
{
    if(fLiteMode || !fInfinityNode) return;

    AssertLockHeld(cs);

    if(commitment.nHashRequest != currentLockRequestHash){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMySignersMap -- commitment is not mine. LockRequest hash: %s\n", commitment.nHashRequest.ToString());
        return;
    }

    auto it = mapSigners.find(currentLockRequestHash);
    if(it == mapSigners.end()){
        mapSigners[currentLockRequestHash].push_back(commitment.vin.prevout);
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMySignersMap -- add commitment to my signer map(%d): %s\n",
                   mapSigners[currentLockRequestHash].size(),commitment.vin.prevout.ToStringShort());
    } else {
        bool found=false;
        for (auto& v : it->second){
            if(v == commitment.vin.prevout){
                found = true;
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMySignersMap -- commitment from same signer: %s\n", commitment.vin.prevout.ToStringShort());
            }
        }
        if(!found){
            mapSigners[currentLockRequestHash].push_back(commitment.vin.prevout);
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMySignersMap -- update commitment to my signer map(%d): %s\n",
                       mapSigners[currentLockRequestHash].size(),commitment.vin.prevout.ToStringShort());
        }
    }
}

/*
 * STEP 4.3
 *
 * read commitment map and myLockRequest, if there is enough commitment was sent
 * => broadcast it
 */
bool CInfinityNodeLockReward::FindAndSendSignersGroup(CConnman& connman)
{
    if(fLiteMode || !fInfinityNode) return false;

    AssertLockHeld(cs);

    int loop = Params().GetConsensus().nInfinityNodeLockRewardTop / Params().GetConsensus().nInfinityNodeLockRewardSigners;

    if((int)mapSigners[currentLockRequestHash].size() >= Params().GetConsensus().nInfinityNodeLockRewardSigners){
        TryConnectToMySigners(mapLockRewardRequest[currentLockRequestHash].nRewardHeight, connman);
    }

    for (int i=0; i <= loop; i++)
    {
        std::vector<COutPoint> signers;
        if(i >=1 && mapSigners[currentLockRequestHash].size() >= Params().GetConsensus().nInfinityNodeLockRewardSigners * i && nGroupSigners < i){
            for(int j=Params().GetConsensus().nInfinityNodeLockRewardSigners * (i - 1); j < Params().GetConsensus().nInfinityNodeLockRewardSigners * i; j++){
                signers.push_back(mapSigners[currentLockRequestHash].at(j));
            }

            if(signers.size() == Params().GetConsensus().nInfinityNodeLockRewardSigners){
                nGroupSigners = i;//track signer group sent
                int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType;
                std::string signerIndex = infnodeman.getVectorNodeRankAtHeight(signers, nSINtypeCanLockReward, mapLockRewardRequest[currentLockRequestHash].nRewardHeight);
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndSendSignersGroup -- send this group: %d, signers: %s for height: %d\n",
                          nGroupSigners, signerIndex, mapLockRewardRequest[currentLockRequestHash].nRewardHeight);

                if (signerIndex != ""){
                    //step 4.3.1
                    CGroupSigners gSigners(infinitynodePeer.burntx, currentLockRequestHash, nGroupSigners, mapLockRewardRequest[currentLockRequestHash].nRewardHeight, signerIndex);
                    if(gSigners.Sign(infinitynodePeer.keyInfinitynode, infinitynodePeer.pubKeyInfinitynode)) {
                        if (AddGroupSigners(gSigners)) {
                            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndSendSignersGroup -- relay my GroupSigner: %d, hash: %s, LockRequest: %s\n",
                                      nGroupSigners, gSigners.GetHash().ToString(), currentLockRequestHash.ToString());
                            gSigners.Relay(connman);
                        }
                    }
                }
            }
            signers.clear();
        }
    }

    return true;
}

/*
 * STEP 5.0
 *
 * check CGroupSigners
 */
bool CInfinityNodeLockReward::CheckGroupSigner(CNode* pnode, const CGroupSigners& gsigners)
{
    if(fLiteMode || !fInfinityNode) return false;

    AssertLockHeld(cs);

    //step 5.1.0: make sure that it is sent from candidate
    if(!mapLockRewardRequest.count(gsigners.nHashRequest)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckGroupSigner -- LockRequest is not found\n");
        return false;
    }

    if(mapLockRewardRequest[gsigners.nHashRequest].burnTxIn != gsigners.vin){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckGroupSigner -- LockRequest is not coherent with CGroupSigners\n");
        return false;
    }

    //step 5.1.1: not too far in future and not inferior than current Height
    if(gsigners.nRewardHeight > nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth + 2
        || gsigners.nRewardHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckGroupSigner -- GroupSigner invalid for height: %d, current height: %d\n",
            gsigners.nRewardHeight, nCachedBlockHeight);
        return false;
    }

    //step 5.1.2: get candidate from vin.prevout
    infinitynode_info_t infoInf;
    if(!infnodeman.GetInfinitynodeInfo(gsigners.vin.prevout, infoInf)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckGroupSigner -- Cannot find sender from list %s\n");
        //someone try to send a VerifyRequest to me but not in DIN => so ban it
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    CMetadata metaSender = infnodemeta.Find(infoInf.metadataID);
    if (metaSender.getMetadataHeight() == 0){
        //for some reason, metadata is not updated, do nothing
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckGroupSigner -- Cannot find sender from list %s\n");
        return false;
    }
    //dont check nHeight of metadata here. Candidate can be paid event the metadata is not ready for Musig. Because his signature is not onchain

    std::string metaPublicKey = metaSender.getMetaPublicKey();
    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
    CPubKey pubKey(tx_data.begin(), tx_data.end());

    std::string strError="";
    std::string strMessage = strprintf("%d%s%s%s%d", gsigners.nRewardHeight, gsigners.nHashRequest.ToString(), gsigners.vin.prevout.ToString(), gsigners.signersId, gsigners.nGroup);
    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckGroupSigner -- publicKey:%s, message: %s\n", pubKey.GetID().ToString(), strMessage);
    //step 5.1.3: verify the sign
    if(!CMessageSigner::VerifyMessage(pubKey, gsigners.vchSig, strMessage, strError)) {
        //sender is in DIN and metadata is correct but sign is KO => so ban it
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckGroupSigner -- VerifyMessage() failed, error: %s, message: \n", strError, strMessage);
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    return true;
}

/*
 * STEP 5.1
 *
 * Musig Partial Sign
 * we know that we use COMPRESSED_PUBLIC_KEY_SIZE format
 */
bool CInfinityNodeLockReward::MusigPartialSign(CNode* pnode, const CGroupSigners& gsigners, CConnman& connman)
{
    if(fLiteMode || !fInfinityNode) return false;

    AssertLockHeld(cs);

    secp256k1_pubkey *pubkeys;
    pubkeys = (secp256k1_pubkey*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_pubkey));
    secp256k1_pubkey *commitmentpk;
    commitmentpk = (secp256k1_pubkey*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_pubkey));
    unsigned char **commitmenthash;
    commitmenthash = (unsigned char**) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(unsigned char*));
    //signer data
    unsigned char myPeerKey[32], myCommitmentPrivkey[32], myCommitmentHash[32];

    //step 5.1.3: get Rank of reward and find signer from Id
    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType;
    std::map<int, CInfinitynode> mapInfinityNodeRank = infnodeman.calculInfinityNodeRank(mapLockRewardRequest[gsigners.nHashRequest].nRewardHeight, nSINtypeCanLockReward, false, true);

    std::string s;
    stringstream ss(gsigners.signersId);
    int nSigner=0, nCommitment=0, myIndex = -1;
    while (getline(ss, s,';')) {
        int Id = atoi(s);
        {
            //find publicKey
            CInfinitynode infSigner = mapInfinityNodeRank[Id];
            CMetadata metaSigner = infnodemeta.Find(infSigner.getMetaID());
            if(metaSigner.getMetadataHeight() == 0){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Cannot get metadata of candidate %s\n", infSigner.getBurntxOutPoint().ToStringShort());
                continue;
            }

            if(gsigners.nRewardHeight < metaSigner.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
                int nWait = metaSigner.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - gsigners.nRewardHeight;
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- metadata of signer is not ready for Musig(wait %d blocks).\n", nWait);
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                for(int c = 0; c < nCommitment; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }

            int nScore;
            int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType; //mypeer must be this SINtype, if not, score is NULL

            if(!infnodeman.getNodeScoreAtHeight(infSigner.getBurntxOutPoint(), nSINtypeCanLockReward, gsigners.nRewardHeight - 101, nScore)) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Can't calculate score signer Rank %d\n",Id);
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                for(int c = 0; c < nCommitment; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }

            if(nScore > Params().GetConsensus().nInfinityNodeLockRewardTop){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- signer Rank %d is not Top Node: %d(%d)\n",
                         Id, Params().GetConsensus().nInfinityNodeLockRewardTop, nScore);
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                for(int c = 0; c < nCommitment; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }

            std::string metaPublicKey = metaSigner.getMetaPublicKey();
            std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
            CPubKey pubKey(tx_data.begin(), tx_data.end());
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Metadata pubkeyId: %s\n", pubKey.GetID().ToString());

            if (!secp256k1_ec_pubkey_parse(secp256k1_context_musig, &pubkeys[nSigner], pubKey.data(), pubKey.size())) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- cannot parse publicKey\n");
                continue;
            }

            if(infinitynodePeer.burntx == infSigner.getBurntxOutPoint() && infinitynodePeer.keyInfinitynode.size()==32 ){
                    myIndex = nSigner;
                    memcpy(myPeerKey, infinitynodePeer.keyInfinitynode.begin(), 32);
            }
            //next signer
            nSigner++;


            //find commitment publicKey
            for (auto& pair : mapLockRewardCommitment) {
                if(pair.second.nHashRequest == gsigners.nHashRequest && pair.second.vin.prevout == infSigner.getBurntxOutPoint()){
                    if (!secp256k1_ec_pubkey_parse(secp256k1_context_musig, &commitmentpk[nCommitment], pair.second.pubkeyR.data(), pair.second.pubkeyR.size())) {
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- cannot parse publicKey\n");
                        continue;
                    }

                    commitmenthash[nCommitment] = (unsigned char*) malloc(32 * sizeof(unsigned char));
                    secp256k1_pubkey pub = commitmentpk[nCommitment];
                    secp256k1_pubkey_to_commitment(secp256k1_context_musig, commitmenthash[nCommitment], &pub);

                    if(infinitynodePeer.burntx == infSigner.getBurntxOutPoint() && pair.second.random.size() == 32){
                        memcpy(myCommitmentPrivkey, pair.second.random.begin(), 32);
                        secp256k1_pubkey pub = commitmentpk[nCommitment];
                        secp256k1_pubkey_to_commitment(secp256k1_context_musig, myCommitmentHash, &pub);
                    }
                    nCommitment++;
                }
            }
        }
    }

    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- found signers: %d, commitments: %d, myIndex: %d\n", nSigner, nCommitment, myIndex);
    if(nSigner != Params().GetConsensus().nInfinityNodeLockRewardSigners || nCommitment != Params().GetConsensus().nInfinityNodeLockRewardSigners){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- number of signers: %d or commitment:% d, is not the same as consensus\n", nSigner, nCommitment);
        free(pubkeys); pubkeys = NULL;
        free(commitmentpk); commitmentpk = NULL;
        for(int c = 0; c < nCommitment; c++) { //use the actual commitment numbers here, not what we expected to find
            free(commitmenthash[c]);
        }
        free(commitmenthash); commitmenthash = NULL;
        return false;
    }

    size_t N_SIGNERS = (size_t)Params().GetConsensus().nInfinityNodeLockRewardSigners;
    unsigned char pk_hash[32];
    unsigned char session_id[32];
    unsigned char nonce_commitment[32];
    unsigned char msg[32] = {'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a'};
    // Currently unused
    //secp256k1_schnorr sig;
    secp256k1_scratch_space *scratch = NULL;
    secp256k1_pubkey combined_pk, nonce;

    CKey secret;
    secret.MakeNewKey(true);
    memcpy(session_id, secret.begin(), 32);

    secp256k1_musig_session musig_session;
    secp256k1_musig_session_signer_data *signer_data;
    signer_data = (secp256k1_musig_session_signer_data*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_musig_session_signer_data));
    secp256k1_musig_partial_signature partial_sig;

    scratch = secp256k1_scratch_space_create(secp256k1_context_musig, 1024 * 1024);

    //message Musig
    CHashWriter ssmsg(SER_GETHASH, PROTOCOL_VERSION);
        ssmsg << gsigners.vin;
        ssmsg << gsigners.nRewardHeight;
    uint256 messageHash = ssmsg.GetHash();
    memcpy(msg, messageHash.begin(), 32);

    //combine publicKeys
    if (!secp256k1_musig_pubkey_combine(secp256k1_context_musig, scratch, &combined_pk, pk_hash, pubkeys, N_SIGNERS)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Combine PublicKey FAILED\n");
        free(pubkeys); pubkeys = NULL;
        free(commitmentpk); commitmentpk = NULL;
        free(signer_data); signer_data = NULL;
        secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
        for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
            free(commitmenthash[c]);
        }
        free(commitmenthash); commitmenthash = NULL;
        return false;
    }

    unsigned char pub[CPubKey::PUBLIC_KEY_SIZE];
    size_t publen = CPubKey::PUBLIC_KEY_SIZE;
    secp256k1_ec_pubkey_serialize(secp256k1_context_musig, pub, &publen, &combined_pk, SECP256K1_EC_COMPRESSED);
    CPubKey combined_pubKey_formated(pub, pub + publen);
    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Combining public keys: %s\n", combined_pubKey_formated.GetID().ToString());

    //i am signer
    if(myIndex >= 0){
        if (!secp256k1_musig_session_initialize_sin(secp256k1_context_musig, &musig_session, signer_data, nonce_commitment,
                                            session_id, msg, &combined_pk, pk_hash, N_SIGNERS, myIndex, myPeerKey, myCommitmentPrivkey)) {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Session Initialize FAILED\n");
            free(pubkeys); pubkeys = NULL;
            free(commitmentpk); commitmentpk = NULL;
            free(signer_data); signer_data = NULL;
            secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
            for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                free(commitmenthash[c]);
            }
            free(commitmenthash); commitmenthash = NULL;
            return false;
        }

        if (!secp256k1_musig_session_get_public_nonce(secp256k1_context_musig, &musig_session, signer_data, &nonce, commitmenthash, N_SIGNERS, NULL)) {
            free(pubkeys); pubkeys = NULL;
            free(commitmentpk); commitmentpk = NULL;
            free(signer_data); signer_data = NULL;
            secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
            for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                free(commitmenthash[c]);
            }
            free(commitmenthash); commitmenthash = NULL;
            return false;
        }

        for (int j = 0; j < N_SIGNERS; j++) {
            if (!secp256k1_musig_set_nonce(secp256k1_context_musig, &signer_data[j], &commitmentpk[j])) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Set Nonce FAILED\n");
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                free(signer_data); signer_data = NULL;
                secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }
        }

        if (!secp256k1_musig_session_combine_nonces(secp256k1_context_musig, &musig_session, signer_data, N_SIGNERS, NULL, NULL)) {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Combine Nonce FAILED\n");
            free(pubkeys); pubkeys = NULL;
            free(commitmentpk); commitmentpk = NULL;
            free(signer_data); signer_data = NULL;
            secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
            for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                free(commitmenthash[c]);
            }
            free(commitmenthash); commitmenthash = NULL;
            return false;
        }

        if (!secp256k1_musig_partial_sign(secp256k1_context_musig, &musig_session, &partial_sig)) {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Partial Sign FAILED\n");
            free(pubkeys); pubkeys = NULL;
            free(commitmentpk); commitmentpk = NULL;
            free(signer_data); signer_data = NULL;
            secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
            for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                free(commitmenthash[c]);
            }
            free(commitmenthash); commitmenthash = NULL;
            return false;
        }

        if (!secp256k1_musig_partial_sig_verify(secp256k1_context_musig, &musig_session, &signer_data[myIndex], &partial_sig, &pubkeys[myIndex])) {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Partial Sign Verify FAILED\n");
            free(pubkeys); pubkeys = NULL;
            free(commitmentpk); commitmentpk = NULL;
            free(signer_data); signer_data = NULL;
            secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
            for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                free(commitmenthash[c]);
            }
            free(commitmenthash); commitmenthash = NULL;
            return false;
        }

        CMusigPartialSignLR partialSign(infinitynodePeer.burntx, gsigners.GetHash(), gsigners.nRewardHeight, partial_sig.data);

                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- sign obj:");
                for(int j=0; j<32;j++){
                    LogPrint(BCLog::INFINITYLOCK," %d ", partialSign.vchMusigPartialSign.at(j));
                }
                LogPrint(BCLog::INFINITYLOCK,"\n");

        if(partialSign.Sign(infinitynodePeer.keyInfinitynode, infinitynodePeer.pubKeyInfinitynode)) {
            if (AddMusigPartialSignLR(partialSign)) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- relay my MusigPartialSign for group: %s, hash: %s, LockRequest: %s\n",
                                      gsigners.signersId, partialSign.GetHash().ToString(), currentLockRequestHash.ToString());
                partialSign.Relay(connman);
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                free(signer_data); signer_data = NULL;
                secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return true;
            }
        }
    }

    free(pubkeys); pubkeys = NULL;
    free(commitmentpk); commitmentpk = NULL;
    free(signer_data); signer_data = NULL;
    secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
    for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
        free(commitmenthash[c]);
    }
    free(commitmenthash); commitmenthash = NULL;
    return false;
}

/*
 * STEP 5.1
 *
 * Check Partial Sign
 */

bool CInfinityNodeLockReward::CheckMusigPartialSignLR(CNode* pnode, const CMusigPartialSignLR& ps)
{
    if(fLiteMode || !fInfinityNode) return false;

    AssertLockHeld(cs);

    //not too far in future and not inferior than current Height
    if(ps.nRewardHeight > nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth + 2
        || ps.nRewardHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- Partial Sign invalid for height: %d, current height: %d\n",
            ps.nRewardHeight, nCachedBlockHeight);
        return false;
    }


    infinitynode_info_t infoInf;
    if(!infnodeman.GetInfinitynodeInfo(ps.vin.prevout, infoInf)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- Cannot find sender from list %s\n");
        //someone try to send a VerifyRequest to me but not in DIN => so ban it
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    if(infoInf.nExpireHeight < nCachedBlockHeight){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- VerifyRequest was sent from expired node. Ban it!\n", ps.vin.prevout.ToStringShort());
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 10);
        return false;
    }

    CMetadata metaSender = infnodemeta.Find(infoInf.metadataID);
    if (metaSender.getMetadataHeight() == 0){
        //for some reason, metadata is not updated, do nothing
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- Cannot find sender from list %s\n");
        return false;
    }

    if(ps.nRewardHeight < metaSender.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
        int nWait = metaSender.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - ps.nRewardHeight;
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMyPeerAndSendVerifyRequest -- metadata is not ready for Musig (wait %d blocks).\n", nWait);
        return false;
    }

    std::string metaPublicKey = metaSender.getMetaPublicKey();
    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
    CPubKey pubKey(tx_data.begin(), tx_data.end());

    std::string strError;
    std::string strMessage = strprintf("%d%s%s%s", ps.nRewardHeight, ps.nHashGroupSigners.ToString(),
                                       ps.vin.prevout.ToString(), EncodeBase58(ps.vchMusigPartialSign));
    if(!CMessageSigner::VerifyMessage(pubKey, ps.vchSig, strMessage, strError)) {
        //sender is in DIN and metadata is correct but sign is KO => so ban it
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- VerifyMessage() failed, error: %s, message: \n", strError, strMessage);
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 20);
        return false;
    }

    //step 2.1 check if sender in Top and SINtype = nInfinityNodeLockRewardSINType (skip this step for now)
    int nScore;
    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType; //mypeer must be this SINtype, if not, score is NULL

    if(!infnodeman.getNodeScoreAtHeight(ps.vin.prevout, nSINtypeCanLockReward, ps.nRewardHeight - 101, nScore)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- Can't calculate score for Infinitynode %s\n",
                    infinitynodePeer.burntx.ToStringShort());
        return false;
    }

    //sender in TopNode => he is not expired at Height
    if(nScore <= Params().GetConsensus().nInfinityNodeLockRewardTop) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- Someone in TopNode send me a Partial Sign. Processing signature...\n");
    } else {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckMusigPartialSignLR -- Someone NOT in TopNode send me a Partial Sign. Banned!\n");
        LOCK(cs_main);
        Misbehaving(pnode->GetId(), 10);
        return false;
    }

    return true;
}

/*
 * STEP 5.2
 *
 * Add all Partial Sign for MyLockRequest in map
 */
void CInfinityNodeLockReward::AddMyPartialSignsMap(const CMusigPartialSignLR& ps)
{
    if(fLiteMode || !fInfinityNode) return;

    AssertLockHeld(cs);

    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMyPartialSignsMap -- try add Partial Sign for group hash: %s\n",
                   ps.nHashGroupSigners.ToString());

    if(mapLockRewardGroupSigners[ps.nHashGroupSigners].vin.prevout != infinitynodePeer.burntx){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMyPartialSignsMap -- Partial Sign is not mine. LockRequest hash: %s\n",
                   mapLockRewardGroupSigners[ps.nHashGroupSigners].nHashRequest.ToString());
        return;
    }

    auto it = mapMyPartialSigns.find(ps.nHashGroupSigners);
    if(it == mapMyPartialSigns.end()){
        mapMyPartialSigns[ps.nHashGroupSigners].push_back(ps);
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMyPartialSignsMap -- add Partial Sign to my map(%d), group signer hash: %s\n",
                   mapMyPartialSigns[ps.nHashGroupSigners].size(), ps.nHashGroupSigners.ToString());
    } else {
        bool found=false;
        for (auto& v : it->second){
            if(v.GetHash() == ps.GetHash()){
                found = true;
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMyPartialSignsMap -- Partial Sign was added: %s\n", ps.GetHash().ToString());
            }
        }
        if(!found){
            mapMyPartialSigns[ps.nHashGroupSigners].push_back(ps);
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::AddMyPartialSignsMap -- update Partial Sign to my map(%d): %s\n",
                   mapMyPartialSigns[ps.nHashGroupSigners].size(), ps.nHashGroupSigners.ToString());
        }
    }
}

/*
 * STEP 5.3
 *
 * Build Musig
 */
bool CInfinityNodeLockReward::FindAndBuildMusigLockReward()
{
    if(fLiteMode || !fInfinityNode) return false;

    AssertLockHeld(cs);

    std::vector<COutPoint> signOrder;
    for (auto& pair : mapMyPartialSigns) {
        uint256 nHashGroupSigner = pair.first;
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Group Signer: %s, GroupSigner exist: %d, size: %d\n",
                       nHashGroupSigner.ToString(), mapLockRewardGroupSigners.count(nHashGroupSigner), pair.second.size());

        if(pair.second.size() == Params().GetConsensus().nInfinityNodeLockRewardSigners && mapLockRewardGroupSigners.count(nHashGroupSigner) == 1) {

            uint256 nHashLockRequest = mapLockRewardGroupSigners[nHashGroupSigner].nHashRequest;

            if(!mapLockRewardRequest.count(nHashLockRequest)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- LockRequest: %s is not in my Map\n",
                       nHashLockRequest.ToString());
                continue;
            }

            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- LockRequest: %s; member: %s\n",
                       nHashLockRequest.ToString(), mapLockRewardGroupSigners[nHashGroupSigner].signersId);
            for(int k=0; k < Params().GetConsensus().nInfinityNodeLockRewardSigners; k++){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- signerId %d, signer: %s, partial sign:%s,\n",
                          k, pair.second.at(k).vin.prevout.ToStringShort() ,pair.second.at(k).GetHash().ToString());
            }
            if(mapSigned.count(mapLockRewardRequest[nHashLockRequest].nRewardHeight)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- !!! Musig for :%d was built by group signers :%s, members: %s\n",
                          mapLockRewardRequest[nHashLockRequest].nRewardHeight, nHashGroupSigner.ToString(), mapLockRewardGroupSigners[nHashGroupSigner].signersId);
                continue;
            }

            int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType;
            std::map<int, CInfinitynode> mapInfinityNodeRank = infnodeman.calculInfinityNodeRank(mapLockRewardRequest[nHashLockRequest].nRewardHeight, nSINtypeCanLockReward, false, true);
            secp256k1_pubkey *pubkeys;
            pubkeys = (secp256k1_pubkey*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_pubkey));
            secp256k1_pubkey *commitmentpk;
            commitmentpk = (secp256k1_pubkey*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_pubkey));
            unsigned char **commitmenthash;
            commitmenthash = (unsigned char**) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(unsigned char*));

            //find commiment
            std::string s;
            stringstream ss(mapLockRewardGroupSigners[nHashGroupSigner].signersId);

            int nSigner=0, nCommitment=0;
            while (getline(ss, s,';')) {
                int Id = atoi(s);
                {//open
                    //find publicKey
                    CInfinitynode infSigner = mapInfinityNodeRank[Id];
                    CMetadata metaSigner = infnodemeta.Find(infSigner.getMetaID());
                    if(metaSigner.getMetadataHeight() == 0){
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Cannot get metadata of candidate %s\n", infSigner.getBurntxOutPoint().ToStringShort());
                        continue;
                    }

                    if(mapLockRewardRequest[nHashLockRequest].nRewardHeight < metaSigner.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
                        int nWait = metaSigner.getMetadataHeight() + Params().MaxReorganizationDepth() * 2 - mapLockRewardRequest[nHashLockRequest].nRewardHeight;
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- metadata of signer is not ready for Musig (wait %d blocks).\n", nWait);
                        free(pubkeys); pubkeys = NULL;
                        free(commitmentpk); commitmentpk = NULL;
                        for(int c = 0; c < nCommitment; c++) {
                            free(commitmenthash[c]);
                        }
                        free(commitmenthash); commitmenthash = NULL;
                        return false;
                    }

                    int nScore;
                    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType; //mypeer must be this SINtype, if not, score is NULL

                    if(!infnodeman.getNodeScoreAtHeight(infSigner.getBurntxOutPoint(), nSINtypeCanLockReward, mapLockRewardRequest[nHashLockRequest].nRewardHeight - 101, nScore)) {
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Can't calculate score signer Rank %d\n",Id);
                        free(pubkeys); pubkeys = NULL;
                        free(commitmentpk); commitmentpk = NULL;
                        for(int c = 0; c < nCommitment; c++) {
                            free(commitmenthash[c]);
                        }
                        free(commitmenthash); commitmenthash = NULL;
                        return false;
                    }

                    if(nScore > Params().GetConsensus().nInfinityNodeLockRewardTop){
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- signer Rank %d is not Top Node: %d(%d)\n",
                                 Id, Params().GetConsensus().nInfinityNodeLockRewardTop, nScore);
                        free(pubkeys); pubkeys = NULL;
                        free(commitmentpk); commitmentpk = NULL;
                        for(int c = 0; c < nCommitment; c++) {
                            free(commitmenthash[c]);
                        }
                        free(commitmenthash); commitmenthash = NULL;
                        return false;
                    }

                    std::string metaPublicKey = metaSigner.getMetaPublicKey();
                    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
                    CPubKey pubKey(tx_data.begin(), tx_data.end());
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Metadata of signer %d, Index: %d pubkeyId: %s\n",nSigner, Id, pubKey.GetID().ToString());

                    if (!secp256k1_ec_pubkey_parse(secp256k1_context_musig, &pubkeys[nSigner], pubKey.data(), pubKey.size())) {
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- cannot parse publicKey\n");
                        continue;
                    }

                    //memrory sign order
                    signOrder.push_back(infSigner.getBurntxOutPoint());
                    //next signer
                    nSigner++;


                    //find commitment publicKey
                    for (auto& pair : mapLockRewardCommitment) {
                        if(pair.second.nHashRequest == nHashLockRequest && pair.second.vin.prevout == infSigner.getBurntxOutPoint()){
                            if (!secp256k1_ec_pubkey_parse(secp256k1_context_musig, &commitmentpk[nCommitment], pair.second.pubkeyR.data(), pair.second.pubkeyR.size())) {
                                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- cannot parse publicKey\n");
                                continue;
                            }

                            commitmenthash[nCommitment] = (unsigned char*) malloc(32 * sizeof(unsigned char));
                            secp256k1_pubkey pub = commitmentpk[nCommitment];
                            secp256k1_pubkey_to_commitment(secp256k1_context_musig, commitmenthash[nCommitment], &pub);

                            nCommitment++;
                        }
                    }
                }//end open
            }//end while

            //build shared publick key
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- found signers: %d, commitments: %d\n", nSigner, nCommitment);
            if(nSigner != Params().GetConsensus().nInfinityNodeLockRewardSigners || nCommitment != Params().GetConsensus().nInfinityNodeLockRewardSigners){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- number of signers: %d or commitment:% d, is not the same as consensus\n", nSigner, nCommitment);
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                for(int c = 0; c < nCommitment; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }

            secp256k1_pubkey combined_pk;
            unsigned char pk_hash[32];
            secp256k1_scratch_space *scratch = NULL;

            scratch = secp256k1_scratch_space_create(secp256k1_context_musig, 1024 * 1024);
            size_t N_SIGNERS = (size_t)Params().GetConsensus().nInfinityNodeLockRewardSigners;

            if (!secp256k1_musig_pubkey_combine(secp256k1_context_musig, scratch, &combined_pk, pk_hash, pubkeys, N_SIGNERS)) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Musig Combine PublicKey FAILED\n");
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }

            unsigned char pub[CPubKey::PUBLIC_KEY_SIZE];
            size_t publen = CPubKey::PUBLIC_KEY_SIZE;
            secp256k1_ec_pubkey_serialize(secp256k1_context_musig, pub, &publen, &combined_pk, SECP256K1_EC_COMPRESSED);
            CPubKey combined_pubKey_formated(pub, pub + publen);
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Combining public keys: %s\n", combined_pubKey_formated.GetID().ToString());

            secp256k1_musig_session verifier_session;
            secp256k1_musig_session_signer_data *verifier_signer_data;
            verifier_signer_data = (secp256k1_musig_session_signer_data*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_musig_session_signer_data));

            unsigned char msg[32] = {'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a'};

            //message Musig
            CHashWriter ssmsg(SER_GETHASH, PROTOCOL_VERSION);
            ssmsg << mapLockRewardGroupSigners[nHashGroupSigner].vin;
            ssmsg << mapLockRewardGroupSigners[nHashGroupSigner].nRewardHeight;
            uint256 messageHash = ssmsg.GetHash();
            memcpy(msg, messageHash.begin(), 32);

            //initialize verifier session
            if (!secp256k1_musig_session_initialize_verifier(secp256k1_context_musig, &verifier_session, verifier_signer_data, msg,
                                            &combined_pk, pk_hash, commitmenthash, N_SIGNERS)) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Musig Verifier Session Initialize FAILED\n");
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                free(verifier_signer_data); verifier_signer_data = NULL;
                secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Musig Verifier Session Initialized!!!\n");

            for(int i=0; i<N_SIGNERS; i++) {
                if(!secp256k1_musig_set_nonce(secp256k1_context_musig, &verifier_signer_data[i], &commitmentpk[i])) {
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Set Nonce :%d FAILED\n", i);
                    free(pubkeys); pubkeys = NULL;
                    free(commitmentpk); commitmentpk = NULL;
                    free(verifier_signer_data); verifier_signer_data = NULL;
                    secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                    for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                        free(commitmenthash[c]);
                    }
                    free(commitmenthash); commitmenthash = NULL;
                    return false;
                }
            }

            if (!secp256k1_musig_session_combine_nonces(secp256k1_context_musig, &verifier_session, verifier_signer_data, N_SIGNERS, NULL, NULL)) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Combine Nonce FAILED\n");
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                free(verifier_signer_data); verifier_signer_data = NULL;
                secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                return false;
            }
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Musig Combine Nonce!!!\n");

            secp256k1_musig_partial_signature *partial_sig;
            partial_sig = (secp256k1_musig_partial_signature*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_musig_partial_signature));
            for(int i=0; i<N_SIGNERS; i++) {
                std::vector<unsigned char> sig;
                for(int j=0; j < pair.second.size(); j++){
                    if(signOrder.at(i) == pair.second.at(j).vin.prevout){
                        sig = pair.second.at(j).vchMusigPartialSign;
                    }
                }

                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- sign %d:", i);

                for(int j=0; j<32;j++){
                    LogPrint(BCLog::INFINITYLOCK," %d ", sig.at(j));
                    partial_sig[i].data[j] = sig.at(j);
                }
                LogPrint(BCLog::INFINITYLOCK,"\n");
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- from: %s\n", signOrder.at(i).ToStringShort());


                if (!secp256k1_musig_partial_sig_verify(secp256k1_context_musig, &verifier_session, &verifier_signer_data[i], &partial_sig[i], &pubkeys[i])) {
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Partial Sign %d Verify FAILED\n", i);
                    free(pubkeys); pubkeys = NULL;
                    free(commitmentpk); commitmentpk = NULL;
                    free(verifier_signer_data); verifier_signer_data = NULL;
                    secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                    for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                        free(commitmenthash[c]);
                    }
                    free(commitmenthash); commitmenthash = NULL;
                    free(partial_sig); partial_sig = NULL;
                    return false;
                }
            }
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Musig Partial Sign Verified!!!\n");

            secp256k1_schnorr final_sig;
            if(!secp256k1_musig_partial_sig_combine(secp256k1_context_musig, &verifier_session, &final_sig, partial_sig, N_SIGNERS, NULL)) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::MusigPartialSign -- Musig Final Sign FAILED\n");
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                free(verifier_signer_data); verifier_signer_data = NULL;
                secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                free(partial_sig); partial_sig = NULL;
                return false;
            }

            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Musig Final Sign built for Reward Height: %d with group signer %s!!!\n",
                       mapLockRewardRequest[nHashLockRequest].nRewardHeight, mapLockRewardGroupSigners[nHashGroupSigner].signersId);

            std::string sLockRewardMusig = strprintf("%d;%d;%s;%s", mapLockRewardRequest[nHashLockRequest].nRewardHeight,
                                      mapLockRewardRequest[nHashLockRequest].nSINtype,
                                      EncodeBase58(final_sig.data, final_sig.data+64),
                                      mapLockRewardGroupSigners[nHashGroupSigner].signersId);

            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Register info: %s\n",
                                          sLockRewardMusig);

            std::string sErrorRegister = "";
            std::string sErrorCheck = "";

            if(!CheckLockRewardRegisterInfo(sLockRewardMusig, sErrorCheck, mapLockRewardGroupSigners[nHashGroupSigner].vin.prevout)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Check error: %s, Register LockReward error: %s\n",
                         sErrorCheck, sErrorRegister);
                free(pubkeys); pubkeys = NULL;
                free(commitmentpk); commitmentpk = NULL;
                free(verifier_signer_data); verifier_signer_data = NULL;
                secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                    free(commitmenthash[c]);
                }
                free(commitmenthash); commitmenthash = NULL;
                free(partial_sig); partial_sig = NULL;
                return false;
            } else {
                //send register info
                if(!AutoResigterLockReward(sLockRewardMusig, sErrorCheck, mapLockRewardGroupSigners[nHashGroupSigner].vin.prevout)){
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Register LockReward false: %s\n", sErrorCheck);
                    free(pubkeys); pubkeys = NULL;
                    free(commitmentpk); commitmentpk = NULL;
                    free(verifier_signer_data); verifier_signer_data = NULL;
                    secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                    for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                        free(commitmenthash[c]);
                    }
                    free(commitmenthash); commitmenthash = NULL;
                    free(partial_sig); partial_sig = NULL;
                    return false;
                } else {
                    //memory the musig in map. No build for this anymore
                    mapSigned[mapLockRewardRequest[nHashLockRequest].nRewardHeight] = nHashGroupSigner;
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::FindAndBuildMusigLockReward -- Register LockReward broadcasted!!!\n");
                    free(pubkeys); pubkeys = NULL;
                    free(commitmentpk); commitmentpk = NULL;
                    free(verifier_signer_data); verifier_signer_data = NULL;
                    secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
                    for(int c = 0; c < Params().GetConsensus().nInfinityNodeLockRewardSigners; c++) {
                        free(commitmenthash[c]);
                    }
                    free(commitmenthash); commitmenthash = NULL;
                    free(partial_sig); partial_sig = NULL;
                }
            }
        }//end number signature check
    }//end loop in mapMyPartialSigns

    return true;
}

/*
 * STEP 6 : register LockReward
 */
bool CInfinityNodeLockReward::AutoResigterLockReward(std::string sLockReward, std::string& strErrorRet, const COutPoint& infCheck)
{
    if(infinitynodePeer.burntx != infCheck) {
        strErrorRet = strprintf("I am not INFINITY NODE: %s", infCheck.ToStringShort());
        return false;
    }

    if(infinitynodePeer.nState != INFINITYNODE_PEER_STARTED){
        strErrorRet = strprintf("INFINITY NODE is not started");
        return false;
    }

    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    CWallet * const pwallet = (wallets.size() > 0) ? wallets[0].get() : nullptr;

    if(!pwallet || pwallet->IsLocked()) return false;

    LOCK2(cs_main, pwallet->cs_wallet);

    std::string strError;
    std::vector<COutput> vPossibleCoins;
    pwallet->AvailableCoins(vPossibleCoins, true, NULL, false, ALL_COINS);

    CTransactionRef tx_New;
    CCoinControl coin_control;

    CAmount nFeeRet = 0;
    mapValue_t mapValue;
    bool fSubtractFeeFromAmount = false;
    int nChangePosRet = -1;
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    CAmount curBalance = pwallet->GetBalance();

    CAmount nAmountRegister = 0.001 * COIN;
    CAmount nAmountToSelect = 0.05 * COIN;

    CTxDestination nodeDest = GetDestinationForKey(infinitynodePeer.pubKeyInfinitynode, OutputType::LEGACY);
    CScript nodeScript = GetScriptForDestination(nodeDest);

    //select coin from Node Address, accept only this address
    CAmount selected = 0;
    for (COutput& out : vPossibleCoins) {
        if(selected >= nAmountToSelect) break;
        if(out.nDepth >= 2 && selected < nAmountToSelect){
            CScript pubScript;
            pubScript = out.tx->tx->vout[out.i].scriptPubKey;
            if(pubScript == nodeScript){
                coin_control.Select(COutPoint(out.tx->GetHash(), out.i));
                selected += out.tx->tx->vout[out.i].nValue;
            }
        }
    }

    if(selected < nAmountToSelect){
        strErrorRet = strprintf("Balance of Infinitynode is not enough.");
        return false;
    }

    //chang address
    coin_control.destChange = nodeDest;

    //CRecipient
    std::string strFail = "";
    std::vector<CRecipient> vecSend;

    CTxDestination dest = DecodeDestination(Params().GetConsensus().cLockRewardAddress);
    CScript scriptPubKeyBurnAddress = GetScriptForDestination(dest);
    std::vector<std::vector<unsigned char> > vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKeyBurnAddress, whichType, vSolutions)){
        strErrorRet = strprintf("Internal Fatal Error!");
        return false;
    }
    CKeyID keyid = CKeyID(uint160(vSolutions[0]));
    CScript script;
    script = GetScriptForBurn(keyid, sLockReward);

    CRecipient recipient = {script, nAmountRegister, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);

    //Transaction
    CTransactionRef tx;
    if (!pwallet->CreateTransaction(vecSend, tx, reservekey, nFeeRequired, nChangePosRet, strError, coin_control, true, ALL_COINS)) {
        if (!fSubtractFeeFromAmount && nAmountRegister + nFeeRequired > curBalance)
            strErrorRet = strprintf("Error: This transaction requires a transaction fee of at least %s", FormatMoney(nFeeRequired));
        else strErrorRet = strprintf("%s, selected coins %s", strError, FormatMoney(selected));
        return false;
    }

    CValidationState state;
    if (!pwallet->CommitTransaction(tx, std::move(mapValue), {} /* orderForm */, {}/*fromAccount*/, reservekey, g_connman.get(),
           state, NetMsgType::TX)) {
        strErrorRet = strprintf("Error: The transaction was rejected! Reason given: %s", FormatStateMessage(state));
        return false;
    }
    return true;
}
/**
 * STEP 7 : Check LockReward Musig - use in ConnectBlock
 */
bool CInfinityNodeLockReward::CheckLockRewardRegisterInfo(std::string sLockReward, std::string& strErrorRet, const COutPoint& infCheck)
{
    std::string s;
    stringstream ss(sLockReward);

    int i=0;
    int nRewardHeight = 0;
    int nSINtype = 0;
    std::string signature = "";
    int *signerIndexes;
    size_t N_SIGNERS = (size_t)Params().GetConsensus().nInfinityNodeLockRewardSigners;
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

    if(i > registerNbInfos){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Cannot read %d necessary informations from registerInfo\n",
            registerNbInfos);
        free(signerIndexes);
        return false;
    }
    std::vector<unsigned char> signdecode;
    DecodeBase58(signature, signdecode);
    secp256k1_schnorr final_sig;
    if(signdecode.size() != 64){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Size of signature is incorrect.\n",
            registerNbInfos);
        free(signerIndexes);
        return false;
    }
    for(int j=0; j<64; j++){
        final_sig.data[j] = signdecode.at(j);
    }

    if(nRewardHeight <= Params().GetConsensus().nInfinityNodeGenesisStatement){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- reward height is incorrect.\n",
            registerNbInfos);
        free(signerIndexes);
        return false;
    }

    if(nSINtype != 1 && nSINtype != 5 && nSINtype != 10){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- not Known SINtype detected.\n");
        free(signerIndexes);
        return false;
    }

    //step 7.1 identify candidate
    CInfinitynode candidate;
    LOCK(infnodeman.cs);
    if(!infnodeman.deterministicRewardAtHeight(nRewardHeight, nSINtype, candidate)){
        strErrorRet = strprintf("Cannot find candidate for Height of LockRequest: %d and SINtype: %d\n", nRewardHeight, nSINtype);
        free(signerIndexes);
        return false;
    }

    if(candidate.vinBurnFund.prevout != infCheck){
        strErrorRet = strprintf("Dont match candidate for height: %d and SINtype: %d\n", nRewardHeight, nSINtype);
        free(signerIndexes);
        return false;
    }

    //step 7.2 identify Topnode and signer publicKey
    secp256k1_pubkey *pubkeys;
    pubkeys = (secp256k1_pubkey*) malloc(Params().GetConsensus().nInfinityNodeLockRewardSigners * sizeof(secp256k1_pubkey));
    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType;

    std::map<int, CInfinitynode> mapInfinityNodeRank = infnodeman.calculInfinityNodeRank(nRewardHeight, nSINtypeCanLockReward, false, true);
    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Identify %d TopNode from register info. Map rank: %d\n",
              Params().GetConsensus().nInfinityNodeLockRewardTop, mapInfinityNodeRank.size());

    int nSignerFound = 0;
        {
            for(int i=0; i < N_SIGNERS; i++){
                CInfinitynode sInfNode = mapInfinityNodeRank[signerIndexes[i]];

                CMetadata metaTopNode = infnodemeta.Find(sInfNode.getMetaID());
                if(metaTopNode.getMetadataHeight() == 0){
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Cannot find metadata of TopNode rank: %d, id: %s\n",
                                 signerIndexes[i], sInfNode.getBurntxOutPoint().ToStringShort());
                    free(signerIndexes);
                    free(pubkeys);
                    return false;
                }

                //check metadata use with nRewardHeight of reward
                bool fFindMetaHisto = false;
                std::string pubkeyMetaHisto = metaTopNode.getMetaPublicKey();//last Pubkey
                int nBestDistant = 10000000; //blocks
                if(nRewardHeight < metaTopNode.getMetadataHeight() + Params().MaxReorganizationDepth() * 2){
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Find info in hisroty\n");
                    //height of current metadata is KO for Musig => find in history to get good metadata info
                    for(auto& v : metaTopNode.getHistory()){
                        int metaHistoMature = v.nHeightHisto + Params().MaxReorganizationDepth() * 2;
                        if(nRewardHeight < metaHistoMature) {continue;}
                        if(nBestDistant > (nRewardHeight - metaHistoMature)){
                            nBestDistant = nRewardHeight - metaHistoMature;
                            pubkeyMetaHisto = v.pubkeyHisto;
                            fFindMetaHisto = true;
                        }
                    }

                    if(!fFindMetaHisto){
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- current metadata height is OK. But can not found in history\n");
                        free(signerIndexes);
                        free(pubkeys);
                        return false;
                    }
                }
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Pubkey signer %d: %s\n", signerIndexes[i], pubkeyMetaHisto);

                int nScore;
                int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType; //mypeer must be this SINtype, if not, score is NULL

                if(!infnodeman.getNodeScoreAtHeight(sInfNode.getBurntxOutPoint(), nSINtypeCanLockReward, nRewardHeight - 101, nScore)) {
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Can't calculate score signer Rank %d\n",signerIndexes[i]);
                    free(signerIndexes);
                    free(pubkeys);
                    return false;
                }

                if(nScore > Params().GetConsensus().nInfinityNodeLockRewardTop){
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- signer Rank %d is not Top Node: %d(%d)\n",
                                 signerIndexes[i], Params().GetConsensus().nInfinityNodeLockRewardTop, nScore);
                    free(signerIndexes);
                    free(pubkeys);
                    return false;
                }

                {
                    std::string metaPublicKey = pubkeyMetaHisto;
                    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
                    CPubKey pubKey(tx_data.begin(), tx_data.end());
                    if (!secp256k1_ec_pubkey_parse(secp256k1_context_musig, &pubkeys[i], pubKey.data(), pubKey.size())) {
                        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- cannot parse publicKey\n");
                        continue;
                    }
                    nSignerFound++;
                }
            }
        }//end open

    if(nSignerFound != N_SIGNERS){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Find %d signers. Consensus is %d signers.\n", nSignerFound, N_SIGNERS);
        free(signerIndexes);
        free(pubkeys);
        return false;
    }

    //step 7.3 build message
    unsigned char msg[32] = {'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a'};

    //message Musig
    CHashWriter ssmsg(SER_GETHASH, PROTOCOL_VERSION);
    ssmsg << candidate.vinBurnFund;
    ssmsg << nRewardHeight;
    uint256 messageHash = ssmsg.GetHash();
    memcpy(msg, messageHash.begin(), 32);

    //shared pk
    secp256k1_pubkey combined_pk;
    unsigned char pk_hash[32];
    secp256k1_scratch_space *scratch = NULL;

    scratch = secp256k1_scratch_space_create(secp256k1_context_musig, 1024 * 1024);
    if (!secp256k1_musig_pubkey_combine(secp256k1_context_musig, scratch, &combined_pk, pk_hash, pubkeys, N_SIGNERS)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Musig Combine PublicKey FAILED\n");
        secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
        free(signerIndexes);
        free(pubkeys);
        return false;
    }

    if(!secp256k1_schnorr_verify(secp256k1_context_musig, &final_sig, msg, &combined_pk)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- Check register info FAILED\n");
        secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
        free(signerIndexes);
        free(pubkeys);
        return false;
    }

    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckLockRewardRegisterInfo -- LockReward is valid for height: %d, SINtype: %d, Outpoint: %s\n",
              nRewardHeight, nSINtype, infCheck.ToStringShort());
    secp256k1_scratch_space_destroy(secp256k1_context_musig, scratch);
    free(signerIndexes);
    free(pubkeys);
    return true;
}

void FillBlock(CMutableTransaction& txNew, int nBlockHeight)
{
    /*pay reward for Node Owner of Infinitynode*/
    {
        std::vector<CLockRewardExtractInfo> vecLockRewardRet;
        if (!infnodeman.getLRForHeight(nBlockHeight-1, vecLockRewardRet)) {
            LogPrint(BCLog::INFINITYLOCK, "IsBlockPayeeValid -- use externe LR database\n");
            infnodelrinfo.getLRInfo(nBlockHeight, vecLockRewardRet);
        }

        CScript DINPayee;
        CInfinitynode infOwner;
        int SINType = 0;
        for (int i = 0; i <= 2; i++) {
            //choose tier value
            if (i == 0) {
                SINType = 10;
            } else if (i == 1) {
                SINType = 5;
            } else {
                SINType = 1;
            }
            bool fBurnRewardOwner = false;
            bool fFoundLockReward = false;
            CAmount InfPaymentOwner = 0;
            InfPaymentOwner = GetMasternodePayment(nBlockHeight, SINType);
            std::string sErrorCheck = "";

            LOCK(infnodeman.cs);
            if (infnodeman.deterministicRewardAtHeight(nBlockHeight, SINType, infOwner)){
                DINPayee = infOwner.GetInfo().scriptPubKey;
                for (auto& v : vecLockRewardRet) {
                    if(v.nSINtype == SINType && v.nRewardHeight == nBlockHeight){
                        //check schnorr musig
                        if(inflockreward.CheckLockRewardRegisterInfo(v.sLRInfo, sErrorCheck, infOwner.getBurntxOutPoint())){
                                CMetadata meta = infnodemeta.Find(infOwner.getMetaID());
                                if(meta.getMetadataHeight() == 0){
                                    LogPrint(BCLog::INFINITYLOCK, "IsBlockPayeeValid -- Not found metadata for candidate at height: %d\n", nBlockHeight);
                                    continue;
                                }

                                bool fLRSenderCheck = false;
                                CScript senderScript;
                                for(auto& vhisto : meta.getHistory()){
                                    std::vector<unsigned char> tx_data = DecodeBase64(vhisto.pubkeyHisto.c_str());
                                    CPubKey pubKey(tx_data.begin(), tx_data.end());
                                    CTxDestination nodeDest = GetDestinationForKey(pubKey, OutputType::LEGACY);
                                    senderScript = GetScriptForDestination(nodeDest);
                                    if(v.scriptPubKey == senderScript){
                                        fLRSenderCheck = true;
                                        break;
                                    }
                                }

                                if(fLRSenderCheck){
                                    LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- LockReward for SINtype: %d is VALID\n", SINType);
                                    fFoundLockReward = true;
                                    break;
                                } else {
                                    LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- %s <<<<>>>> %s\n", ScriptToAsmStr(v.scriptPubKey), ScriptToAsmStr(senderScript));
                                    LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- Found LR, but sender is NOT VALID\n");
                                }
                        }
                    }
                }

                if(fFoundLockReward){
                    LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- TESTNET LockReward ADD Payment\n");
                    txNew.vout[0].nValue -= InfPaymentOwner;
                    txNew.vout.push_back(CTxOut(InfPaymentOwner, DINPayee));
                }else{
                    fBurnRewardOwner=true;
                    LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- TESTNET LockReward NOT FOUND or NOT Valid (%s) => Burn\n", sErrorCheck);
                }
            } else {
                LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- TESTNET SINtype: %d, No candidate found\n", SINType);
                fBurnRewardOwner=true;
            }

            if(fBurnRewardOwner){
                txNew.vout[0].nValue -= InfPaymentOwner;
                CTxDestination burnDestination =  DecodeDestination(Params().GetConsensus().cBurnAddress);
                CScript burnAddressScript = GetScriptForDestination(burnDestination);
                txNew.vout.push_back(CTxOut(InfPaymentOwner, burnAddressScript));
            }
        }
    }

    /*pay small reward for Node address of Infinitynode*/
    CScript DINPayeeNode;
    CInfinitynode infinitynode;
    int SINType = 0;

    for (int i = 0; i <= 2; i++) {
            //choose tier value
            if (i == 0) {
                SINType = 10;
            } else if (i == 1) {
                SINType = 5;
            } else {
                SINType = 1;
            }

        bool fBurnRewardNode = false;

        CAmount InfPayment = 0;
        InfPayment = Params().GetConsensus().nMasternodeBurnSINNODE_10;
        {
            LOCK(infnodeman.cs);
            if (infnodeman.deterministicRewardAtHeight(nBlockHeight, SINType, infinitynode)){

                LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- candidate %d at height %d: %s\n", SINType, nBlockHeight, infinitynode.getCollateralAddress());
                CMetadata metaSender = infnodemeta.Find(infinitynode.getMetaID());
                if (metaSender.getMetadataHeight() == 0){
                    LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- can not get metadata of node\n");
                    fBurnRewardNode=true;
                }
                //payment to the last metadata info, so do not do further check

                if(!fBurnRewardNode){
                    std::string metaPublicKey = metaSender.getMetaPublicKey();
                    std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
                    CPubKey pubKey(tx_data.begin(), tx_data.end());
                    if(pubKey.IsValid() && pubKey.IsCompressed()){
                        CTxDestination dest = GetDestinationForKey(pubKey, OutputType::LEGACY);
                        std::string address2 = EncodeDestination(dest);
                        LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- payment for: %s amount %lld\n",address2, InfPayment);

                        DINPayeeNode = GetScriptForDestination(dest);
                        txNew.vout[0].nValue -= InfPayment;
                        txNew.vout.push_back(CTxOut(InfPayment, DINPayeeNode));
                    }else{
                        fBurnRewardNode=true;
                    }
                }
            } else {
                LogPrint(BCLog::INFINITYLOCK, "FillBlockPayments -- can not found infinitynode candidate %d at height %d\n", SINType, nBlockHeight);
                fBurnRewardNode=true;
            }

            if(fBurnRewardNode){
                txNew.vout[0].nValue -= InfPayment;
                CTxDestination burnDestination =  DecodeDestination(Params().GetConsensus().cBurnAddress);
                CScript burnAddressScript = GetScriptForDestination(burnDestination);
                txNew.vout.push_back(CTxOut(InfPayment, burnAddressScript));
            }
        }
    }
}

/*
 * Takes a block as argument, returns if it contains a valid LR commitment or not.
 */
bool LockRewardValidation(const int nBlockHeight, const CTransactionRef txNew)
{
    //fork height for DIN
    if(nBlockHeight < Params().GetConsensus().nDINActivationHeight) return true;

    {
        int counterNodePayment = 0;
        CScript burnfundScript;
        burnfundScript << OP_DUP << OP_HASH160 << ParseHex(Params().GetConsensus().cBurnAddressPubKey) << OP_EQUALVERIFY << OP_CHECKSIG;

        //extract LockReward
        std::vector<CLockRewardExtractInfo> vecLockRewardRet;
        if (!infnodeman.getLRForHeight(nBlockHeight-1, vecLockRewardRet)) {
            LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- use externe LR database\n");
            infnodelrinfo.getLRInfo(nBlockHeight, vecLockRewardRet);
        }
        LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- LR size: %d\n", (int) vecLockRewardRet.size());

        int txIndex = 0;
        for (auto txout : txNew->vout) {
            txIndex ++;
            if (3 <= txIndex && txIndex <=5) {
                //BEGIN
                CScript DINPayee;

                int SINType = 0;
                //choose tier value
                if (txIndex == 3) {
                    SINType = 10;
                } else if (txIndex == 4) {
                    SINType = 5;
                } else {
                    SINType = 1;
                }
                //candidate for this Height
                //check if exist a LR for candidate: Yes: Must pay for him with exact Amount; No: Burn
                CInfinitynode infOwner;
                std::string sErrorCheck = "";

                LOCK(infnodeman.cs);
                if (infnodeman.deterministicRewardAtHeight(nBlockHeight, SINType, infOwner)){

                    CAmount InfPaymentOwner = 0;
                    InfPaymentOwner = GetMasternodePayment(nBlockHeight, SINType);

                    bool fCandidateValid = false;
                    CTxDestination addressTxDIN;
                    std::string addressTxDIN2 = "";
                    ExtractDestination(txout.scriptPubKey, addressTxDIN);
                    addressTxDIN2 = EncodeDestination(addressTxDIN);

                    for (auto& v : vecLockRewardRet) {
                        if(v.nSINtype == SINType && v.nRewardHeight == nBlockHeight && txout.nValue == InfPaymentOwner){
                            //and LR was sent from good metadata: v.scriptPubKey
                            if(inflockreward.CheckLockRewardRegisterInfo(v.sLRInfo, sErrorCheck, infOwner.getBurntxOutPoint())){
                                CMetadata meta = infnodemeta.Find(infOwner.getMetaID());
                                if(meta.getMetadataHeight() == 0){
                                    LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- Not found metadata for candidate at height: %d\n", nBlockHeight);
                                    continue;
                                }

                                bool fLRSenderCheck = false;
                                CScript senderScript;
                                for(auto& vhisto : meta.getHistory()){
                                    std::vector<unsigned char> tx_data = DecodeBase64(vhisto.pubkeyHisto.c_str());
                                    CPubKey pubKey(tx_data.begin(), tx_data.end());
                                    CTxDestination nodeDest = GetDestinationForKey(pubKey, OutputType::LEGACY);
                                    senderScript = GetScriptForDestination(nodeDest);
                                    if(v.scriptPubKey == senderScript){
                                        fLRSenderCheck = true;
                                        break;
                                    }
                                }

                                if(fLRSenderCheck){
                                    LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- VALID tx out: %d, LockReward for SINtype: %d, address: %d\n", txIndex, SINType, addressTxDIN2);
                                    fCandidateValid = true;
                                } else {
                                    LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- %s <<<<>>>> %s\n", ScriptToAsmStr(v.scriptPubKey), ScriptToAsmStr(senderScript));
                                    LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- Found LR, but sender is NOT VALID\n");
                                }
                            } else {
                                LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- LR found for height but NOT VALID: %s\n", sErrorCheck);
                            }
                        }
                    }

                    //LR and amount of reward is valid, check script to make sure that destination is candidate
                    if(fCandidateValid){
                        if (txout.scriptPubKey == infOwner.GetInfo().scriptPubKey){
                            LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- VALID tx out: %d, Payment for SINtype: %d, address: %d\n", txIndex, SINType, addressTxDIN2);
                            counterNodePayment ++;
                        }
                    }
                    //No LR found for candidate => payment is correct if reward is burnt
                    else {
                        if (txout.scriptPubKey == burnfundScript){
                            LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- VALID tx out: %d, No LR for SINtype: %d, burnd it: %d.\n", txIndex, SINType, addressTxDIN2);
                            counterNodePayment ++;
                        }
                    }
                }
                //Not found candidate, payment is correct if reward is burnt
                else {
                    if (txout.scriptPubKey == burnfundScript){
                        LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- VALID tx out: %d, No Candiate found for SINtype: %d.\n", txIndex, SINType);
                        counterNodePayment ++;
                    }
                }
            } // from 6 to 8th positiion of payment small payment for VPS
            if (6 <= txIndex && txIndex <=8) {
                //BEGIN
                CScript DINPayeeNode;

                int SINType = 0;
                //choose tier value
                if (txIndex == 6) {
                    SINType = 10;
                } else if (txIndex == 7) {
                    SINType = 5;
                } else {
                    SINType = 1;
                }
                //candidate for this Height
                //check if exist a LR for candidate: Yes: Must pay for him with exact Amount; No: Burn
                CInfinitynode infOwner;
                std::string sErrorCheck = "";

                LOCK(infnodeman.cs);
                bool fBurnRewardNode = false;
                bool fNodeAddressValid = false;

                CAmount InfPayment = 0;
                InfPayment = Params().GetConsensus().nMasternodeBurnSINNODE_10;

                CTxDestination addressTxDIN;
                std::string addressTxDIN2 = "";
                ExtractDestination(txout.scriptPubKey, addressTxDIN);
                addressTxDIN2 = EncodeDestination(addressTxDIN);

                if (infnodeman.deterministicRewardAtHeight(nBlockHeight, SINType, infOwner)){
                    CMetadata metaSender = infnodemeta.Find(infOwner.getMetaID());
                    if (metaSender.getMetadataHeight() == 0){
                        LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- Not found metadata for candidate at height: %d\n", nBlockHeight);
                        fBurnRewardNode=true;
                    }
                    //payment to the last metadata info, so do not do further check

                    if(!fBurnRewardNode){
                        std::string metaPublicKey = metaSender.getMetaPublicKey();
                        std::vector<unsigned char> tx_data = DecodeBase64(metaPublicKey.c_str());
                        CPubKey pubKey(tx_data.begin(), tx_data.end());
                        if(pubKey.IsValid() && pubKey.IsCompressed()){
                            CTxDestination dest = GetDestinationForKey(pubKey, OutputType::LEGACY);
                            std::string address2 = EncodeDestination(dest);
                            LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- payment for node: %s amount %lld\n",address2, InfPayment);

                            DINPayeeNode = GetScriptForDestination(dest);
                            if(txout.scriptPubKey == DINPayeeNode && txout.nValue == InfPayment) {
                                fNodeAddressValid = true;
                                fBurnRewardNode = false;
                            }
                        }else{
                            fBurnRewardNode=true;
                        }
                    }
                } else {
                    LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- can not found infinitynode candidate %d at height %d\n", SINType, nBlockHeight);
                    fBurnRewardNode=true;
                }

                if(fNodeAddressValid == true && fBurnRewardNode == false) {
                    LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- VALID tx out: %d, Payment for SINtype: %d, address: %d\n", txIndex, SINType, addressTxDIN2);
                    counterNodePayment ++;
                } else if (fNodeAddressValid == false && fBurnRewardNode == true) {
                    if (txout.scriptPubKey == burnfundScript){
                        LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- VALID tx out: %d, No Candiate found for SINtype: %d.\n", txIndex, SINType);
                        counterNodePayment ++;
                    }
                }
            }
        }//end loop output

        if ( counterNodePayment == 6 ) {
            LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- 6 payments are validated\n");
            return true;
        } else {
            LogPrint(BCLog::INFINITYLOCK, "LockRewardValidation -- ERROR: Missing required payment\n");
            return false;
        }
    }
}

/*
 * Connect to group Signer, top N score of rewardHeight
 */
void CInfinityNodeLockReward::TryConnectToMySigners(int rewardHeight, CConnman& connman)
{
    if(fLiteMode || !fInfinityNode) return;

    AssertLockHeld(cs);

    int nSINtypeCanLockReward = Params().GetConsensus().nInfinityNodeLockRewardSINType;

    uint256 nBlockHash = uint256();
    if (!GetBlockHash(nBlockHash, rewardHeight - 101)) {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::%s -- ERROR: GetBlockHash() failed at nBlockHeight %d\n", __func__, rewardHeight - 101);
        return;
    }

    std::vector<CInfinitynode> vecScoreInf;
    if(!infnodeman.getTopNodeScoreAtHeight(nSINtypeCanLockReward, rewardHeight - 101,
                                           Params().GetConsensus().nInfinityNodeLockRewardTop, vecScoreInf))
    {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward:: Can not get Top Node at height %d",rewardHeight - 101);
        return;
    }

/*
    std::map<int, CInfinitynode> mapInfinityNodeRank = infnodeman.calculInfinityNodeRank(rewardHeight, nSINtypeCanLockReward, false, true);
*/
    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::TryConnectToMySigners -- Try connect to %d TopNode. Vector score: %d\n",
              Params().GetConsensus().nInfinityNodeLockRewardTop, vecScoreInf.size());

    int score  = 0;
    for (auto& s : vecScoreInf){
        if(score <= Params().GetConsensus().nInfinityNodeLockRewardTop){
            CMetadata metaTopNode = infnodemeta.Find(s.getMetaID());
            std::string connectionType = "";

            if(metaTopNode.getMetadataHeight() == 0){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::TryConnectToMySigners -- Cannot find metadata of TopNode score: %d, id: %s\n",
                                 score, s.getBurntxOutPoint().ToStringShort());
                score++;
                continue;
            }

            CService addr = metaTopNode.getService();
            CAddress add = CAddress(addr, NODE_NETWORK);
            bool fconnected = false;

            if(addr != infinitynodePeer.service){
                std::vector<CNode*> vNodesCopy = connman.CopyNodeVector();
                for (auto* pnode : vNodesCopy)
                {
                    if (pnode->addr.ToStringIP() == add.ToStringIP()){
                        fconnected = true;
                        connectionType = strprintf("connection exist(%d - %s)", pnode->GetId(), add.ToStringIP());
                        break;
                    }
                }
                // looped through all nodes, release them
                connman.ReleaseNodeVector(vNodesCopy);
            }else{
                fconnected = true;
                connectionType = "I am";
            }

            if(!fconnected){
                CNode* pnode = connman.OpenNetworkConnection(add, false, nullptr, NULL, false, false, false, true);
                if(pnode == NULL) {
                } else {
                    fconnected = true;
                    connectionType = strprintf("new connection(%s)", add.ToStringIP());
                }
            }

            if(fconnected){
                 LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::TryConnectToMySigners -- %s TopNode score: %d, id: %s\n",
                                 connectionType, score, s.getBurntxOutPoint().ToStringShort());
            } else {
                 LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::TryConnectToMySigners -- Cannot try to connect TopNode score: %d, id: %s.\n",
                                 score, s.getBurntxOutPoint().ToStringShort());
            }
        }

        score++;
    }
}

/*
 * STEP 0: create LockRewardRequest if i am a candidate at nHeight
 */
bool CInfinityNodeLockReward::ProcessBlock(int nBlockHeight, CConnman& connman)
{
    if(fLiteMode || !fInfinityNode){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessBlock -- Lite mode or not Infinitynode\n");
        return false;
    }
    //DIN must be built before begin the process
    if(infnodeman.isReachedLastBlock() == false){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessBlock -- Downloading block! wait...\n");
        return false;
    }
    //mypeer must have status STARTED
    if(infinitynodePeer.nState != INFINITYNODE_PEER_STARTED){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessBlock -- Node is not started! Can not process block\n");
        return false;
    }

    //step 0.1: Check if this InfinitynodePeer is a candidate at nBlockHeight
    CInfinitynode infRet;
    if(!infnodeman.Get(infinitynodePeer.burntx, infRet)){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessBlock -- Can not identify mypeer in list, height: %d\n", nBlockHeight);
        return false;
    }

    int nRewardHeight = infnodeman.isPossibleForLockReward(infinitynodePeer.burntx);

    LOCK2(cs_main, cs);
    if(nRewardHeight == 0 || (nRewardHeight < (nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardLoop))){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessBlock -- Try to LockReward false at height %d\n", nBlockHeight);
        mapSigners.clear();
        mapMyPartialSigns.clear();
        currentLockRequestHash = uint256();
        nFutureRewardHeight = 0;
        nGroupSigners = 0;
        return false;
    }

    //step 0.2 we know that nRewardHeight >= nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardLoop
    int loop = (Params().GetConsensus().nInfinityNodeCallLockRewardDeepth / (nRewardHeight - nCachedBlockHeight)) - 1;
    CLockRewardRequest newRequest(nRewardHeight, infRet.getBurntxOutPoint(), infRet.getSINType(), loop);
    if (newRequest.Sign(infinitynodePeer.keyInfinitynode, infinitynodePeer.pubKeyInfinitynode)) {
        if (AddLockRewardRequest(newRequest)) {
            //step 0.3 identify all TopNode at nRewardHeight and try make a connection with them ( it is an optimisation )
            TryConnectToMySigners(nRewardHeight, connman);
            //track my last request
            mapSigners.clear();
            currentLockRequestHash = newRequest.GetHash();
            nFutureRewardHeight = newRequest.nRewardHeight;
            nGroupSigners = 0;
            //
            if(loop ==0){
                mapMyPartialSigns.clear();
            }
            //relay it
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessBlock -- relay my LockRequest loop: %d, hash: %s\n", loop, newRequest.GetHash().ToString());
            newRequest.Relay(connman);
            return true;
        }
    }
    return false;
}

void CInfinityNodeLockReward::ProcessDirectMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode  || !fInfinityNode) return;

    if (strCommand == NetMsgType::INFVERIFY) {
        CVerifyRequest vrequest;
        vRecv >> vrequest;
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessDirectMessage -- new VerifyRequest from %d, Sig1: %d, Sig2: %d, hash: %s\n",
                     pfrom->GetId(), vrequest.vchSig1.size(), vrequest.vchSig2.size(), vrequest.GetHash().ToString());
        pfrom->setAskFor.erase(vrequest.GetHash());
        {
            LOCK2(cs_main, cs);
            if(vrequest.vchSig1.size() > 0 &&  vrequest.vchSig2.size() == 0) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessDirectMessage -- VerifyRequest: I am candidate. Reply the verify from: %d, hash: %s\n",
                          pfrom->GetId(), vrequest.GetHash().ToString());
                SendVerifyReply(pfrom, vrequest, connman);
            } else if(vrequest.vchSig1.size() > 0 &&  vrequest.vchSig2.size() > 0) {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessDirectMessage -- VerifyRequest: I am TopNode. Receive a reply from candidate %d, hash: %s\n",
                          pfrom->GetId(), vrequest.GetHash().ToString());
                if(CheckVerifyReply(pfrom, vrequest, connman)){
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessDirectMessage -- Candidate is valid. Broadcast the my Rpubkey for Musig and disconnect the direct connect to candidata\n");
                }else{
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessDirectMessage -- Candidate is NOT valid.\n");
                }
            }
            return;
        }
    }
}

void CInfinityNodeLockReward::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman& connman)
{
    if(fLiteMode) return; // disable all SIN specific functionality

    //if we are downloading blocks, do nothing
    if(!infnodeman.isReachedLastBlock()){return;}

    if (strCommand == NetMsgType::INFLOCKREWARDINIT) {
        CLockRewardRequest lockReq;
        vRecv >> lockReq;
        //dont ask pfrom for this Request anymore
        uint256 nHash = lockReq.GetHash();
        pfrom->setAskFor.erase(nHash);
        {
            LOCK2(cs_main, cs);
            if(mapLockRewardRequest.count(nHash)){
                LogPrintf("CInfinityNodeLockReward::ProcessMessage -- I had this LockRequest %s. End process\n", nHash.ToString());
                return;
            }
            if(!CheckLockRewardRequest(pfrom, lockReq, connman, nCachedBlockHeight)){
                return;
            }
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- receive and add new LockRewardRequest from %d\n",pfrom->GetId());
            if(AddLockRewardRequest(lockReq)){
                lockReq.Relay(connman);
                if(!CheckMyPeerAndSendVerifyRequest(pfrom, lockReq, connman)){
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- CheckMyPeerAndSendVerifyRequest is false.\n");
                    return;
                }
            }
            return;
        }
    } else if (strCommand == NetMsgType::INFCOMMITMENT) {
        CLockRewardCommitment commitment;
        vRecv >> commitment;
        uint256 nHash = commitment.GetHash();
        pfrom->setAskFor.erase(nHash);
        {
            LOCK2(cs_main, cs);
            if(mapLockRewardCommitment.count(nHash)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- I had this commitment %s. End process\n", nHash.ToString());
                return;
            }
            if(!CheckCommitment(pfrom, commitment)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- Commitment is false from: %d\n",pfrom->GetId());
                return;
            }
            if(AddCommitment(commitment)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- relay Commitment for LockRequest %s. Remind nFutureRewardHeight: %d, LockRequest: %s\n",
                           commitment.nHashRequest.ToString(), nFutureRewardHeight, currentLockRequestHash.ToString());
                commitment.Relay(connman);
                AddMySignersMap(commitment);
                FindAndSendSignersGroup(connman);
            } else {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- commitment received. Dont do anything\n");
            }
            return;
        }
    } else if (strCommand == NetMsgType::INFLRGROUP) {
        CGroupSigners gSigners;
        vRecv >> gSigners;
        uint256 nHash = gSigners.GetHash();
        pfrom->setAskFor.erase(nHash);
        {
            LOCK2(cs_main, cs);
            if(mapLockRewardGroupSigners.count(nHash)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- I had this group signer: %s. End process\n", nHash.ToString());
                return;
            }
            if(!CheckGroupSigner(pfrom, gSigners)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- CheckGroupSigner is false\n");
                return;
            }
            if(AddGroupSigners(gSigners)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- receive group signer %s for lockrequest %s\n",
                          gSigners.signersId, gSigners.nHashRequest.ToString());
            }
            gSigners.Relay(connman);
            if(!MusigPartialSign(pfrom, gSigners, connman)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- MusigPartialSign is false\n");
            }
            return;
        }
    } else if (strCommand == NetMsgType::INFLRMUSIG) {
        CMusigPartialSignLR partialSign;
        vRecv >> partialSign;
        uint256 nHash = partialSign.GetHash();
        pfrom->setAskFor.erase(nHash);
        {
            LOCK2(cs_main, cs);
            if(mapPartialSign.count(nHash)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- I had this Partial Sign %s. End process\n", nHash.ToString());
                return;
            }
            if(!CheckMusigPartialSignLR(pfrom, partialSign)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- CheckMusigPartialSignLR is false\n");
                return;
            }
            if(AddMusigPartialSignLR(partialSign)){
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- receive Partial Sign from %s of group %s, hash: %s\n",
                          partialSign.vin.prevout.ToStringShort(), partialSign.nHashGroupSigners.ToString(), partialSign.GetHash().ToString());
                partialSign.Relay(connman);
                AddMyPartialSignsMap(partialSign);
                if (!FindAndBuildMusigLockReward()) {
                    LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- Couldn't build MuSig\n");
                    return;
                }
            } else {
                LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::ProcessMessage -- Partial Sign received. Dont do anything\n");
            }
            return;
        }
    }
}

void CInfinityNodeLockReward::UpdatedBlockTip(const CBlockIndex *pindex, CConnman& connman)
{
    if(!pindex) return;

    nCachedBlockHeight = pindex->nHeight;

    //CheckPreviousBlockVotes(nFutureBlock);
    if(infnodeman.isReachedLastBlock()){
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::UpdatedBlockTip -- nCachedBlockHeight=%d\n", nCachedBlockHeight);
        int nFutureBlock = nCachedBlockHeight + Params().GetConsensus().nInfinityNodeCallLockRewardDeepth;
        ProcessBlock(nFutureBlock, connman);
    } else {
        LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::UpdatedBlockTip -- nCachedBlockHeight=%d. BUT ReachedLastBlock is FALSE => do nothing!\n", nCachedBlockHeight);
    }
}


void CInfinityNodeLockReward::CheckAndRemove(CConnman& connman)
{
    /*this function is called in InfinityNode thread*/
    LOCK(cs); //cs_main needs to be called by the parent function

    //nothing to remove
    if (nCachedBlockHeight <= Params().GetConsensus().nInfinityNodeBeginHeight) { return;}

    //remove mapLockRewardRequest
    std::map<uint256, CLockRewardRequest>::iterator itRequest = mapLockRewardRequest.begin();
    while(itRequest != mapLockRewardRequest.end()) {
        if(itRequest->second.nRewardHeight < nCachedBlockHeight - LIMIT_MEMORY)
        {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckAndRemove -- remove mapLockRewardRequest for height: %d, current: %d\n",
                     itRequest->second.nRewardHeight, nCachedBlockHeight);
            mapSigners.erase(itRequest->second.GetHash());
            mapLockRewardRequest.erase(itRequest++);
        }else{
            ++itRequest;
        }
    }

    //remove mapLockRewardCommitment
    std::map<uint256, CLockRewardCommitment>::iterator itCommit = mapLockRewardCommitment.begin();
    while(itCommit != mapLockRewardCommitment.end()) {
        if (itCommit->second.nRewardHeight < nCachedBlockHeight - LIMIT_MEMORY) {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckAndRemove -- remove mapLockRewardCommitment for height: %d, current: %d\n",
                     itCommit->second.nRewardHeight, nCachedBlockHeight);
            mapLockRewardCommitment.erase(itCommit++);
        } else {
            ++itCommit;
        }
    }

    //remove mapLockRewardGroupSigners
    std::map<uint256, CGroupSigners>::iterator itGroup = mapLockRewardGroupSigners.begin();
    while(itGroup != mapLockRewardGroupSigners.end()) {
        if (itGroup->second.nRewardHeight < nCachedBlockHeight - LIMIT_MEMORY) {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckAndRemove -- remove mapLockRewardGroupSigners for height: %d, current: %d\n",
                     itGroup->second.nRewardHeight, nCachedBlockHeight);
            mapLockRewardGroupSigners.erase(itGroup++);
        } else {
            ++itGroup;
        }
    }

    //remove mapPartialSign
    std::map<uint256, CMusigPartialSignLR>::iterator itSign = mapPartialSign.begin();
    while(itSign != mapPartialSign.end()) {
        if (itSign->second.nRewardHeight < nCachedBlockHeight - LIMIT_MEMORY) {
            LogPrint(BCLog::INFINITYLOCK,"CInfinityNodeLockReward::CheckAndRemove -- remove mapPartialSign for height: %d, current: %d\n",
                     itSign->second.nRewardHeight, nCachedBlockHeight);
            mapMyPartialSigns.erase(itSign->second.nHashGroupSigners);
            mapPartialSign.erase(itSign++);
        } else {
            ++itSign;
        }
    }
}

//call in infinitynode.cpp: show memory size
std::string CInfinityNodeLockReward::GetMemorySize()
{
    LOCK(cs);
    std::string ret = "";
    ret = strprintf("Request: %d, Commitment: %d, GroupSigners: %d, mapPartialSign: %d", mapLockRewardRequest.size(),
                     mapLockRewardCommitment.size(), mapLockRewardGroupSigners.size(), mapPartialSign.size());
    return ret;
}

/* static */ int ECCMusigHandle::refcount = 0;

ECCMusigHandle::ECCMusigHandle()
{
    if (refcount == 0) {
        assert(secp256k1_context_musig == nullptr);
        secp256k1_context_musig = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_NONE);
        assert(secp256k1_context_musig != nullptr);
    }
    refcount++;
}

ECCMusigHandle::~ECCMusigHandle()
{
    refcount--;
    if (refcount == 0) {
        assert(secp256k1_context_musig != nullptr);
        secp256k1_context_destroy(secp256k1_context_musig);
        secp256k1_context_musig = nullptr;
    }
}
