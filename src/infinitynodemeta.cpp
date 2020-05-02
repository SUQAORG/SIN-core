// Copyright (c) 2018-2020 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <infinitynodemeta.h>
#include <infinitynodeman.h>
#include <util/system.h> //fMasterNode variable
#include <flat-database.h>
#include <util/strencodings.h>

CInfinitynodeMeta infnodemeta;

const std::string CInfinitynodeMeta::SERIALIZATION_VERSION_STRING = "CInfinitynodeMeta-Version-1";

CInfinitynodeMeta::CInfinitynodeMeta()
: cs(),
  mapNodeMetadata()
{}

void CInfinitynodeMeta::Clear()
{
    LOCK(cs);
    mapNodeMetadata.clear();
}

bool CInfinitynodeMeta::Add(CMetadata &meta)
{
    LOCK(cs);
    LogPrintf("CInfinitynodeMeta::new Metadata from %s %d\n", meta.getMetaID(), meta.getMetadataHeight());
    auto it = mapNodeMetadata.find(meta.getMetaID());
    if(it == mapNodeMetadata.end()){
        LogPrintf("CInfinitynodeMeta::1st metadata from %s\n", meta.getMetaID());
        mapNodeMetadata[meta.getMetaID()] = meta;
        return true;
    } else {
        CMetadata m = it->second;
        if(m.getMetaID() == meta.getMetaID() && meta.getMetadataHeight() >  m.getMetadataHeight()){
            LogPrintf("CInfinitynodeMeta::new metadata from higher height %s\n", meta.getMetaID());
            mapNodeMetadata.erase(meta.getMetaID());
            mapNodeMetadata[meta.getMetaID()] = meta;
            return true;
        }else{
            LogPrintf("CInfinitynodeMeta::nHeight is lower than current height %d\n", m.getMetadataHeight());
            return false;
        }
    }
}

bool CInfinitynodeMeta::Has(std::string  metaID)
{
    LOCK(cs);
    return mapNodeMetadata.find(metaID) != mapNodeMetadata.end();
}

CMetadata CInfinitynodeMeta::Find(std::string  metaID)
{
    LOCK(cs);
    CMetadata meta;
    auto it = mapNodeMetadata.find(metaID);
    if(it != mapNodeMetadata.end()){meta = it->second;}
    return meta;
}

bool CInfinitynodeMeta::Get(std::string  nodePublicKey, CMetadata& meta)
{
    bool res = false;
    LOCK(cs);
    for (auto& infpair : mapNodeMetadata) {
        CMetadata m = infpair.second;
        if(m.getMetaPublicKey() == nodePublicKey){
            meta = m;
            res = true;
        }
    }
    return res;
}

bool CInfinitynodeMeta::metaScan(int nBlockHeight)
{
    Clear();
    LogPrintf("CInfinitynodeMeta::metaScan -- Cleared map. Size is %d\n", (int)mapNodeMetadata.size());
    if (nBlockHeight <= Params().GetConsensus().nInfinityNodeGenesisStatement) return false;
    uint256 blockHash;
    if(!GetBlockHash(blockHash, nBlockHeight)) {
        LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMeta::metaScan -- can not read block hash\n");
        return false;
    }

    CBlockIndex* pindex;
    pindex = LookupBlockIndex(blockHash);
    CBlockIndex* prevBlockIndex = pindex;

    while (prevBlockIndex->nHeight >= Params().GetConsensus().nInfinityNodeGenesisStatement)
    {
        CBlock blockReadFromDisk;
        if (ReadBlockFromDisk(blockReadFromDisk, prevBlockIndex, Params().GetConsensus()))
        {
            for (const CTransactionRef& tx : blockReadFromDisk.vtx) {
                //Not coinbase
                if (!tx->IsCoinBase()) {
                   for (unsigned int i = 0; i < tx->vout.size(); i++) {
                        const CTxOut& out = tx->vout[i];
                        std::vector<std::vector<unsigned char>> vSolutions;
                        txnouttype whichType;
                        const CScript& prevScript = out.scriptPubKey;
                        Solver(prevScript, whichType, vSolutions);
                        //Send to Metadata
                        if (whichType == TX_BURN_DATA && Params().GetConsensus().cMetadataAddress == EncodeDestination(CKeyID(uint160(vSolutions[0]))))
                        {
                          //Amount for UpdateMeta
                            if ( (Params().GetConsensus().nInfinityNodeUpdateMeta - 1) * COIN <= out.nValue
                                 && out.nValue <= (Params().GetConsensus().nInfinityNodeUpdateMeta) * COIN){
                                if (vSolutions.size() == 2){
                                    std::string metadata(vSolutions[1].begin(), vSolutions[1].end());
                                    string s;
                                    stringstream ss(metadata);
                                    int i=0;
                                    int check=0;
                                    std::string publicKeyString;
                                    CService service;
                                    std::string burnTxID;
                                    while (getline(ss, s,';')) {
                                        CTxDestination NodeAddress;
                                        //1st position: publicKey
                                        if (i==0) {
                                            publicKeyString = s;
                                            std::vector<unsigned char> tx_data = DecodeBase64(publicKeyString.c_str());
                                            LogPrintf("CInfinitynodeMeta::metaScan -- publicKey: %s\n", publicKeyString);
                                            CPubKey decodePubKey(tx_data.begin(), tx_data.end());
                                            if (decodePubKey.IsValid()) {
                                                check++;
                                            }else{
                                                LogPrintf("CInfinitynodeMeta::metaScan -- ERROR: publicKey is not valid: %s\n", publicKeyString);
                                            }
                                        }
                                        //2nd position: Node IP
                                        if (i==1 && Lookup(s.c_str(), service, 0, false)) {
                                            check++;
                                        }
                                        //3th position: 12 character from Infinitynode BurnTx
                                        if (i==2 && s.length() >= 16) {
                                            check++;
                                            burnTxID = s.substr(0, 16);
                                        }
                                        //Update node metadata if nHeight is bigger
                                        if (check == 3){
                                            //prevBlockIndex->nHeight
                                            const CTxIn& txin = tx->vin[0];
                                            int index = txin.prevout.n;

                                            CTransactionRef prevtx;
                                            uint256 hashblock;
                                            if(!GetTransaction(txin.prevout.hash, prevtx, Params().GetConsensus(), hashblock, false)) {
                                                LogPrintf("CInfinitynodeMeta::metaScan -- PrevBurnFund tx is not in block.\n");
                                                return false;
                                            }

                                            CTxDestination addressBurnFund;
                                            if(!ExtractDestination(prevtx->vout[index].scriptPubKey, addressBurnFund)){
                                                LogPrintf("CInfinitynodeMeta::metaScan -- False when extract payee from BurnFund tx.\n");
                                                return false;
                                            }

                                            std::ostringstream streamInfo;
                                            streamInfo << EncodeDestination(addressBurnFund) << "-" << burnTxID;

                                            LogPrintf("CInfinitynodeMeta:: meta update: %s, %s, %s, %d\n", 
                                                         streamInfo.str(), publicKeyString, service.ToString(), prevBlockIndex->nHeight);
                                            int avtiveBK = 0;
                                            int nHeight = prevBlockIndex->nHeight;
                                            CMetadata meta = CMetadata(streamInfo.str(), publicKeyString, service, nHeight, avtiveBK);
                                            Add(meta);
                                        }
                                        i++;
                                    }
                                }
                            }
                        } // Send to metadata
                    }
                }
            }
        } else {
            LogPrint(BCLog::INFINITYNODE, "CInfinitynodeMeta::metaScan -- can not read block from disk\n");
            return false;
        }
        // continue with previous block
        prevBlockIndex = prevBlockIndex->pprev;
    }

    CFlatDB<CInfinitynodeMeta> flatdb7("infinitynodemeta.dat", "magicInfinityMeta");
    flatdb7.Dump(infnodemeta);

    return true;
}

bool CInfinitynodeMeta::setActiveBKAddress(std::string  metaID)
{
    LOCK(cs);
    auto it = mapNodeMetadata.find(metaID);
    if(it == mapNodeMetadata.end()){
        return false;
    } else {
        int active = 1;
        mapNodeMetadata[metaID].setBackupAddress(active);
        return true;
    }
}

std::string CInfinitynodeMeta::ToString() const
{
    std::ostringstream info;
    LOCK(cs);
    info << "Metadata: " << (int)mapNodeMetadata.size() << "\n";
    for (auto& infpair : mapNodeMetadata) {
        CMetadata m = infpair.second;
        info << " MetadataID: " << infpair.first << " PublicKey: " << m.getMetaPublicKey();
    }

    return info.str();
}