// Copyright (c) 2018-2020 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIN_INFINITYNODEMETA_H
#define SIN_INFINITYNODEMEYA_H

#include <key.h>
#include <validation.h>
#include <script/standard.h>
#include <key_io.h>

using namespace std;

class CInfinitynodeMeta;
class CMetadata;

extern CInfinitynodeMeta infnodemeta;

class CMetadata
{
private:
    std::string metaID;
    std::string metadataPublicKey;
    CService metadataService;
    int nMetadataHeight;
    int activeBackupAddress;
public:
    CMetadata() :
        metaID(),
        metadataPublicKey(),
        metadataService(),
        nMetadataHeight(0),
        activeBackupAddress(0)
        {}

    CMetadata(std::string metaIDIn, std::string sPublicKey, CService cService, int& nHeight, int& nActive) :
        metaID(metaIDIn),
        metadataPublicKey(sPublicKey),
        metadataService(cService),
        nMetadataHeight(nHeight),
        activeBackupAddress(nActive){}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(metaID);
        READWRITE(metadataPublicKey);
        READWRITE(metadataService);
        READWRITE(nMetadataHeight);
        READWRITE(activeBackupAddress);
    }

    std::string getMetaPublicKey(){return metadataPublicKey;}
    CService getService(){return metadataService;}
    int getMetadataHeight(){return nMetadataHeight;}
    int getFlagActiveBackupAddress(){return activeBackupAddress;}
    std::string getMetaID(){return metaID;}

    void setBackupAddress(int& nActive){activeBackupAddress = nActive;};
};

class CInfinitynodeMeta
{
private:
    static const std::string SERIALIZATION_VERSION_STRING;
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
    // Keep track of current block height
    int nCachedBlockHeight;
public:
    std::map<std::string, CMetadata> mapNodeMetadata;

    CInfinitynodeMeta();

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
        READWRITE(mapNodeMetadata);
    }

    void Clear();
    bool Add(CMetadata &meta);
    bool Has(std::string  metaID);
    CMetadata Find(std::string  metaID);
    bool Get(std::string  nodePublicKey, CMetadata& meta);
    std::map<std::string, CMetadata> GetFullNodeMetadata() { LOCK(cs); return mapNodeMetadata; }

    bool metaScan(int nHeight);
    bool setActiveBKAddress(std::string  metaID);

    std::string ToString() const;
    /// This is dummy overload to be used for dumping/loading mncache.dat
    void CheckAndRemove() {}
};
#endif // SIN_INFINITYNODERSV_H