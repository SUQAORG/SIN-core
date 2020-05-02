// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIN_INFINITYNODEPEER_H
#define SIN_INFINITYNODEPEER_H

#include <chainparams.h>
#include <key.h>
#include <net.h>
#include <primitives/transaction.h>

class CInfinitynodePeer;

static const int INFINITYNODE_PEER_INITIAL          = 0; // initial state
static const int INFINITYNODE_PEER_INPUT_TOO_NEW    = 1;
static const int INFINITYNODE_PEER_NOT_CAPABLE      = 2;
static const int INFINITYNODE_PEER_STARTED          = 3;

extern CInfinitynodePeer infinitynodePeer;

class CInfinitynodePeer
{
public:
    enum infinitynode_type_enum_t {
        INFINITYNODE_UNKNOWN = 0,
        INFINITYNODE_REMOTE  = 1
    };

private:

    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    infinitynode_type_enum_t eType;

    bool fPingerEnabled;

    /// Ping
    bool AutoCheck(CConnman& connman);

public:

    // Keys for the active Infinitynode
    CPubKey pubKeyInfinitynode;
    CKey keyInfinitynode;

    // Initialized while registering Infinitynode
    COutPoint burntx;
    CService service;
    int nSINType;

    int nState; // should be one of INFINITYNODE_PEER_XXX
    std::string strNotCapableReason;


    CInfinitynodePeer()
        : eType(INFINITYNODE_UNKNOWN),
          pubKeyInfinitynode(),
          keyInfinitynode(),
          burntx(),
          service(),
          nSINType(0),
          nState(INFINITYNODE_PEER_INITIAL)
    {}

    /// Manage state of peer
    void ManageState(CConnman& connman);

    std::string GetStateString() const;
    std::string GetStatus() const;
    std::string GetTypeString() const;
    std::string GetMyPeerInfo() const;

private:
    void ManageStateInitial(CConnman& connman);
    void ManageStateRemote();
};

#endif // SIN_INFINITYNODEMAN_H