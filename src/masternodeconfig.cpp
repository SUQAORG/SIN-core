// Copyright (c) 2014-2017 The Dash Core developers
// Copyright (c) 2018 FXTC developers
// Copyright (c) 2018-2019 SIN developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <masternodeconfig.h>
//#include <netbase.h>
#include <util/system.h>
#include <util/strencodings.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

CMasternodeConfig masternodeConfig;

void CMasternodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex,
                           std::string txHashBurnFund, std::string outputIndexBurnFund) {
    CMasternodeEntry cme(alias, ip, privKey, txHash, outputIndex, txHashBurnFund, outputIndexBurnFund);
    entries.push_back(cme);
}

bool CMasternodeConfig::read(std::string& strErr) {
    int linenumber = 1;
    boost::filesystem::path pathMasternodeConfigFile = GetConfigFile(gArgs.GetArg(MASTERNODE_CONF_FILENAME_ARG, MASTERNODE_CONF_FILENAME));
    boost::filesystem::ifstream streamConfig(pathMasternodeConfigFile);

    if (!streamConfig.good()) {

        FILE* configFile = fopen(pathMasternodeConfigFile.string().c_str(), "a");
        if (configFile != NULL) {
            std::string strHeader = "# infinitynode config file\n"
                          "# Format: alias IP:port infinitynodeprivkey collateral_output_txid collateral_output_index burnfund_output_txid burnfund_output_index\n"
                          "# infinitynode1 127.0.0.1:20980 7RVuQhi45vfazyVtskTRLBgNuSrYGecS5zj2xERaooFVnWKKjhS b7ed8c1396cf57ac78d756186b6022d3023fd2f1c338b7fbae42d342fdd7070a 0 563d9434e816b3e8ffc5347c6b8db07509de6068f6759f21a16be5d92b7e3111 1\n";
            fwrite(strHeader.c_str(), std::strlen(strHeader.c_str()), 1, configFile);
            fclose(configFile);
        }
        return true; // Nothing to read, so just return
    }

    for(std::string line; std::getline(streamConfig, line); linenumber++)
    {
        if(line.empty())
        {
             LogPrintf("* line is empty\n");
             continue;
        }

        std::istringstream iss(line);
        std::string comment, alias, ip, privKey, txHash, outputIndex, txHashBurnFund, outputIndexBurnFund;

        LogPrintf("* parsing line '%s'\n",line.c_str());

        if (iss >> comment) {
            if(comment.at(0) == '#') continue;
            iss.str(line);
            iss.clear();
        }

        if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex >> txHashBurnFund >> outputIndexBurnFund)) {
            iss.str(line);
            iss.clear();
            if (!(iss >> alias >> ip >> privKey >> txHash >> outputIndex >> txHashBurnFund >> outputIndexBurnFund)) {
                strErr = _("Could not parse infinitynode.conf") + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
                streamConfig.close();
                return false;
            }
        }

        int port = 0;
        std::string hostname = "";
        SplitHostPort(ip, port, hostname);
        if(port == 0 || hostname == "") {
            strErr = _("Failed to parse host:port string") + "\n"+
                    strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"";
            streamConfig.close();
            return false;
        }
        if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
            if(port != Params().GetDefaultPort()) {
                strErr = _("Invalid port detected in infinitynode.conf") + "\n" +
                        strprintf(_("Port: %d"), port) + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                        strprintf(_("(must be %d for mainnet)"), Params().GetDefaultPort());
                streamConfig.close();
                return false;
            }
        } else if(port == Params().GetMainnetPort()) {
            strErr = _("Invalid port detected in infinitynode.conf") + "\n" +
                    strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                    strprintf(_("(%d could be used only on mainnet)"), Params().GetDefaultPort());
            streamConfig.close();
            return false;
        }

        if(Params().NetworkIDString() == CBaseChainParams::TESTNET) {
            if(port != Params().GetDefaultPort()) {
                strErr = _("Invalid port detected in infinitynode.conf") + "\n" +
                        strprintf(_("Port: %d"), port) + "\n" +
                        strprintf(_("Line: %d"), linenumber) + "\n\"" + line + "\"" + "\n" +
                        strprintf(_("(must be %d for mainnet)"), Params().GetDefaultPort());
                streamConfig.close();
                return false;
            }
        }


        add(alias, ip, privKey, txHash, outputIndex, txHashBurnFund, outputIndexBurnFund);
    }

    streamConfig.close();
    return true;
}
