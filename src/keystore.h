// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.
#ifndef ARGENCOIN_KEYSTORE_H
#define ARGENCOIN_KEYSTORE_H

#include "crypter.h"

class CKeyStore
{
protected:
    mutable CCriticalSection cs_KeyStore;

public:
    virtual bool AddKey(const CKey& key) =0;
    virtual bool HaveKey(const CArgencoinAddress &address) const =0;
    virtual bool GetKey(const CArgencoinAddress &address, CKey& keyOut) const =0;
    virtual bool GetPubKey(const CArgencoinAddress &address, std::vector<unsigned char>& vchPubKeyOut) const;
    virtual std::vector<unsigned char> GenerateNewKey();
};

typedef std::map<CArgencoinAddress, CSecret> KeyMap;

class CBasicKeyStore : public CKeyStore
{
protected:
    KeyMap mapKeys;

public:
    bool AddKey(const CKey& key);
    bool HaveKey(const CArgencoinAddress &address) const
    {
        bool result;
        CRITICAL_BLOCK(cs_KeyStore)
            result = (mapKeys.count(address) > 0);
        return result;
    }
    bool GetKey(const CArgencoinAddress &address, CKey& keyOut) const
    {
        CRITICAL_BLOCK(cs_KeyStore)
        {
            KeyMap::const_iterator mi = mapKeys.find(address);
            if (mi != mapKeys.end())
            {
                keyOut.SetSecret((*mi).second);
                return true;
            }
        }
        return false;
    }
};

typedef std::map<CArgencoinAddress, std::pair<std::vector<unsigned char>, std::vector<unsigned char> > > CryptedKeyMap;

class CCryptoKeyStore : public CBasicKeyStore
{
private:
    CryptedKeyMap mapCryptedKeys;

    CKeyingMaterial vMasterKey;

    // if fUseCrypto is true, mapKeys must be empty
    // if fUseCrypto is false, vMasterKey must be empty
    bool fUseCrypto;

protected:
    bool SetCrypted();

    // will encrypt previously unencrypted keys
    bool EncryptKeys(CKeyingMaterial& vMasterKeyIn);

    bool Unlock(const CKeyingMaterial& vMasterKeyIn);

public:
    CCryptoKeyStore() : fUseCrypto(false)
    {
    }

    bool IsCrypted() const
    {
        return fUseCrypto;
    }

    bool IsLocked() const
    {
        if (!IsCrypted())
            return false;
        bool result;
        CRITICAL_BLOCK(cs_KeyStore)
            result = vMasterKey.empty();
        return result;
    }

    bool Lock()
    {
        if (!SetCrypted())
            return false;

        CRITICAL_BLOCK(cs_KeyStore)
            vMasterKey.clear();

        return true;
    }

    virtual bool AddCryptedKey(const std::vector<unsigned char> &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    std::vector<unsigned char> GenerateNewKey();
    bool AddKey(const CKey& key);
    bool HaveKey(const CArgencoinAddress &address) const
    {
        CRITICAL_BLOCK(cs_KeyStore)
        {
            if (!IsCrypted())
                return CBasicKeyStore::HaveKey(address);
            return mapCryptedKeys.count(address) > 0;
        }
    }
    bool GetKey(const CArgencoinAddress &address, CKey& keyOut) const;
    bool GetPubKey(const CArgencoinAddress &address, std::vector<unsigned char>& vchPubKeyOut) const;
};

#endif
