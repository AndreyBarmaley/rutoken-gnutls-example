/***************************************************************************
 *   Copyright © 2022 by Andrey Afletdinov <public.irkutsk@gmail.com>      *
 *                                                                         *
 *   GnuTLS: crypto wrapper c++                                            *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#ifndef _GNUTLS_CRYPTO_
#define _GNUTLS_CRYPTO_

#include "gnutls/x509.h"
#include "gnutls/gnutls.h"
#include "gnutls/crypto.h"
#include "gnutls/abstract.h"

#include <vector>
#include <string>
#include <memory>
#include <filesystem>

namespace TLS
{
    /// @private
    struct x509_crt
    {
        gnutls_x509_crt_t crt;

        x509_crt(gnutls_x509_crt_t ptr = nullptr) : crt(ptr) {}
        ~x509_crt(){ if(crt) gnutls_x509_crt_deinit(crt); }
    };

    /// @private
    struct public_key
    {
        gnutls_pubkey_t key;

        public_key(gnutls_pubkey_t ptr = nullptr) : key(ptr) {}
        ~public_key(){ if(key) gnutls_pubkey_deinit(key); }
    };

    /// @private
    struct private_key
    {
        gnutls_privkey_t key;

        private_key(gnutls_privkey_t ptr = nullptr) : key(ptr) {}
        ~private_key(){ if(key) gnutls_privkey_deinit(key); }
    };

    /// @private
    struct pkcs7
    {
        gnutls_pkcs7_t ptr;

        pkcs7(gnutls_pkcs7_t val = nullptr) : ptr(val) {}
        ~pkcs7(){ if(ptr) gnutls_pkcs7_deinit(ptr); }
    };

    /// tools
    std::string errorStr(std::string_view func, int err);
    std::vector<uint8_t> randomKey(size_t keysz);

    /// Datum interface
    class Datum
    {
    public:
        virtual ~Datum() {}

        virtual gnutls_datum_t* get(void) = 0;
        virtual const gnutls_datum_t* get(void) const = 0;

        unsigned char* data(void) { return get()->data; }
        const unsigned char* data(void) const { return get()->data; }
        size_t size(void) const { return get()->size; }

        std::string toString(void) const;
        std::vector<uint8_t> toVector(void) const;
        std::string toHexString(std::string_view sep = ",", bool prefix = true) const;
    };

    /// Datum shared
    class DatumShared : public Datum
    {
        std::shared_ptr<gnutls_datum_t> ptr;

    public:
        DatumShared(size_t sz = 0);
        DatumShared(std::string_view str);
        DatumShared(const std::vector<uint8_t> &);
        ~DatumShared();

        const gnutls_datum_t* get(void) const override { return ptr.get(); }
        gnutls_datum_t* get(void) override { return ptr.get(); }

        DatumShared copyAligned(size_t block);

        bool save(const std::filesystem::path &);
        static DatumShared load(const std::filesystem::path &);
    };

    /// Datum const
    class DatumConst : public Datum
    {
        gnutls_datum_t st;

    public:
        DatumConst();
        DatumConst(std::string_view str);
        DatumConst(const uint8_t* ptr, size_t);
        DatumConst(const std::vector<uint8_t> &);

        const gnutls_datum_t* get(void) const override { return & st; }
        gnutls_datum_t* get(void) override { return & st; }
    };

    /// X509 certificate
    class X509Crt
    {
        std::shared_ptr<x509_crt> ptr;

    public:
        X509Crt();
        virtual ~X509Crt() {}

        gnutls_x509_crt_t get(void) { return ptr->crt; }

        static X509Crt import(const Datum &, bool der);
        DatumShared export2(bool der);

        bool setKey(gnutls_x509_privkey_t key);

        int getVersion(void) const;
        time_t getExpirationTime(void) const;
        time_t getActivationTime(void) const;
        std::vector<uint8_t> getFingerPrint(gnutls_digest_algorithm_t algo = GNUTLS_DIG_SHA1) const;
        std::vector<uint8_t> getSerial(void) const;
        std::string getIssuerDN(void) const;
        std::string getOwnerDN(void) const;
        std::pair<gnutls_pk_algorithm_t, int> getAlgoritmBits(void) const;
    };


    /// Public key
    class PublicKey
    {
        std::shared_ptr<public_key> ptr;

    public:
        PublicKey();
        virtual ~PublicKey() {}

        gnutls_pubkey_t get(void) { return ptr->key; }

        static PublicKey importX509(gnutls_x509_crt_t crt);

        DatumShared export2(bool der);
        DatumShared encrypt(const Datum &);

        std::pair<gnutls_pk_algorithm_t, int> getAlgoritmBits(void) const;
    };

    /// PrivKey
    class PrivateKey
    {
        std::shared_ptr<private_key> ptr;

    public:
        PrivateKey();
        virtual ~PrivateKey() {}

        gnutls_privkey_t get(void) { return ptr->key; }

        static PrivateKey importX509(const Datum & dt, bool der);

        bool generate(gnutls_pk_algorithm_t algo, size_t bits);
        DatumShared decrypt(const Datum &);
    };

    /// PKCS7
    class PKCS7
    {
        std::shared_ptr<pkcs7> ptr;

    public:
        PKCS7();
        virtual ~PKCS7() {}

        bool setCrt(gnutls_x509_crt_t crt);

        static PKCS7 import(const Datum &, bool der);
        DatumShared export2(bool der);
    };
}

#endif
