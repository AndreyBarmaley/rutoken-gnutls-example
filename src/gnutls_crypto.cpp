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

#include "gnutls_crypto.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <iterator>
#include <iostream>
#include <algorithm>
#include <exception>

namespace TLS
{
    std::string errorStr(std::string_view func, int err)
    {
        std::ostringstream os;
        os << func << ", error: \"" << gnutls_strerror(err) << "\", code: " << err;
        return os.str();
    }

    std::vector<uint8_t> randomKey(size_t keysz)
    {
        std::vector<uint8_t> res(keysz);

        if(int ret = gnutls_rnd(GNUTLS_RND_KEY, res.data(), res.size()))
            throw std::runtime_error(errorStr("gnutls_rnd", ret));

        return res;
    }

    std::string Datum::toString(void) const
    {
        return std::string(reinterpret_cast<const char*>(data()), size());
    }

    std::vector<uint8_t> Datum::toVector(void) const
    {
        return std::vector<uint8_t>(data(), data() + size());
    }

    std::string Datum::toHexString(std::string_view sep, bool prefix) const
    {
        std::ostringstream os;
        for(size_t it = 0; it != size(); ++it)
        {
            if(prefix)
                os << "0x";
            os << std::setw(2) << std::setfill('0') << std::uppercase << std::hex << static_cast<int>(*(data() + it));
            if(sep.size() && it + 1 != size()) os << sep;
        }

        return os.str();
    }

    /// Datum shared
    DatumShared::DatumShared(size_t sz)
    {
        ptr.reset(new gnutls_datum_t{nullptr, 0});
        if(sz)
        {
            ptr->data = (unsigned char*) gnutls_malloc(sz);
            ptr->size = sz;
        }
    }

    DatumShared::DatumShared(std::string_view str)
    {
        ptr.reset(new gnutls_datum_t{nullptr, 0});
        ptr->data = (unsigned char*) gnutls_malloc(str.size());
        ptr->size = str.size();
        std::copy_n(str.data(), str.size(), ptr->data);
    }

    DatumShared::DatumShared(const std::vector<uint8_t> & vec)
    {
        ptr.reset(new gnutls_datum_t{nullptr, 0});
        ptr->data = (unsigned char*) gnutls_malloc(vec.size());
        ptr->size = vec.size();
        std::copy_n(vec.data(), vec.size(), ptr->data);
    }

    DatumShared::~DatumShared()
    {
        if(ptr.unique() && ptr->data)
            gnutls_free(ptr->data);
    }

    DatumShared DatumShared::copyAligned(size_t block)
    {
        size_t newsz = size() + block - (size() % block);
        if(newsz == size())
            return *this;

        DatumShared dt(newsz);
        std::copy_n(data(), size(), dt.data());
        std::fill_n(dt.data() + size(), dt.size() - size(), 0);

        return dt;
    }

    DatumShared DatumShared::load(const std::filesystem::path & path)
    {
        if(! std::filesystem::exists(path))
            throw std::invalid_argument(std::string("not found: ").append(path.c_str()));

        DatumShared dt;
        auto ret = gnutls_load_file(path.c_str(), dt.get());
        if(GNUTLS_E_SUCCESS != ret)
            throw std::invalid_argument(errorStr("gnutls_load_file", ret));
        return dt;
    }

    bool DatumShared::save(const std::filesystem::path & path)
    {
        std::ofstream ofs(path.c_str(), std::ios::binary);

        if(! ofs)
        {
            std::cerr << "error write: " << path.c_str() << std::endl;
            return false;
        }

        if(auto dt = get())
        {
            ofs.write((const char*) dt->data, dt->size);
            return true;
        }

        return false;
    }

    /// Datum const
    DatumConst::DatumConst()
    {
        st.data = nullptr;
        st.size = 0;
    }

    DatumConst::DatumConst(std::string_view str)
    {
        st.data = (unsigned char*) str.data();
        st.size = str.size();
    }

    DatumConst::DatumConst(const std::vector<uint8_t> & vec)
    {
        st.data = (unsigned char*) vec.data();
        st.size = vec.size();
    }

    /// X509 certificate
    X509Crt::X509Crt()
    {
        gnutls_x509_crt_t crt = nullptr;
        auto ret = gnutls_x509_crt_init(& crt);
        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_x509_crt_init", ret));
        ptr = std::make_shared<X509CrtInt>(crt);
    }

    X509Crt X509Crt::import(const Datum & dt, bool der)
    {
        X509Crt res;

        auto ret = gnutls_x509_crt_import(res.get(), dt.get(), der ? GNUTLS_X509_FMT_DER : GNUTLS_X509_FMT_PEM);
        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_x509_crt_import", ret));

        return res;
    }

    DatumShared X509Crt::export2(bool der)
    {
        DatumShared dt;
        auto ret = gnutls_x509_crt_export2(ptr->crt, der ? GNUTLS_X509_FMT_DER : GNUTLS_X509_FMT_PEM, dt.get());

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_x509_crt_export2", ret));

        return dt;
    }

    bool X509Crt::setKey(gnutls_x509_privkey_t key)
    {
        auto ret = gnutls_x509_crt_set_key(ptr->crt, key);

        if(GNUTLS_E_SUCCESS != ret)
        {
            std::cerr << errorStr("gnutls_x509_crt_set_key", ret) << std::endl;
            return false;
        }

        return true;
    }

    int X509Crt::getVersion(void) const
    {
        return gnutls_x509_crt_get_version(ptr->crt);
    }

    time_t X509Crt::getExpirationTime(void) const
    {
        return gnutls_x509_crt_get_expiration_time(ptr->crt);
    }

    time_t X509Crt::getActivationTime(void) const
    {
        return gnutls_x509_crt_get_activation_time(ptr->crt);
    }

    std::vector<uint8_t> X509Crt::getFingerPrint(gnutls_digest_algorithm_t algo) const
    {
        size_t resultSize = 0;
        std::vector<uint8_t> res(256);
        int ret = GNUTLS_E_SUCCESS;

        while(GNUTLS_E_SHORT_MEMORY_BUFFER == (ret = gnutls_x509_crt_get_fingerprint(ptr->crt, algo, res.data(), & resultSize)))
            res.resize(res.size() * 2);

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_x509_crt_get_fingerprin", ret));

        res.resize(resultSize);
        return res;
    }

    std::vector<uint8_t> X509Crt::getSerial(void) const
    {
        size_t resultSize = 0;
        std::vector<uint8_t> res(256);
        int ret = GNUTLS_E_SUCCESS;

        while(GNUTLS_E_SHORT_MEMORY_BUFFER == (ret = gnutls_x509_crt_get_serial(ptr->crt, res.data(), & resultSize)))
            res.resize(res.size() * 2);

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_x509_crt_get_serial", ret));

        res.resize(resultSize);
        return res;
    }

    std::string X509Crt::getIssuerDN(void) const
    {
        size_t resultSize = 0;
        std::string res(256, 0x20);
        int ret = GNUTLS_E_SUCCESS;

        while(GNUTLS_E_SHORT_MEMORY_BUFFER == (ret = gnutls_x509_crt_get_issuer_dn(ptr->crt, res.data(), & resultSize)))
            res.resize(res.size() * 2, 0x20);

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_x509_crt_get_issuer_dn", ret));

        res.resize(resultSize);
        return res;
    }

    std::string X509Crt::getOwnerDN(void) const
    {
        size_t resultSize = 0;
        std::string res(256, 0x20);
        int ret = GNUTLS_E_SUCCESS;

        while(GNUTLS_E_SHORT_MEMORY_BUFFER == (ret = gnutls_x509_crt_get_dn(ptr->crt, res.data(), & resultSize)))
            res.resize(res.size() * 2, 0x20);

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr(" gnutls_x509_crt_get_dn", ret));

        res.resize(resultSize);
        return res;
    }

    std::pair<gnutls_pk_algorithm_t, int> X509Crt::getAlgoritmBits(void) const
    {
        unsigned int bits = 0;
        auto algo = gnutls_x509_crt_get_pk_algorithm(ptr->crt, & bits);
        return std::make_pair(static_cast<gnutls_pk_algorithm_t>(algo), bits);
    }

    /// Public key
    PublicKey::PublicKey()
    {
        gnutls_pubkey_t key = nullptr;
        auto ret = gnutls_pubkey_init(& key);
        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_pubkey_init", ret));
        ptr = std::make_shared<PublicKeyInt>(key);
    }

    PublicKey PublicKey::importX509(const Datum & dt, bool der)
    {
        PublicKey res;

        auto ret = gnutls_pubkey_import_x509_raw(res.get(), dt.get(), der ? GNUTLS_X509_FMT_DER : GNUTLS_X509_FMT_PEM, 0);

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_pubkey_import_x509_raw", ret));

        return res;
    }

    DatumShared PublicKey::export2(bool der)
    {
        DatumShared dt;
        auto ret = gnutls_pubkey_export2(ptr->key, der ? GNUTLS_X509_FMT_DER : GNUTLS_X509_FMT_PEM, dt.get());

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_pubkey_export2", ret));

        return dt;
    }

    DatumShared PublicKey::encrypt(const Datum & dt)
    {
        DatumShared res;
        auto ret = gnutls_pubkey_encrypt_data(ptr->key, 0, dt.get(), res.get());

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_pubkey_encrypt_data", ret));

        return res;
    }

    std::pair<gnutls_pk_algorithm_t, int> PublicKey::getAlgoritmBits(void) const
    {
        unsigned int bits = 0;
        auto algo = gnutls_pubkey_get_pk_algorithm(ptr->key, & bits);
        return std::make_pair(static_cast<gnutls_pk_algorithm_t>(algo), bits);
    }

    /// PrivKey
    PrivateKey::PrivateKey()
    {
        gnutls_privkey_t key = nullptr;
        auto ret = gnutls_privkey_init(& key);
        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_privkey_init", ret));
        ptr = std::make_shared<PrivateKeyInt>(key);
    }

    PrivateKey PrivateKey::importX509(const Datum & dt, bool der)
    {
        PrivateKey res;
        auto ret = gnutls_privkey_import_x509_raw(res.get(), dt.get(), der ? GNUTLS_X509_FMT_DER : GNUTLS_X509_FMT_PEM, nullptr, 0);

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_privkey_import_x509_raw", ret));

        return res;
    }

    DatumShared PrivateKey::decrypt(const Datum & dt)
    {
        DatumShared res;
        auto ret = gnutls_privkey_decrypt_data(ptr->key, 0, dt.get(), res.get());

        if(GNUTLS_E_SUCCESS != ret)
            throw std::runtime_error(errorStr("gnutls_privkey_decrypt_data", ret));

        return res;
    }

    bool PrivateKey::generate(gnutls_pk_algorithm_t algo, size_t bits)
    {
        auto ret = gnutls_privkey_generate(ptr->key, algo, bits, 0);
        if(GNUTLS_E_SUCCESS != ret)
        {
            std::cerr << errorStr("gnutls_privkey_generate", ret) << std::endl;
            return false;
        }
        return true;
    }
}
