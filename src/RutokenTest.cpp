#include <list>
#include <chrono>
#include <iostream>
#include <exception>

#include "gnutls_crypto.h"

// pki-core/comon
#include "common.h"

using namespace std::chrono_literals;

std::list<std::string> rutokenCerts(void)
{
    auto pin = "12345678";
    rutoken::pkicore::initialize("rutoken");

    SCOPE_EXIT()
    {
        rutoken::pkicore::deinitialize();
    };

    auto devices = rutoken::pkicore::Pkcs11Device::enumerate();
    if(devices.empty())
        throw std::runtime_error("rutoken device not found");

    std::list<std::string>list;
    for(auto & dev : devices)
    {
        dev.login(pin);

        if(dev.isLoggedIn())
        {
            for(auto & pkcs11Cert : dev.enumerateCerts())
                list.emplace_back(pkcs11Cert.toPem());
        }
    }

    return list;
}

bool rutokenCheckDecrypt(const std::string & pemCert, const std::vector<uint8_t> & crypto, const std::vector<uint8_t> & pass)
{
    auto pin = "12345678";
    rutoken::pkicore::initialize("rutoken");

    SCOPE_EXIT()
    {
        rutoken::pkicore::deinitialize();
    };

    auto devices = rutoken::pkicore::Pkcs11Device::enumerate();
    if(devices.empty())
        throw std::runtime_error("rutoken device not found");

    for(auto & dev : devices)
    {
        dev.login(pin);

        if(dev.isLoggedIn())
        {
            auto envelopedData = rutoken::pkicore::cms::EnvelopedData::parse(crypto);
            for(auto & pkcs11Cert : dev.enumerateCerts())
            {
                if(pkcs11Cert.toPem() == pemCert)
                {
                    auto params = rutoken::pkicore::cms::EnvelopedData::DecryptParams(pkcs11Cert);
                    std::cout << "!!!" << std::endl;
                    auto message = envelopedData.decrypt(params);
                    auto result = rutoken::pkicore::cms::Data::cast(std::move(message));

                    return pass == result.data();
                }
            }
        }
    }

    return false;
}

std::vector<uint8_t> gnutlsCreateCryptoPass(std::string_view cert, const std::vector<uint8_t> & pass)
{
    auto pubKey = TLS::PublicKey::importX509(TLS::DatumConst(cert), false /* ber/pem format */);
    return pubKey.encrypt(TLS::DatumConst(pass)).toVector();
}

int main(int argc, char** argv)
{
    try
    {
        for(auto & pemCert : rutokenCerts())
        {
            auto start = std::chrono::steady_clock::now();

            std::vector<uint8_t> pass = TLS::randomKey(32);
            auto crypto = gnutlsCreateCryptoPass(pemCert, pass);
            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);

            std::cout << "crypt size: " << crypto.size() << ", time: " << dt.count() << "us" << std::endl;

            auto res = rutokenCheckDecrypt(pemCert, crypto, pass);
            std::cout << "check result: " << std::boolalpha << res << std::endl;
        }
    }
    catch(const std::exception & err)
    {
        std::cerr << err.what() << std::endl;
    }

    return 0;
}
