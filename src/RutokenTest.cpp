#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/x509.h"
#include "openssl/pkcs7.h"
#include "openssl/safestack.h"

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
    auto x509 = TLS::X509Crt::import(TLS::DatumConst(cert), false);
    auto pubKey = TLS::PublicKey::importX509(x509.get());
    return pubKey.encrypt(TLS::DatumConst(pass)).toVector();
}

std::vector<uint8_t> opensslCreateCryptoPass(std::string_view cert, const std::vector<uint8_t> & data)
{
    std::unique_ptr<BIO, void(*)(BIO*)> bCert{ BIO_new_mem_buf(cert.data(), cert.size()), BIO_free_all };
    std::unique_ptr<BIO, void(*)(BIO*)> bData{ BIO_new_mem_buf(data.data(), data.size()), BIO_free_all };

    // create x509
    std::unique_ptr<X509, void(*)(X509*)> x509{ PEM_read_bio_X509(bCert.get(), nullptr, nullptr, nullptr), X509_free };
    // create stack of
    std::unique_ptr<STACK_OF(X509), void(*)(STACK_OF(X509)*)> stack{ sk_X509_new_null(), [](STACK_OF(X509)* st){ SKM_sk_free(X509, (st)); } };
    sk_X509_push(stack.get(), x509.get());
    // encrypt pkcs7
    std::unique_ptr<PKCS7, void(*)(PKCS7*)> p7{ PKCS7_encrypt(stack.get(), bData.get(), EVP_aes_128_cbc(),  PKCS7_BINARY), PKCS7_free };
    // store buf
    std::unique_ptr<BIO, void(*)(BIO*)> bDest{ BIO_new(BIO_s_mem()), BIO_free_all };
    PEM_write_bio_PKCS7(bDest.get(), p7.get());

    uint8_t* ptr = nullptr;
    auto len = BIO_get_mem_data(bDest.get(), & ptr);

    // import PEM format
    auto pkcs7 = TLS::PKCS7::import(TLS::DatumConst(ptr, len), false);
    // export DER format
    return pkcs7.export2(true).toVector();
}

int main(int argc, char** argv)
{
    try
    {
        // rutoken part
        for(auto & pemCert : rutokenCerts())
        {
            auto start = std::chrono::steady_clock::now();

            std::vector<uint8_t> pass = TLS::randomKey(32);
            auto crypto = opensslCreateCryptoPass(pemCert, pass);
            auto dt = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start);
            std::cout << "crypt size: " << crypto.size() << ", time: " << dt.count() << "us" << std::endl;

            bool res = rutokenCheckDecrypt(pemCert, crypto, pass);
            std::cout << "check result: " << std::boolalpha <<  res << std::endl;
        }
    }
    catch(const std::exception & err)
    {
        std::cerr << err.what() << std::endl;
    }

    return 0;
}
