#include "TeamServerSecurity.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace
{
std::string bytesToHex(const unsigned char* data, std::size_t size)
{
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < size; ++index)
        output << std::setw(2) << static_cast<unsigned int>(data[index]);
    return output.str();
}

std::vector<unsigned char> hexToBytes(const std::string& value)
{
    if (value.empty() || value.size() % 2 != 0)
        throw std::runtime_error("Invalid hexadecimal security value");

    std::vector<unsigned char> bytes(value.size() / 2, 0);
    for (std::size_t index = 0; index < bytes.size(); ++index)
    {
        const std::string pair = value.substr(index * 2, 2);
        std::size_t consumed = 0;
        const unsigned long parsed = std::stoul(pair, &consumed, 16);
        if (consumed != pair.size() || parsed > 255)
            throw std::runtime_error("Invalid hexadecimal security value");
        bytes[index] = static_cast<unsigned char>(parsed);
    }
    return bytes;
}

std::vector<unsigned char> pbkdf2(
    const std::string& password,
    const std::vector<unsigned char>& salt,
    int iterations)
{
    if (iterations < 100000)
        throw std::runtime_error("PBKDF2 iteration count is below the security minimum");

    std::vector<unsigned char> result(32, 0);
    if (PKCS5_PBKDF2_HMAC(
            password.data(),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            iterations,
            EVP_sha256(),
            static_cast<int>(result.size()),
            result.data()) != 1)
    {
        throw std::runtime_error("OpenSSL could not derive the password hash");
    }
    return result;
}
} // namespace

nlohmann::json TeamServerPasswordHash::toJson() const
{
    return {
        {"algorithm", algorithm},
        {"iterations", iterations},
        {"salt", salt},
        {"digest", digest}};
}

TeamServerPasswordHash TeamServerPasswordHash::fromJson(const nlohmann::json& value)
{
    if (!value.is_object())
        throw std::runtime_error("Password entry must be an object");

    TeamServerPasswordHash result;
    result.algorithm = value.value("algorithm", std::string());
    result.iterations = value.value("iterations", 0);
    result.salt = value.value("salt", std::string());
    result.digest = value.value("digest", std::string());
    if (result.algorithm != "pbkdf2-sha256")
        throw std::runtime_error("Unsupported password hashing algorithm");
    if (result.iterations < 100000 || result.salt.empty() || result.digest.empty())
        throw std::runtime_error("Incomplete password hashing parameters");
    (void)hexToBytes(result.salt);
    (void)hexToBytes(result.digest);
    return result;
}

TeamServerPasswordHash deriveTeamServerPasswordHash(const std::string& password, int iterations)
{
    if (password.size() < 16)
        throw std::runtime_error("Password must contain at least 16 characters");

    std::array<unsigned char, 16> salt {};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1)
        throw std::runtime_error("OpenSSL could not generate a password salt");

    const std::vector<unsigned char> saltBytes(salt.begin(), salt.end());
    const std::vector<unsigned char> digest = pbkdf2(password, saltBytes, iterations);
    TeamServerPasswordHash result;
    result.iterations = iterations;
    result.salt = bytesToHex(salt.data(), salt.size());
    result.digest = bytesToHex(digest.data(), digest.size());
    return result;
}

bool verifyTeamServerPassword(const std::string& password, const TeamServerPasswordHash& expected)
{
    const std::vector<unsigned char> salt = hexToBytes(expected.salt);
    const std::vector<unsigned char> expectedDigest = hexToBytes(expected.digest);
    const std::vector<unsigned char> actualDigest = pbkdf2(password, salt, expected.iterations);
    return actualDigest.size() == expectedDigest.size()
        && CRYPTO_memcmp(actualDigest.data(), expectedDigest.data(), actualDigest.size()) == 0;
}

std::string generateTeamServerSecret(std::size_t bytes)
{
    if (bytes < 16 || bytes > 1024)
        throw std::runtime_error("Invalid secure random value size");
    std::vector<unsigned char> random(bytes, 0);
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1)
        throw std::runtime_error("OpenSSL could not generate secure random data");
    return bytesToHex(random.data(), random.size());
}

std::string sha256Fingerprint(const std::string& pemCertificate)
{
    BIO* input = BIO_new_mem_buf(pemCertificate.data(), static_cast<int>(pemCertificate.size()));
    if (!input)
        throw std::runtime_error("Could not allocate certificate reader");
    X509* certificate = PEM_read_bio_X509(input, nullptr, nullptr, nullptr);
    BIO_free(input);
    if (!certificate)
        throw std::runtime_error("Could not parse certificate for fingerprinting");

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int digestLength = 0;
    const int status = X509_digest(certificate, EVP_sha256(), digest.data(), &digestLength);
    X509_free(certificate);
    if (status != 1)
        throw std::runtime_error("Could not fingerprint certificate");
    return bytesToHex(digest.data(), digestLength);
}

void writeTeamServerFile(const fs::path& path, const std::string& content, bool privateFile)
{
    std::error_code error;
    fs::create_directories(path.parent_path(), error);
    if (error)
        throw std::runtime_error("Could not create directory for " + path.string() + ": " + error.message());

    const fs::path temporary = path.string() + ".tmp-" + generateTeamServerSecret(16);
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output.good())
            throw std::runtime_error("Could not create " + temporary.string());
        output << content;
        output.close();
        if (!output.good())
        {
            fs::remove(temporary, error);
            throw std::runtime_error("Could not flush " + temporary.string());
        }
    }

#ifndef _WIN32
    const mode_t mode = privateFile ? (S_IRUSR | S_IWUSR) : (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (::chmod(temporary.c_str(), mode) != 0)
    {
        fs::remove(temporary, error);
        throw std::runtime_error("Could not set secure permissions on " + temporary.string());
    }
#else
    (void)privateFile;
#endif

    fs::rename(temporary, path, error);
    if (error)
    {
        fs::remove(path, error);
        error.clear();
        fs::rename(temporary, path, error);
    }
    if (error)
    {
        fs::remove(temporary, error);
        throw std::runtime_error("Could not atomically install " + path.string());
    }
}

void requirePrivateTeamServerFile(
    const fs::path& path,
    const std::string& description,
    bool strictPermissions)
{
    std::error_code error;
    if (!fs::is_regular_file(path, error))
        throw std::runtime_error(description + " not found: " + path.string());
#ifndef _WIN32
    if (strictPermissions)
    {
        struct stat status {};
        if (::stat(path.c_str(), &status) != 0)
            throw std::runtime_error("Could not inspect permissions for " + description);
        if ((status.st_mode & (S_IRWXG | S_IRWXO)) != 0)
            throw std::runtime_error(description + " must not be accessible by group or other users: " + path.string());
    }
#else
    (void)strictPermissions;
#endif
}

