#include "TeamServerInstance.hpp"

#include "TeamServerSecurity.hpp"

#include <algorithm>
#include <cctype>
#include <array>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "nlohmann/json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace
{
struct GeneratedCertificate
{
    std::string certificate;
    std::string privateKey;
};

std::string readFile(const fs::path& path, const std::string& description)
{
    std::ifstream input(path, std::ios::binary);
    if (!input.good())
        throw std::runtime_error(description + " not found: " + path.string());
    return std::string(std::istreambuf_iterator<char>(input), {});
}

void addExtension(X509* certificate, int nid, const std::string& value)
{
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(
        nullptr,
        &context,
        nid,
        const_cast<char*>(value.c_str()));
    if (!extension)
        throw std::runtime_error("Could not create an X509 extension");
    const int result = X509_add_ext(certificate, extension, -1);
    X509_EXTENSION_free(extension);
    if (result != 1)
        throw std::runtime_error("Could not attach an X509 extension");
}

bool looksLikeIpAddress(const std::string& value)
{
    if (value.find(':') != std::string::npos)
        return true;
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char character)
    {
        return std::isdigit(character) || character == '.';
    });
}

std::string bioToString(BIO* bio)
{
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio, &memory);
    if (!memory || !memory->data || memory->length == 0)
        throw std::runtime_error("OpenSSL produced an empty PEM value");
    return std::string(memory->data, memory->length);
}

GeneratedCertificate generateSelfSignedCertificate(const std::string& hostname)
{
    EVP_PKEY_CTX* keyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!keyContext)
        throw std::runtime_error("Could not allocate an RSA key generator");
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(keyContext) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(keyContext, 3072) <= 0
        || EVP_PKEY_keygen(keyContext, &key) <= 0)
    {
        EVP_PKEY_CTX_free(keyContext);
        throw std::runtime_error("Could not generate the TLS private key");
    }
    EVP_PKEY_CTX_free(keyContext);

    X509* certificate = X509_new();
    if (!certificate)
    {
        EVP_PKEY_free(key);
        throw std::runtime_error("Could not allocate the TLS certificate");
    }

    try
    {
        if (X509_set_version(certificate, 2) != 1)
            throw std::runtime_error("Could not set the TLS certificate version");

        std::array<unsigned char, 8> serialBytes {};
        if (RAND_bytes(serialBytes.data(), static_cast<int>(serialBytes.size())) != 1)
            throw std::runtime_error("Could not generate the TLS certificate serial");
        long serial = 0;
        for (unsigned char value : serialBytes)
            serial = (serial << 7) ^ value;
        serial &= 0x7fffffffL;
        ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial == 0 ? 1 : serial);

        X509_gmtime_adj(X509_getm_notBefore(certificate), -300);
        X509_gmtime_adj(X509_getm_notAfter(certificate), 365L * 24L * 60L * 60L);
        if (X509_set_pubkey(certificate, key) != 1)
            throw std::runtime_error("Could not attach the TLS public key");

        X509_NAME* subject = X509_get_subject_name(certificate);
        if (X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>("Exploration TeamServer"), -1, -1, 0) != 1
            || X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(hostname.c_str()), -1, -1, 0) != 1
            || X509_set_issuer_name(certificate, subject) != 1)
        {
            throw std::runtime_error("Could not set the TLS certificate identity");
        }

        addExtension(certificate, NID_basic_constraints, "critical,CA:FALSE");
        addExtension(certificate, NID_key_usage, "critical,digitalSignature,keyEncipherment");
        addExtension(certificate, NID_ext_key_usage, "serverAuth");
        addExtension(certificate, NID_subject_alt_name,
            std::string(looksLikeIpAddress(hostname) ? "IP:" : "DNS:") + hostname);

        if (X509_sign(certificate, key, EVP_sha256()) <= 0)
            throw std::runtime_error("Could not sign the TLS certificate");

        BIO* certificateBio = BIO_new(BIO_s_mem());
        BIO* keyBio = BIO_new(BIO_s_mem());
        if (!certificateBio || !keyBio)
        {
            BIO_free(certificateBio);
            BIO_free(keyBio);
            throw std::runtime_error("Could not allocate TLS PEM buffers");
        }
        if (PEM_write_bio_X509(certificateBio, certificate) != 1
            || PEM_write_bio_PrivateKey(keyBio, key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        {
            BIO_free(certificateBio);
            BIO_free(keyBio);
            throw std::runtime_error("Could not serialize the TLS material");
        }

        GeneratedCertificate result {bioToString(certificateBio), bioToString(keyBio)};
        BIO_free(certificateBio);
        BIO_free(keyBio);
        X509_free(certificate);
        EVP_PKEY_free(key);
        return result;
    }
    catch (...)
    {
        X509_free(certificate);
        EVP_PKEY_free(key);
        throw;
    }
}

json defaultRuntimeConfiguration()
{
    return {
        {"Version", "1.0.0-rc.1"},
        {"LogLevel", "info"},
        {"DefaultWindowsArch", "x64"},
        {"SupportedWindowsArchs", {"x86", "x64", "arm64"}},
        {"DefaultLinuxArch", "x64"},
        {"SupportedLinuxArchs", {"x64"}},
        {"DomainName", ""},
        {"ExposedIp", ""},
        {"IpInterface", "eth0"},
        {"xorKey", generateTeamServerSecret(24)},
        {"ListenerHttpConfig", {
            {"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
            {"wsUri", {"/ws"}},
            {"uriFileDownload", "/images/commun/serv/"},
            {"server", {{"headers", {{"Connection", "Keep-Alive"}, {"Content-Type", "application/json"}}}}}}},
        {"ListenerHttpsConfig", {
            {"uri", {"/MicrosoftUpdate/ShellEx/KB242742/default.aspx"}},
            {"wsUri", {"/ws"}},
            {"uriFileDownload", "/images/commun/serv/"},
            {"server", {{"headers", {{"Connection", "Keep-Alive"}, {"Content-Type", "application/json"}}}}}}}
    };
}

void validateOptions(const TeamServerInstanceOptions& options)
{
    if (options.instanceRoot.empty() || options.releaseRoot.empty())
        throw std::runtime_error("Instance and release directories are required");
    if (options.hostname.empty())
        throw std::runtime_error("A TLS hostname is required");
    if (options.port < 1 || options.port > 65535)
        throw std::runtime_error("The gRPC port is outside the valid range");
    if (options.adminUsername.empty())
        throw std::runtime_error("The bootstrap administrator username is required");
    if (options.profile == TeamServerProfile::Development && options.listenAddress != "127.0.0.1" && options.listenAddress != "::1")
        throw std::runtime_error("Development profile may only listen on a loopback address");
    if (options.profile == TeamServerProfile::Production
        && (options.tlsCertificate.empty() || options.tlsPrivateKey.empty()))
    {
        throw std::runtime_error("Production profile requires an external TLS certificate and private key");
    }
    if (options.requireClientCertificate && options.clientCaCertificate.empty())
        throw std::runtime_error("mTLS requires a client CA certificate");
}
} // namespace

std::string teamServerProfileName(TeamServerProfile profile)
{
    switch (profile)
    {
    case TeamServerProfile::Development:
        return "development";
    case TeamServerProfile::Standalone:
        return "standalone";
    case TeamServerProfile::Production:
        return "production";
    }
    throw std::runtime_error("Unknown TeamServer profile");
}

TeamServerProfile parseTeamServerProfile(const std::string& value)
{
    if (value == "development" || value == "dev")
        return TeamServerProfile::Development;
    if (value == "standalone")
        return TeamServerProfile::Standalone;
    if (value == "production" || value == "prod")
        return TeamServerProfile::Production;
    throw std::runtime_error("Unknown profile: " + value);
}

fs::path defaultTeamServerInstanceRoot()
{
    if (const char* configured = std::getenv("C2_INSTANCE_DIR"); configured && *configured)
        return fs::absolute(configured);
    return fs::absolute("instance");
}

TeamServerInstanceResult initializeTeamServerInstance(const TeamServerInstanceOptions& suppliedOptions)
{
    TeamServerInstanceOptions options = suppliedOptions;
    options.instanceRoot = fs::absolute(options.instanceRoot);
    options.releaseRoot = fs::absolute(options.releaseRoot);
    validateOptions(options);

    const fs::path configFile = options.instanceRoot / "config" / "TeamServerConfig.json";
    if (fs::exists(configFile) && !options.force)
        throw std::runtime_error("Instance already exists: " + options.instanceRoot.string());

    if (options.force && fs::exists(options.instanceRoot))
    {
        const fs::path canonicalRoot = fs::weakly_canonical(options.instanceRoot);
        if (canonicalRoot == canonicalRoot.root_path() || canonicalRoot == options.releaseRoot)
            throw std::runtime_error("Refusing to replace an unsafe instance directory");
        std::error_code removeError;
        fs::remove_all(options.instanceRoot, removeError);
        if (removeError)
            throw std::runtime_error("Could not replace instance directory: " + removeError.message());
    }

    const fs::path dataRoot = options.instanceRoot / "data";
    const fs::path logRoot = options.instanceRoot / "logs";
    const fs::path secretRoot = options.instanceRoot / "secrets";
    const fs::path pkiRoot = options.instanceRoot / "pki";
    const fs::path clientRoot = options.instanceRoot / "client";
    for (const fs::path& directory : {dataRoot, logRoot, secretRoot, pkiRoot, clientRoot})
        fs::create_directories(directory);

    fs::path certificatePath = options.tlsCertificate;
    fs::path privateKeyPath = options.tlsPrivateKey;
    std::string certificatePem;
    if (options.profile == TeamServerProfile::Production)
    {
        certificatePath = fs::absolute(certificatePath);
        privateKeyPath = fs::absolute(privateKeyPath);
        certificatePem = readFile(certificatePath, "TLS certificate");
        (void)readFile(privateKeyPath, "TLS private key");
        requirePrivateTeamServerFile(privateKeyPath, "TLS private key", true);
    }
    else
    {
        GeneratedCertificate generated = generateSelfSignedCertificate(options.hostname);
        certificatePath = pkiRoot / "server.crt";
        privateKeyPath = secretRoot / "server.key";
        writeTeamServerFile(certificatePath, generated.certificate, false);
        writeTeamServerFile(privateKeyPath, generated.privateKey, true);
        certificatePem = std::move(generated.certificate);
    }

    const std::string adminPassword = options.adminPassword.empty()
        ? generateTeamServerSecret(24)
        : options.adminPassword;
    const TeamServerPasswordHash passwordHash = deriveTeamServerPasswordHash(adminPassword);
    const fs::path credentialsPath = secretRoot / "credentials.json";
    const json credentials = {
        {"schema_version", 1},
        {"users", json::array({{
            {"username", options.adminUsername},
            {"role", "admin"},
            {"password", passwordHash.toJson()}}})}};
    writeTeamServerFile(credentialsPath, credentials.dump(2) + "\n", true);

    json config = defaultRuntimeConfiguration();
    config["Profile"] = teamServerProfileName(options.profile);
    config["ReleaseRoot"] = options.releaseRoot.string();
    config["DataRoot"] = dataRoot.string();
    config["UploadedArtifactsDirectoryPath"] = (dataRoot / "UploadedArtifacts").string();
    config["GeneratedArtifactsDirectoryPath"] = (dataRoot / "GeneratedArtifacts").string();
    config["HostedArtifactsDirectoryPath"] = (dataRoot / "GeneratedArtifacts" / "hosted").string();
    config["CredentialVaultDirectoryPath"] = (dataRoot / "CredentialVault").string();
    config["CredentialVaultPath"] = (dataRoot / "CredentialVault" / "vault.json").string();
    config["CredentialVaultKeyFile"] = (secretRoot / "vault.key").string();
    config["Runtime"] = {{"log_directory", logRoot.string()}};
    config["Server"] = {
        {"listen_address", options.listenAddress},
        {"hostname", options.hostname},
        {"port", options.port},
        {"max_message_mb", 64}};
    config["Security"] = {
        {"authentication", {
            {"credentials_file", credentialsPath.string()},
            {"token_ttl_minutes", 60},
            {"max_failures", 5},
            {"lockout_seconds", 60}}},
        {"tls", {
            {"certificate_file", certificatePath.string()},
            {"private_key_file", privateKeyPath.string()},
            {"client_ca_file", options.clientCaCertificate.empty() ? "" : fs::absolute(options.clientCaCertificate).string()},
            {"require_client_certificate", options.requireClientCertificate}}}};
    config["ListenerHttpsConfig"]["ServHttpsListenerCrtFile"] = certificatePath.string();
    config["ListenerHttpsConfig"]["ServHttpsListenerKeyFile"] = privateKeyPath.string();
    config["ListenerHttpConfig"]["downloadFolder"] = (dataRoot / "GeneratedArtifacts" / "hosted").string();
    config["ListenerHttpsConfig"]["downloadFolder"] = (dataRoot / "GeneratedArtifacts" / "hosted").string();
    writeTeamServerFile(configFile, config.dump(2) + "\n", true);

    std::string trustPem;
    if (!options.trustCertificate.empty())
        trustPem = readFile(fs::absolute(options.trustCertificate), "TLS trust certificate");
    else
        trustPem = certificatePem;

    const std::string fingerprint = sha256Fingerprint(certificatePem);
    const json clientProfile = {
        {"schema_version", 1},
        {"instance_id", generateTeamServerSecret(16)},
        {"profile", teamServerProfileName(options.profile)},
        {"endpoint", {{"host", options.hostname}, {"port", options.port}}},
        {"tls", {
            {"root_certificates_pem", trustPem},
            {"server_name", options.hostname},
            {"sha256_fingerprint", fingerprint}}},
        {"authentication", {{"username", options.adminUsername}}}};
    const fs::path clientProfilePath = clientRoot / "client-profile.json";
    writeTeamServerFile(clientProfilePath, clientProfile.dump(2) + "\n", false);

    const fs::path bootstrapPath = secretRoot / "bootstrap.txt";
    writeTeamServerFile(
        bootstrapPath,
        "username=" + options.adminUsername + "\npassword=" + adminPassword
            + "\nclient_profile=" + clientProfilePath.string() + "\n",
        true);

    return {configFile, clientProfilePath, bootstrapPath, fingerprint};
}

