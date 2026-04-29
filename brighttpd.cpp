#include "io_uring_ring.hpp"

#include <array>
#include <atomic>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <csignal>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pwd.h>
#include <string>
#include <string_view>
#include <sys/prctl.h>
#include <thread>
#include <system_error>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

namespace fs = std::filesystem;
using brighttpd::io_uring_ring;

extern "C" {
    extern const unsigned char _binary_index_html_start[];
    extern const unsigned char _binary_index_html_end[];
    extern const unsigned char _binary_404_html_start[];
    extern const unsigned char _binary_404_html_end[];
}

namespace
{

constexpr unsigned default_ring_entries = 1024;
constexpr std::size_t default_request_buffer_size = 8192;
constexpr std::size_t default_body_buffer_size = 16384;
constexpr std::size_t default_max_connections = 512;
constexpr int default_listen_backlog = 8192;
constexpr unsigned default_submit_batch_threshold = 32;
constexpr std::size_t default_splice_chunk_size = 1 << 20;
constexpr std::size_t default_buffered_file_threshold = 8192;
constexpr unsigned default_header_timeout_seconds = 2;
constexpr unsigned default_tls_handshake_timeout_seconds = 3;
constexpr unsigned default_keepalive_timeout_seconds = 5;
constexpr unsigned default_response_timeout_seconds = 30;
constexpr unsigned default_idle_scan_interval_seconds = 1;
constexpr int default_tcp_defer_accept = 1;
constexpr int default_tcp_fastopen = 4096;
using steady_clock = std::chrono::steady_clock;

enum class ConnState : uint8_t
{
    Idle,
    TlsHandshake,
    Receiving,
    SendingHeader,
    SplicingIn,
    SplicingOut,
    WaitingSocket,
    Closing,
};

enum class OpKind : uint8_t
{
    Accept = 1,
    Recv = 2,
    SendParts = 3,
    ReadBody = 4,
    SpliceIn = 5,
    SpliceOut = 6,
    PollSocket = 7,
    Close = 8,
    Shutdown = 9,
    Timer = 10,
};

struct range_result;

unsigned default_worker_count();
std::string_view trim_view(std::string_view text);
sockaddr_in6 parse_listen_address(std::string_view listen);
range_result parse_single_byte_range(std::string_view value, std::uint64_t size);
std::string build_header(std::string_view status, std::uint64_t size, std::string_view mime, bool keep_alive, unsigned keepalive_timeout_seconds,
                         bool accept_ranges = false, std::string_view content_range = {});
std::string build_redirect_header(std::string_view location, bool keep_alive, unsigned keepalive_timeout_seconds, std::size_t body_len);

struct config
{
    std::string listen;
    std::optional<std::string> tls_listen;
    fs::path root;
    std::optional<fs::path> mime_types_path;
    std::optional<fs::path> tls_p12_path;
    std::optional<std::string> tls_p12_passphrase;
    bool tls_redirect = true;
    std::optional<std::string> user;
    std::optional<std::string> group;
    unsigned workers = default_worker_count();
    unsigned ring_entries = default_ring_entries;
    std::size_t request_buffer_size = default_request_buffer_size;
    std::size_t body_buffer_size = default_body_buffer_size;
    std::size_t max_connections = default_max_connections;
    int listen_backlog = default_listen_backlog;
    unsigned submit_batch_threshold = default_submit_batch_threshold;
    std::size_t splice_chunk_size = default_splice_chunk_size;
    std::size_t buffered_threshold = default_buffered_file_threshold;
    unsigned header_timeout_seconds = default_header_timeout_seconds;
    unsigned tls_handshake_timeout_seconds = default_tls_handshake_timeout_seconds;
    unsigned keepalive_timeout_seconds = default_keepalive_timeout_seconds;
    unsigned response_timeout_seconds = default_response_timeout_seconds;
    unsigned idle_scan_interval_seconds = default_idle_scan_interval_seconds;
    int tcp_defer_accept = default_tcp_defer_accept;
    int tcp_fastopen = default_tcp_fastopen;
};

struct cli_options
{
    bool show_help{false};
    bool dry_run{false};
    fs::path config_path;
};

struct file_record
{
    std::string route;
    std::string fs_path;
    std::string mime;
    int fd{-1};
    int fixed_fd{-1};
    std::uint64_t size{0};
    const char* embedded_body{nullptr};
    std::size_t embedded_body_len{0};
    std::string header_keep;
    std::string header_close;
};

struct inline_response
{
    std::string header_keep;
    std::string header_close;
    const char* body{nullptr};
    std::size_t body_len{0};
};

struct parse_result
{
    bool complete{false};
    bool valid{false};
    bool head_only{false};
    bool keep_alive{false};
    bool close_after{false};
    std::string_view route{};
    std::string_view host{};
    std::string_view range{};
};

enum class range_status : uint8_t
{
    NotPresent,
    Unsupported,
    Satisfiable,
    Unsatisfiable,
};

struct byte_range
{
    std::uint64_t start{0};
    std::uint64_t end{0};
};

struct range_result
{
    range_status status{range_status::NotPresent};
    byte_range range{};
};

enum class worker_mode : uint8_t
{
    StaticFiles,
    RedirectToTls,
};

struct shared_state
{
    std::vector<file_record> files;
    std::unordered_map<std::string_view, const file_record*> routes;
    const file_record* index{nullptr};
    const file_record* not_found{nullptr};
    inline_response bad_request;
    inline_response method_not_allowed;
};

struct tls_context
{
    SSL_CTX* ctx{nullptr};

    tls_context() = default;
    explicit tls_context(SSL_CTX *value) : ctx(value) {}

    tls_context(const tls_context&) = delete;
    tls_context& operator=(const tls_context&) = delete;

    tls_context(tls_context &&other) noexcept : ctx(other.ctx)
    {
        other.ctx = nullptr;
    }

    tls_context& operator=(tls_context &&other) noexcept
    {
        if (this != &other)
        {
            if (ctx != nullptr)
            {
                SSL_CTX_free(ctx);
            }

            ctx = other.ctx;
            other.ctx = nullptr;
        }

        return *this;
    }

    ~tls_context()
    {
        if (ctx != nullptr)
        {
            SSL_CTX_free(ctx);
        }
    }

    explicit operator bool() const
    {
        return ctx != nullptr;
    }
};

struct connection
{
    ConnState state{ConnState::Idle};
    int fd{-1};
    SSL* ssl{nullptr};
    bool tls_handshake_done{false};
    bool tls_ktls_ready{false};

    std::vector<char> request;
    std::size_t request_len{0};
    unsigned pending_buf_id{0};
    int pending_bytes{0};
    bool recv_still_armed{false};

    const file_record* file{nullptr};
    const inline_response* inline_response_ptr{nullptr};
    const std::string* header{nullptr};
    std::string dynamic_header_keep;
    std::string dynamic_header_close;
    std::string dynamic_body;
    bool head_only{false};
    bool close_after{false};
    bool wants_inline{false};
    bool buffered_body{false};
    bool corked{false};

    std::size_t header_sent{0};
    std::size_t inline_body_sent{0};
    std::uint64_t file_offset{0};
    std::uint64_t file_end{0};
    std::size_t send_base_offset{0};
    std::size_t send_len{0};
    std::size_t send_sent{0};
    msghdr send_msg{};
    std::array<iovec, 2> send_iov{};
    std::vector<char> body;

    std::size_t splice_target{0};
    std::size_t pipe_ready{0};

    short poll_events{0};
    bool poll_armed{false};

    steady_clock::time_point last_activity{steady_clock::now()};
    steady_clock::time_point request_started_at{steady_clock::now()};
    steady_clock::time_point accepted_at{steady_clock::now()};
    steady_clock::time_point response_started_at{steady_clock::now()};
};

std::atomic<bool> g_running{true};
std::array<int, 2> g_shutdown_pipe{-1, -1};

constexpr char shutdown_sigint_message[] = "brighttpd received Ctrl+C, shutting down\n";
constexpr char shutdown_sigterm_message[] = "brighttpd received SIGTERM, shutting down\n";

struct mime_types;

const mime_types* g_active_mime_types = nullptr;

constexpr char embedded_mime_types[] = R"(types {
    text/html                                        html htm shtml;
    text/css                                         css;
    text/xml                                         xml;
    image/gif                                        gif;
    image/jpeg                                       jpeg jpg;
    application/javascript                           js;
    application/atom+xml                             atom;
    application/rss+xml                              rss;

    text/mathml                                      mml;
    text/plain                                       txt;
    text/vnd.sun.j2me.app-descriptor                 jad;
    text/vnd.wap.wml                                 wml;
    text/x-component                                 htc;

    image/avif                                       avif;
    image/png                                        png;
    image/svg+xml                                    svg svgz;
    image/tiff                                       tif tiff;
    image/vnd.wap.wbmp                               wbmp;
    image/webp                                       webp;
    image/x-icon                                     ico;
    image/x-jng                                      jng;
    image/x-ms-bmp                                   bmp;

    font/woff                                        woff;
    font/woff2                                       woff2;

    application/java-archive                         jar war ear;
    application/json                                 json;
    application/mac-binhex40                         hqx;
    application/msword                               doc;
    application/pdf                                  pdf;
    application/postscript                           ps eps ai;
    application/rtf                                  rtf;
    application/vnd.apple.mpegurl                    m3u8;
    application/vnd.google-earth.kml+xml             kml;
    application/vnd.google-earth.kmz                 kmz;
    application/vnd.ms-excel                         xls;
    application/vnd.ms-fontobject                    eot;
    application/vnd.ms-powerpoint                    ppt;
    application/vnd.oasis.opendocument.graphics      odg;
    application/vnd.oasis.opendocument.presentation  odp;
    application/vnd.oasis.opendocument.spreadsheet   ods;
    application/vnd.oasis.opendocument.text          odt;
    application/vnd.openxmlformats-officedocument.presentationml.presentation
                                                     pptx;
    application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
                                                     xlsx;
    application/vnd.openxmlformats-officedocument.wordprocessingml.document
                                                     docx;
    application/vnd.wap.wmlc                         wmlc;
    application/wasm                                 wasm;
    application/x-7z-compressed                      7z;
    application/x-cocoa                              cco;
    application/x-java-archive-diff                  jardiff;
    application/x-java-jnlp-file                     jnlp;
    application/x-makeself                           run;
    application/x-perl                               pl pm;
    application/x-pilot                              prc pdb;
    application/x-rar-compressed                     rar;
    application/x-redhat-package-manager             rpm;
    application/x-sea                                sea;
    application/x-shockwave-flash                    swf;
    application/x-stuffit                            sit;
    application/x-tcl                                tcl tk;
    application/x-x509-ca-cert                       der pem crt;
    application/x-xpinstall                          xpi;
    application/xhtml+xml                            xhtml;
    application/xspf+xml                             xspf;
    application/zip                                  zip;

    application/octet-stream                         bin exe dll;
    application/octet-stream                         deb;
    application/octet-stream                         dmg;
    application/octet-stream                         iso img;
    application/octet-stream                         msi msp msm;

    audio/midi                                       mid midi kar;
    audio/mpeg                                       mp3;
    audio/ogg                                        ogg;
    audio/x-m4a                                      m4a;
    audio/x-realaudio                                ra;

    video/3gpp                                       3gpp 3gp;
    video/mp2t                                       ts;
    video/mp4                                        mp4;
    video/mpeg                                       mpeg mpg;
    video/quicktime                                  mov;
    video/webm                                       webm;
    video/x-flv                                      flv;
    video/x-m4v                                      m4v;
    video/x-mng                                      mng;
    video/x-ms-asf                                   asx asf;
    video/x-ms-wmv                                   wmv;
    video/x-msvideo                                  avi;
})";

struct mime_types
{
    std::unordered_map<std::string, std::string> by_extension;

    static std::string lowercase(std::string value)
    {
        for (char& ch : value)
        {
            if (ch >= 'A' && ch <= 'Z')
            {
                ch = static_cast<char>(ch - 'A' + 'a');
            }
        }

        return value;
    }

    static std::vector<std::string> tokenize(std::string_view text)
    {
        std::vector<std::string> tokens;
        std::string current;

        auto flush = [&]()
        {
            if (!current.empty())
            {
                tokens.push_back(std::move(current));
                current.clear();
            }
        };

        for (std::size_t i = 0; i < text.size(); ++i)
        {
            const char ch = text[i];

            if (ch == '#')
            {
                flush();

                while (i < text.size() && text[i] != '\n')
                {
                    ++i;
                }

                continue;
            }

            if (std::isspace(static_cast<unsigned char>(ch)) != 0)
            {
                flush();
                continue;
            }

            if (ch == '{' || ch == '}' || ch == ';')
            {
                flush();
                tokens.emplace_back(1, ch);
                continue;
            }

            current.push_back(ch);
        }

        flush();
        return tokens;
    }

    static mime_types parse(std::string_view text)
    {
        mime_types result;
        const std::vector<std::string> tokens = tokenize(text);
        bool in_types = false;

        for (std::size_t i = 0; i < tokens.size();)
        {
            if (!in_types)
            {
                if (tokens[i] == "types")
                {
                    if (i + 1 >= tokens.size() || tokens[i + 1] != "{")
                    {
                        throw std::runtime_error("invalid mime.types: expected 'types {'");
                    }

                    in_types = true;
                    i += 2;
                    continue;
                }

                ++i;
                continue;
            }

            if (tokens[i] == "}")
            {
                return result;
            }

            if (tokens[i] == ";")
            {
                ++i;
                continue;
            }

            const std::string mime = tokens[i++];
            bool saw_extension = false;

            while (i < tokens.size() && tokens[i] != ";")
            {
                if (tokens[i] == "}")
                {
                    throw std::runtime_error("invalid mime.types: missing ';' before '}'");
                }

                result.by_extension.emplace("." + lowercase(tokens[i]), mime);
                saw_extension = true;
                ++i;
            }

            if (!saw_extension)
            {
                throw std::runtime_error("invalid mime.types: mime entry missing extension");
            }

            if (i >= tokens.size() || tokens[i] != ";")
            {
                throw std::runtime_error("invalid mime.types: missing ';' after mime entry");
            }

            ++i;
        }

        if (!in_types)
        {
            throw std::runtime_error("invalid mime.types: missing 'types' block");
        }

        throw std::runtime_error("invalid mime.types: missing closing '}'");
    }

    static const mime_types& load_default()
    {
        static const mime_types instance = parse(embedded_mime_types);
        return instance;
    }

    static mime_types load_from_file(const fs::path &path)
    {
        std::ifstream file(path);

        if (!file)
        {
            throw std::runtime_error("failed to open mime types file: " + path.string());
        }

        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return parse(content);
    }

    std::string lookup(const fs::path &path) const
    {
        const std::string ext = lowercase(path.extension().string());

        if (const auto it = by_extension.find(ext); it != by_extension.end())
        {
            return it->second;
        }

        return "application/octet-stream";
    }
};

std::string mime_for(const fs::path &path)
{
    return g_active_mime_types->lookup(path);
}

std::uint64_t file_size_for(int fd)
{
    struct stat st {};

    if (::fstat(fd, &st) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "fstat");
    }

    return static_cast<std::uint64_t>(st.st_size);
}

int open_static_file(const fs::path &path)
{
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);

    if (fd < 0)
    {
        throw std::system_error(errno, std::generic_category(), "open");
    }

    return fd;
}

bool ascii_iequal(std::string_view a, std::string_view b)
{
    if (a.size() != b.size())
    {
        return false;
    }

    for (std::size_t i = 0; i < a.size(); ++i)
    {
        const unsigned char lhs = static_cast<unsigned char>(a[i]);
        const unsigned char rhs = static_cast<unsigned char>(b[i]);

        if (std::tolower(lhs) != std::tolower(rhs))
        {
            return false;
        }
    }

    return true;
}

std::string_view find_header_value(std::string_view request, std::string_view name)
{
    std::size_t pos = request.find("\r\n");

    if (pos == std::string_view::npos)
    {
        return {};
    }

    pos += 2;

    while (pos < request.size())
    {
        const std::size_t line_end = request.find("\r\n", pos);

        if (line_end == std::string_view::npos || line_end == pos)
        {
            return {};
        }

        const std::string_view line = request.substr(pos, line_end - pos);
        const std::size_t colon = line.find(':');

        if (colon != std::string_view::npos && ascii_iequal(trim_view(line.substr(0, colon)), name))
        {
            return trim_view(line.substr(colon + 1));
        }

        pos = line_end + 2;
    }

    return {};
}

parse_result parse_request(const char* buf, std::size_t len)
{
    parse_result result;

    if (len < 4)
    {
        return result;
    }

    const char* header_end = nullptr;

    for (std::size_t i = 3; i < len; ++i)
    {
        if (buf[i - 3] == '\r' && buf[i - 2] == '\n' && buf[i - 1] == '\r' && buf[i] == '\n')
        {
            header_end = buf + i + 1;
            break;
        }
    }

    if (!header_end)
    {
        return result;
    }

    result.complete = true;
    const std::string_view request(buf, static_cast<std::size_t>(header_end - buf));
    const auto line_end = request.find("\r\n");

    if (line_end == std::string_view::npos)
    {
        return result;
    }

    const std::string_view line = request.substr(0, line_end);
    const auto first_space = line.find(' ');

    if (first_space == std::string_view::npos)
    {
        return result;
    }

    const auto second_space = line.find(' ', first_space + 1);

    if (second_space == std::string_view::npos)
    {
        return result;
    }

    const std::string_view method = line.substr(0, first_space);

    if (method == "GET")
    {
        result.head_only = false;
    }
    else if (method == "HEAD")
    {
        result.head_only = true;
    }
    else
    {
        result.valid = false;
        return result;
    }

    const std::string_view target = line.substr(first_space + 1, second_space - first_space - 1);
    const std::string_view version = line.substr(second_space + 1);

    if (target.empty() || target.front() != '/')
    {
        return result;
    }

    if (target.find("..") != std::string_view::npos)
    {
        return result;
    }

    if (version != "HTTP/1.1" && version != "HTTP/1.0")
    {
        return result;
    }

    result.route = target;
    result.host = find_header_value(request, "Host");
    result.range = find_header_value(request, "Range");
    result.keep_alive = (version == "HTTP/1.1");

    if (request.find("\nConnection: close\r\n") != std::string_view::npos ||
            request.find("\nconnection: close\r\n") != std::string_view::npos)
    {
        result.keep_alive = false;
    }

    if (version == "HTTP/1.0" &&
            (request.find("\nConnection: keep-alive\r\n") != std::string_view::npos ||
             request.find("\nconnection: keep-alive\r\n") != std::string_view::npos))
    {
        result.keep_alive = true;
    }

    result.close_after = !result.keep_alive;
    result.valid = true;
    return result;
}

bool parse_decimal_u64(std::string_view text, std::uint64_t& value)
{
    if (text.empty())
    {
        return false;
    }

    std::uint64_t parsed = 0;

    for (char ch : text)
    {
        if (ch < '0' || ch > '9')
        {
            return false;
        }

        const std::uint64_t digit = static_cast<std::uint64_t>(ch - '0');

        if (parsed > (std::numeric_limits<std::uint64_t>::max() - digit) / 10)
        {
            return false;
        }

        parsed = parsed * 10 + digit;
    }

    value = parsed;
    return true;
}

range_result parse_single_byte_range(std::string_view value, std::uint64_t size)
{
    range_result result;

    if (value.empty())
    {
        return result;
    }

    result.status = range_status::Unsupported;
    constexpr std::string_view prefix = "bytes=";

    if (value.size() <= prefix.size() || !ascii_iequal(value.substr(0, prefix.size()), prefix))
    {
        return result;
    }

    const std::string_view spec = trim_view(value.substr(prefix.size()));

    if (spec.empty() || spec.find(',') != std::string_view::npos)
    {
        return result;
    }

    const std::size_t dash = spec.find('-');

    if (dash == std::string_view::npos || spec.find('-', dash + 1) != std::string_view::npos)
    {
        return result;
    }

    const std::string_view first_text = trim_view(spec.substr(0, dash));
    const std::string_view last_text = trim_view(spec.substr(dash + 1));

    if (first_text.empty() && last_text.empty())
    {
        return result;
    }

    std::uint64_t first = 0;
    std::uint64_t last = 0;

    if (first_text.empty())
    {
        if (!parse_decimal_u64(last_text, last))
        {
            return result;
        }

        if (last == 0 || size == 0)
        {
            result.status = range_status::Unsatisfiable;
            return result;
        }

        result.status = range_status::Satisfiable;
        result.range.start = last >= size ? 0 : size - last;
        result.range.end = size;
        return result;
    }

    if (!parse_decimal_u64(first_text, first))
    {
        return result;
    }

    if (!last_text.empty() && !parse_decimal_u64(last_text, last))
    {
        return result;
    }

    if (!last_text.empty() && last < first)
    {
        return result;
    }

    if (first >= size)
    {
        result.status = range_status::Unsatisfiable;
        return result;
    }

    result.status = range_status::Satisfiable;
    result.range.start = first;
    result.range.end = last_text.empty() || last >= size ? size : last + 1;
    return result;
}

// user_data encodes OpKind in low 8 bits and connection index above that
std::uint64_t encode_user_data(OpKind kind, std::uint32_t index)
{
    return (static_cast<std::uint64_t>(index) << 8U) | static_cast<std::uint8_t>(kind);
}

OpKind decode_kind(std::uint64_t user_data)
{
    return static_cast<OpKind>(user_data & 0xffU);
}

std::uint32_t decode_index(std::uint64_t user_data)
{
    return static_cast<std::uint32_t>(user_data >> 8U);
}

bool would_block(int res)
{
    return res == -EAGAIN || res == -EWOULDBLOCK;
}

void set_socket_cork(int fd, bool enabled)
{
    int value = enabled ? 1 : 0;
    (void)::setsockopt(fd, IPPROTO_TCP, TCP_CORK, &value, sizeof(value));
}

std::string config_summary(const config &cfg)
{
    std::string summary = "brighttpd starting up with configuration: ";
    summary.append("listen=");
    summary.append(cfg.listen.empty() ? std::string("<disabled>") : cfg.listen);
    summary.append(" tls_listen=");
    summary.append(cfg.tls_listen ? *cfg.tls_listen : std::string("<disabled>"));
    summary.append(" root=");
    summary.append(cfg.root.string());
    summary.append(" mime_types=");
    summary.append(cfg.mime_types_path ? cfg.mime_types_path->string() : std::string("<embedded>"));
    summary.append(" tls_p12=");
    summary.append(cfg.tls_p12_path ? cfg.tls_p12_path->string() : std::string("<disabled>"));
    summary.append(" tls_p12_passphrase=");
    summary.append(cfg.tls_p12_passphrase ? std::string("<provided>") : std::string("<none>"));
    summary.append(" tls_redirect=");
    summary.append(cfg.tls_redirect ? "yes" : "no");
    summary.append(" user=");
    summary.append(cfg.user ? *cfg.user : std::string("<unchanged>"));
    summary.append(" group=");
    summary.append(cfg.group ? *cfg.group : std::string("<unchanged>"));
    summary.append(" workers=");
    summary.append(std::to_string(cfg.workers));
    summary.append(" ring_entries=");
    summary.append(std::to_string(cfg.ring_entries));
    summary.append(" request_buffer_size=");
    summary.append(std::to_string(cfg.request_buffer_size));
    summary.append(" body_buffer_size=");
    summary.append(std::to_string(cfg.body_buffer_size));
    summary.append(" max_connections=");
    summary.append(std::to_string(cfg.max_connections));
    summary.append(" listen_backlog=");
    summary.append(std::to_string(cfg.listen_backlog));
    summary.append(" submit_batch_threshold=");
    summary.append(std::to_string(cfg.submit_batch_threshold));
    summary.append(" splice_chunk_size=");
    summary.append(std::to_string(cfg.splice_chunk_size));
    summary.append(" buffered_threshold=");
    summary.append(std::to_string(cfg.buffered_threshold));
    summary.append(" header_timeout=");
    summary.append(std::to_string(cfg.header_timeout_seconds));
    summary.append(" tls_handshake_timeout=");
    summary.append(std::to_string(cfg.tls_handshake_timeout_seconds));
    summary.append(" keepalive_timeout=");
    summary.append(std::to_string(cfg.keepalive_timeout_seconds));
    summary.append(" response_timeout=");
    summary.append(std::to_string(cfg.response_timeout_seconds));
    summary.append(" idle_scan_interval=");
    summary.append(std::to_string(cfg.idle_scan_interval_seconds));
    summary.append(" tcp_defer_accept=");
    summary.append(std::to_string(cfg.tcp_defer_accept));
    summary.append(" tcp_fastopen=");
    summary.append(std::to_string(cfg.tcp_fastopen));
    return summary;
}

std::uint16_t listen_port(std::string_view listen)
{
    const sockaddr_in6 addr = parse_listen_address(listen);
    return ntohs(addr.sin6_port);
}

std::string normalize_redirect_host(std::string_view host_header)
{
    if (host_header.empty())
    {
        return "localhost";
    }

    if (host_header.front() == '[')
    {
        const std::size_t close = host_header.find(']');

        if (close != std::string_view::npos)
        {
            return std::string(host_header.substr(0, close + 1));
        }

        return std::string(host_header);
    }

    const std::size_t first_colon = host_header.find(':');

    if (first_colon != std::string_view::npos && host_header.find(':', first_colon + 1) == std::string_view::npos)
    {
        return std::string(host_header.substr(0, first_colon));
    }

    return std::string(host_header);
}

std::string redirect_location(const config &cfg, std::string_view host_header, std::string_view route)
{
    std::string location = "https://";
    location.append(normalize_redirect_host(host_header));
    const std::uint16_t port = listen_port(*cfg.tls_listen);

    if (port != 443)
    {
        location.push_back(':');
        location.append(std::to_string(port));
    }

    location.append(route);
    return location;
}

std::string mode_to_octal(mode_t mode)
{
    std::string text = "0";
    text.push_back(static_cast<char>('0' + ((mode >> 6) & 0x7)));
    text.push_back(static_cast<char>('0' + ((mode >> 3) & 0x7)));
    text.push_back(static_cast<char>('0' + (mode & 0x7)));
    return text;
}

std::string program_name(const char* argv0)
{
    if (argv0 == nullptr || *argv0 == '\0')
    {
        return "brighttpd";
    }

    return fs::path(argv0).filename().string();
}

unsigned default_worker_count()
{
    return std::max(1u, std::thread::hardware_concurrency());
}

std::string_view trim_view(std::string_view text)
{
    std::size_t start = 0;

    while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])) != 0)
    {
        ++start;
    }

    std::size_t end = text.size();

    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1])) != 0)
    {
        --end;
    }

    return text.substr(start, end - start);
}

std::pair<std::string_view, std::string_view> split_directive_line(std::string_view line)
{
    const std::size_t separator = line.find_first_of(" \t");

    if (separator == std::string_view::npos)
    {
        return {trim_view(line), {}};
    }

    return
    {
        trim_view(line.substr(0, separator)),
        trim_view(line.substr(separator + 1)),
    };
}

template <typename T>
T parse_unsigned_option(std::string_view value, std::string_view option)
{
    if (value.empty())
    {
        throw std::runtime_error("missing value for " + std::string(option));
    }

    std::string owned(value);
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::strtoull(owned.c_str(), &end, 10);

    if (errno != 0 || end == nullptr || *end != '\0')
    {
        throw std::runtime_error("invalid numeric value for " + std::string(option) + ": " + owned);
    }

    if (parsed > static_cast<unsigned long long>(std::numeric_limits<T>::max()))
    {
        throw std::runtime_error("value out of range for " + std::string(option) + ": " + owned);
    }

    return static_cast<T>(parsed);
}

std::string usage_text(std::string_view argv0)
{
    std::string usage;
    usage.append("Usage:\n");
    usage.append("  ");
    usage.append(argv0);
    usage.append(" -c /path/to/brighttpd.conf\n");
    usage.append("  ");
    usage.append(argv0);
    usage.append(" -c /path/to/brighttpd.conf -n\n");
    usage.append("  ");
    usage.append(argv0);
    usage.append(" -h\n\n");
    usage.append("Options:\n");
    usage.append("  -c PATH  Read server config from PATH\n");
    usage.append("  -n       Dry run: validate config, TLS bundle, MIME map, and assets, then exit\n");
    usage.append("  -h       Show this help text\n\n");
    usage.append("Config directives:\n");
    usage.append("  listen [::]:8080\n");
    usage.append("  tls_listen [::]:8443\n");
    usage.append("  root /srv/www/site\n");
    usage.append("  mime_types /etc/nginx/mime.types\n");
    usage.append("  tls_p12 /etc/ssl/private/site.p12\n");
    usage.append("  tls_p12_passphrase secret\n");
    usage.append("  tls_redirect yes\n");
    usage.append("  user www-data\n");
    usage.append("  group www-data\n");
    usage.append("  workers 8\n");
    usage.append("  ring_entries 1024\n");
    usage.append("  request_buffer_size 8192\n");
    usage.append("  body_buffer_size 16384\n");
    usage.append("  max_connections 512\n");
    usage.append("  listen_backlog 8192\n");
    usage.append("  submit_batch_threshold 32\n");
    usage.append("  splice_chunk_size 1048576\n");
    usage.append("  buffered_threshold 8192\n");
    usage.append("  header_timeout 2\n");
    usage.append("  tls_handshake_timeout 3\n");
    usage.append("  keepalive_timeout 5\n");
    usage.append("  response_timeout 30\n");
    usage.append("  idle_scan_interval 1\n");
    usage.append("  tcp_defer_accept 1\n");
    usage.append("  tcp_fastopen 4096\n");
    return usage;
}

[[noreturn]] void throw_openssl_error(const char* what)
{
    const unsigned long code = ERR_get_error();

    if (code == 0)
    {
        throw std::runtime_error(std::string(what) + ": unknown OpenSSL error");
    }

    char buffer[256];
    ERR_error_string_n(code, buffer, sizeof(buffer));
    throw std::runtime_error(std::string(what) + ": " + buffer);
}

bool proc_crypto_has(std::string_view pattern)
{
    std::ifstream file("/proc/crypto");

    if (!file)
    {
        return false;
    }

    std::string line;

    while (std::getline(file, line))
    {
        if (line.find(pattern) != std::string::npos)
        {
            return true;
        }
    }

    return false;
}

struct ktls_cipher_policy
{
    std::string tls12;
    std::string tls13;
};

std::string join_cipher_list(const std::vector<std::string_view>& items)
{
    std::string result;

    for (std::size_t i = 0; i < items.size(); ++i)
    {
        if (i != 0)
        {
            result.push_back(':');
        }

        result.append(items[i]);
    }

    return result;
}

ktls_cipher_policy build_ktls_cipher_policy()
{
    std::vector<std::string_view> tls12;
    std::vector<std::string_view> tls13;

    if (proc_crypto_has("name         : gcm(aes)"))
    {
        tls12.push_back("ECDHE-ECDSA-AES128-GCM-SHA256");
        tls12.push_back("ECDHE-RSA-AES128-GCM-SHA256");
        tls12.push_back("ECDHE-ECDSA-AES256-GCM-SHA384");
        tls12.push_back("ECDHE-RSA-AES256-GCM-SHA384");

        tls13.push_back("TLS_AES_128_GCM_SHA256");
        tls13.push_back("TLS_AES_256_GCM_SHA384");
    }

    if (tls12.empty() || tls13.empty())
    {
        throw std::runtime_error("no validated kTLS cipher suites available on this host");
    }

    return
    {
        join_cipher_list(tls12),
        join_cipher_list(tls13),
    };
}

void probe_ktls_ulp()
{
    // kTLS (TCP_ULP=tls) can only be enabled on a connected socket, so we
    // create a real loopback connection to probe whether the kernel supports it
    const int listener = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (listener < 0)
    {
        throw std::system_error(errno, std::generic_category(), "socket probe listener");
    }

    int one = 1;

    (void)::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (::bind(listener, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        const int saved = errno;
        ::close(listener);
        throw std::system_error(saved, std::generic_category(), "bind probe listener");
    }

    if (::listen(listener, 1) != 0)
    {
        const int saved = errno;
        ::close(listener);
        throw std::system_error(saved, std::generic_category(), "listen probe listener");
    }

    socklen_t addr_len = sizeof(addr);

    if (::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addr_len) != 0)
    {
        const int saved = errno;
        ::close(listener);
        throw std::system_error(saved, std::generic_category(), "getsockname probe listener");
    }

    int accepted = -1;
    std::thread accept_thread([&]()
    {
        accepted = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
    });

    const int client = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (client < 0)
    {
        ::close(listener);
        accept_thread.join();
        throw std::system_error(errno, std::generic_category(), "socket probe client");
    }

    if (::connect(client, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        const int saved = errno;
        ::close(client);
        ::close(listener);
        accept_thread.join();
        throw std::system_error(saved, std::generic_category(), "connect probe client");
    }

    accept_thread.join();

    if (accepted < 0)
    {
        ::close(client);
        ::close(listener);
        throw std::system_error(errno, std::generic_category(), "accept probe listener");
    }

    const char name[] = "tls";

    if (::setsockopt(accepted, IPPROTO_TCP, TCP_ULP, name, sizeof(name)) != 0)
    {
        const int saved = errno;
        ::close(client);
        ::close(listener);
        ::close(accepted);
        throw std::system_error(saved, std::generic_category(), "setsockopt(TCP_ULP=tls)");
    }

    ::close(client);
    ::close(listener);
    ::close(accepted);
}

tls_context create_tls_context(const config &cfg)
{
    if (!cfg.tls_p12_path)
    {
        return {};
    }

#ifdef OPENSSL_NO_KTLS
    throw std::runtime_error("OpenSSL was built without kTLS support");
#endif
    probe_ktls_ulp();
    const ktls_cipher_policy cipher_policy = build_ktls_cipher_policy();

    if (OPENSSL_init_ssl(0, nullptr) != 1)
    {
        throw_openssl_error("OPENSSL_init_ssl");
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (ctx == nullptr)
    {
        throw_openssl_error("SSL_CTX_new");
    }

    tls_context owned(ctx);
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
#ifdef SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE);
#endif
    SSL_CTX_set_options(
        ctx,
        SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(ctx, 300);
    SSL_CTX_set_num_tickets(ctx, 4);
    static const unsigned char session_id_context[] = "brighttpd";

    if (SSL_CTX_set_session_id_context(
                ctx,
                session_id_context,
                static_cast<unsigned int>(sizeof(session_id_context) - 1)) != 1)
    {
        throw_openssl_error("SSL_CTX_set_session_id_context");
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_set_cipher_list(ctx, cipher_policy.tls12.c_str()) != 1)
    {
        throw_openssl_error("SSL_CTX_set_cipher_list");
    }

    if (SSL_CTX_set_ciphersuites(ctx, cipher_policy.tls13.c_str()) != 1)
    {
        throw_openssl_error("SSL_CTX_set_ciphersuites");
    }

    FILE *file = ::fopen(cfg.tls_p12_path->c_str(), "rb");

    if (file == nullptr)
    {
        throw std::system_error(errno, std::generic_category(), "fopen tls p12");
    }

    PKCS12 *bundle = d2i_PKCS12_fp(file, nullptr);
    ::fclose(file);

    if (bundle == nullptr)
    {
        throw_openssl_error("d2i_PKCS12_fp");
    }

    EVP_PKEY *key = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *chain = nullptr;
    const char* passphrase = cfg.tls_p12_passphrase ? cfg.tls_p12_passphrase->c_str() : "";
    const int parsed = PKCS12_parse(bundle, passphrase, &key, &cert, &chain);
    PKCS12_free(bundle);

    if (parsed != 1)
    {
        throw_openssl_error("PKCS12_parse");
    }

    const auto cleanup = [&]()
    {
        if (chain != nullptr)
        {
            sk_X509_pop_free(chain, X509_free);
            chain = nullptr;
        }

        if (cert != nullptr)
        {
            X509_free(cert);
            cert = nullptr;
        }

        if (key != nullptr)
        {
            EVP_PKEY_free(key);
            key = nullptr;
        }
    };

    if (SSL_CTX_use_certificate(ctx, cert) != 1)
    {
        cleanup();
        throw_openssl_error("SSL_CTX_use_certificate");
    }

    if (SSL_CTX_use_PrivateKey(ctx, key) != 1)
    {
        cleanup();
        throw_openssl_error("SSL_CTX_use_PrivateKey");
    }

    for (int i = 0; chain != nullptr && i < sk_X509_num(chain); ++i)
    {
        X509 *extra = sk_X509_value(chain, i);

        if (SSL_CTX_add_extra_chain_cert(ctx, X509_dup(extra)) != 1)
        {
            cleanup();
            throw_openssl_error("SSL_CTX_add_extra_chain_cert");
        }
    }

    if (SSL_CTX_check_private_key(ctx) != 1)
    {
        cleanup();
        throw_openssl_error("SSL_CTX_check_private_key");
    }

    cleanup();

    return owned;
}

struct privilege_drop
{
    std::optional<uid_t> uid;
    std::optional<gid_t> gid;
    std::optional<std::string> initgroups_user;
};

bool is_decimal(std::string_view text)
{
    if (text.empty())
    {
        return false;
    }

    for (char ch : text)
    {
        if (ch < '0' || ch > '9')
        {
            return false;
        }
    }

    return true;
}

std::optional<uid_t> resolve_uid(std::string_view user, std::optional<gid_t>& primary_gid, std::optional<std::string>& initgroups_user)
{
    if (is_decimal(user))
    {
        return static_cast<uid_t>(std::strtoul(std::string(user).c_str(), nullptr, 10));
    }

    if (passwd *pwd = ::getpwnam(std::string(user).c_str()))
    {
        primary_gid = pwd->pw_gid;
        initgroups_user = pwd->pw_name;
        return pwd->pw_uid;
    }

    throw std::runtime_error("unknown user: " + std::string(user));
}

std::optional<gid_t> resolve_gid(std::string_view group)
{
    if (is_decimal(group))
    {
        return static_cast<gid_t>(std::strtoul(std::string(group).c_str(), nullptr, 10));
    }

    if (struct group *grp = ::getgrnam(std::string(group).c_str()))
    {
        return grp->gr_gid;
    }

    throw std::runtime_error("unknown group: " + std::string(group));
}

privilege_drop resolve_privilege_drop(const config &cfg)
{
    privilege_drop drop;
    std::optional<gid_t> user_primary_gid;

    if (cfg.user)
    {
        drop.uid = resolve_uid(*cfg.user, user_primary_gid, drop.initgroups_user);
    }

    if (cfg.group)
    {
        drop.gid = resolve_gid(*cfg.group);
    }
    else if (user_primary_gid)
    {
        drop.gid = user_primary_gid;
    }

    return drop;
}

void clear_capabilities()
{
    __user_cap_header_struct header {};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    std::array<__user_cap_data_struct, 2> data {};

    if (::syscall(SYS_capset, &header, data.data()) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "capset");
    }
}

void harden_process(const config &cfg)
{
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "prctl(PR_SET_NO_NEW_PRIVS)");
    }

    const privilege_drop drop = resolve_privilege_drop(cfg);

    if (drop.uid || drop.gid)
    {
        if (::geteuid() != 0)
        {
            throw std::runtime_error("dropping user/group requires starting as root");
        }

        if (drop.initgroups_user && drop.gid)
        {
            if (::initgroups(drop.initgroups_user->c_str(), *drop.gid) != 0)
            {
                throw std::system_error(errno, std::generic_category(), "initgroups");
            }
        }
        else if (::setgroups(0, nullptr) != 0)
        {
            throw std::system_error(errno, std::generic_category(), "setgroups");
        }

        if (drop.gid && ::setgid(*drop.gid) != 0)
        {
            throw std::system_error(errno, std::generic_category(), "setgid");
        }

        if (drop.uid && ::setuid(*drop.uid) != 0)
        {
            throw std::system_error(errno, std::generic_category(), "setuid");
        }
    }

    clear_capabilities();
}

#if defined(__x86_64__)
#define BRIGHTTPD_ALLOW_SYSCALL(name) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

void install_seccomp_filter()
{
    sock_filter filter[] =
    {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<unsigned>(offsetof(seccomp_data, arch))),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, static_cast<unsigned>(offsetof(seccomp_data, nr))),

        BRIGHTTPD_ALLOW_SYSCALL(brk),
        BRIGHTTPD_ALLOW_SYSCALL(clock_gettime), // needed by OpenSSL / kTLS
        BRIGHTTPD_ALLOW_SYSCALL(close),
        BRIGHTTPD_ALLOW_SYSCALL(exit),
        BRIGHTTPD_ALLOW_SYSCALL(exit_group),
        BRIGHTTPD_ALLOW_SYSCALL(futex),
        BRIGHTTPD_ALLOW_SYSCALL(getpid),
        BRIGHTTPD_ALLOW_SYSCALL(getrandom),
        BRIGHTTPD_ALLOW_SYSCALL(gettid),
        BRIGHTTPD_ALLOW_SYSCALL(io_uring_enter),
        BRIGHTTPD_ALLOW_SYSCALL(madvise),
        BRIGHTTPD_ALLOW_SYSCALL(mmap),
        BRIGHTTPD_ALLOW_SYSCALL(mprotect),
        BRIGHTTPD_ALLOW_SYSCALL(munmap),
        BRIGHTTPD_ALLOW_SYSCALL(read),
        BRIGHTTPD_ALLOW_SYSCALL(recvfrom),
        BRIGHTTPD_ALLOW_SYSCALL(recvmsg),
        BRIGHTTPD_ALLOW_SYSCALL(restart_syscall),
        BRIGHTTPD_ALLOW_SYSCALL(rt_sigreturn),
        BRIGHTTPD_ALLOW_SYSCALL(sendfile),
        BRIGHTTPD_ALLOW_SYSCALL(sendmsg),
        BRIGHTTPD_ALLOW_SYSCALL(sendto),
        BRIGHTTPD_ALLOW_SYSCALL(setsockopt),
        BRIGHTTPD_ALLOW_SYSCALL(shutdown),
        BRIGHTTPD_ALLOW_SYSCALL(write),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    sock_fprog program
    {
        static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
        filter,
    };

    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "prctl(PR_SET_SECCOMP)");
    }
}

#undef BRIGHTTPD_ALLOW_SYSCALL
#else
void install_seccomp_filter()
{
    throw std::runtime_error("seccomp filter is only implemented for x86_64");
}

#endif

sockaddr_in6 parse_listen_address(std::string_view listen)
{
    sockaddr_in6 addr {};
    addr.sin6_family = AF_INET6;

    std::string host;
    std::string port_text;

    if (listen.empty())
    {
        throw std::runtime_error("missing required --listen <addr:port>");
    }

    if (listen.front() == '[')
    {
        const auto close = listen.find(']');

        if (close == std::string_view::npos || close + 1 >= listen.size() || listen[close + 1] != ':')
        {
            throw std::runtime_error("invalid listen address, expected [ipv6]:port");
        }

        host.assign(listen.substr(1, close - 1));
        port_text.assign(listen.substr(close + 2));
    }
    else
    {
        const auto colon = listen.rfind(':');

        if (colon == std::string_view::npos)
        {
            throw std::runtime_error("invalid listen address, expected addr:port");
        }

        host.assign(listen.substr(0, colon));
        port_text.assign(listen.substr(colon + 1));
    }

    if (host.empty() || port_text.empty())
    {
        throw std::runtime_error("invalid listen address, expected addr:port");
    }

    const unsigned long port = std::strtoul(port_text.c_str(), nullptr, 10);

    if (port == 0 || port > 65535)
    {
        throw std::runtime_error("invalid listen port");
    }

    addr.sin6_port = htons(static_cast<std::uint16_t>(port));

    if (::inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr) == 1)
    {
        return addr;
    }

    in_addr v4_addr {};

    if (::inet_pton(AF_INET, host.c_str(), &v4_addr) == 1)
    {
        addr.sin6_addr = IN6ADDR_ANY_INIT;
        addr.sin6_addr.s6_addr[10] = 0xff;
        addr.sin6_addr.s6_addr[11] = 0xff;
        std::memcpy(&addr.sin6_addr.s6_addr[12], &v4_addr, sizeof(v4_addr));
        return addr;
    }

    throw std::runtime_error("invalid numeric listen address");
}

int create_listener_socket(const config &cfg, std::string_view listen)
{
    const int fd = ::socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

    if (fd < 0)
    {
        throw std::system_error(errno, std::generic_category(), "socket");
    }

    int one = 1;
    int zero = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    // REUSEPORT: each worker binds the same port so the kernel distributes accepts
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    ::setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));

    int backlog_hint = cfg.tcp_defer_accept;
    ::setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &backlog_hint, sizeof(backlog_hint));
    int fastopen = cfg.tcp_fastopen;
    ::setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &fastopen, sizeof(fastopen));

    const sockaddr_in6 addr = parse_listen_address(listen);

    if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "bind");
    }

    if (::listen(fd, cfg.listen_backlog) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "listen");
    }

    return fd;
}

class worker
{
public:
    worker(
        const config &config,
        const shared_state &shared,
        const tls_context *tls,
        worker_mode mode,
        unsigned worker_id,
        int listener_fd)
        : config_(config),
          shared_(shared),
          tls_(tls),
          mode_(mode),
          worker_id_(worker_id),
          ring_(config.ring_entries),
          listener_fd_(listener_fd),
          connections_(config.max_connections)
    {
        free_list_.reserve(config.max_connections);

        for (std::uint32_t i = 0; i < config.max_connections; ++i)
        {
            connections_[i].request.resize(config.request_buffer_size);
            connections_[i].body.resize(config.body_buffer_size);
            free_list_.push_back(static_cast<std::uint32_t>(config.max_connections - 1 - i));
        }

        buf_ring_entries_ = 1;

        while (buf_ring_entries_ < connections_.size())
            buf_ring_entries_ <<= 1;

        buf_ring_mask_ = io_uring_ring::buf_ring_mask(buf_ring_entries_);
        recv_buffers_.resize(buf_ring_entries_ * config_.request_buffer_size);
        buf_ring_ = ring_.setup_buf_ring(kBufGroup, buf_ring_entries_);

        for (unsigned i = 0; i < buf_ring_entries_; ++i)
        {
            char* buf = recv_buffers_.data() + i * config_.request_buffer_size;
            io_uring_ring::buf_ring_add(buf_ring_, buf, static_cast<unsigned>(config_.request_buffer_size), i, buf_ring_mask_, i);
        }

        io_uring_ring::buf_ring_advance(buf_ring_, buf_ring_entries_);
        register_static_files();
        create_splice_pipe();
    }

    ~worker()
    {
        if (listener_fd_ >= 0)
        {
            ::close(listener_fd_);
        }

        if (splice_pipe_[0] >= 0)
        {
            ::close(splice_pipe_[0]);
        }

        if (splice_pipe_[1] >= 0)
        {
            ::close(splice_pipe_[1]);
        }

        if (buf_ring_)
        {
            ring_.free_buf_ring(buf_ring_, kBufGroup, buf_ring_entries_);
            buf_ring_ = nullptr;
        }
    }

    void run()
    {
        pin_to_cpu();
        install_seccomp_filter();
        submit_accept_multishot();
        submit_shutdown_poll();
        submit_timer();
        flush_submissions();

        while (g_running.load(std::memory_order_relaxed) || shutting_down_)
        {
            const int rc = ring_.pending() > 0 ? ring_.submit_and_wait(1) : ring_.get_events(1);

            if (rc < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }

                throw std::system_error(errno, std::generic_category(), "io_uring_enter");
            }

            unsigned completed = 0;

            while (io_uring_cqe *cqe = ring_.peek_cqe())
            {
                const auto kind = decode_kind(cqe->user_data);
                const auto index = decode_index(cqe->user_data);
                const int res = cqe->res;
                const unsigned flags = cqe->flags;
                ring_.cqe_seen();
                handle_completion(kind, index, res, flags);
                ++completed;

                if (completed >= config_.submit_batch_threshold && ring_.pending() > 0)
                {
                    flush_submissions();
                    completed = 0;
                }
            }

            flush_submissions();

            if (shutting_down_ && active_connections() == 0 && ring_.pending() == 0)
            {
                break;
            }
        }
    }

private:
    void submit_accept_multishot()
    {
        io_uring_sqe *sqe = wait_for_sqe();
        // MULTISHOT: single SQE reaps accepts until it drains the accept queue
        io_uring_ring::prep_accept_multishot(sqe, listener_fd_, SOCK_NONBLOCK | SOCK_CLOEXEC);
        sqe->user_data = encode_user_data(OpKind::Accept, 0);
    }

    void submit_recv(std::uint32_t index)
    {
        connection &conn = connections_[index];

        if (conn.ssl != nullptr)
        {
            drive_tls(index);
            return;
        }

        conn.state = ConnState::Receiving;
        io_uring_sqe *sqe = wait_for_sqe();
        io_uring_ring::prep_recv(
            sqe,
            conn.fd,
            conn.request.data() + conn.request_len,
            static_cast<unsigned>(conn.request.size() - conn.request_len),
            0);
        sqe->user_data = encode_user_data(OpKind::Recv, index);
    }

    void submit_recv_multishot(std::uint32_t index)
    {
        connection &conn = connections_[index];
        conn.state = ConnState::Receiving;
        io_uring_sqe *sqe = wait_for_sqe();
        io_uring_ring::prep_recv_multishot(sqe, conn.fd);
        sqe->buf_group = kBufGroup;
        sqe->flags |= IOSQE_BUFFER_SELECT;
        sqe->user_data = encode_user_data(OpKind::Recv, index);
    }

    void submit_send_parts(std::uint32_t index)
    {
        connection &conn = connections_[index];

        if (conn.ssl != nullptr)
        {
            drive_tls(index);
            return;
        }

        conn.state = ConnState::SendingHeader;
        io_uring_sqe *sqe = wait_for_sqe();
        conn.send_msg = {};

        unsigned iov_count = 0;
        const std::size_t header_remaining =
            conn.header && conn.header_sent < conn.header->size() ? (conn.header->size() - conn.header_sent) : 0;

        if (header_remaining > 0)
        {
            conn.send_iov[iov_count].iov_base =
                const_cast<char*>(conn.header->data() + conn.header_sent);
            conn.send_iov[iov_count].iov_len = header_remaining;
            ++iov_count;
        }

        const std::size_t body_remaining = conn.send_len - conn.send_sent;

        if (body_remaining > 0)
        {
            conn.send_iov[iov_count].iov_base = conn.wants_inline
                                                ? const_cast<char*>(inline_body_data(conn) + conn.send_base_offset + conn.send_sent)
                                                : static_cast<void*>(conn.body.data() + conn.send_sent);
            conn.send_iov[iov_count].iov_len = body_remaining;
            ++iov_count;
        }

        if (iov_count == 1)
        {
            io_uring_ring::prep_send(sqe, conn.fd, conn.send_iov[0].iov_base, conn.send_iov[0].iov_len, MSG_NOSIGNAL);
        }
        else
        {
            conn.send_msg.msg_iov = conn.send_iov.data();
            conn.send_msg.msg_iovlen = iov_count;
            io_uring_ring::prep_sendmsg(sqe, conn.fd, &conn.send_msg, MSG_NOSIGNAL);
        }

        sqe->user_data = encode_user_data(OpKind::SendParts, index);
    }

    void submit_read_body(std::uint32_t index)
    {
        connection &conn = connections_[index];
        conn.state = ConnState::SendingHeader;
        io_uring_sqe *sqe = wait_for_sqe();
        const std::size_t remaining = static_cast<std::size_t>(conn.file_end - conn.file_offset);
        const unsigned len = static_cast<unsigned>(std::min<std::size_t>(conn.body.size(), remaining));

        if (conn.file->fixed_fd >= 0)
        {
            io_uring_ring::prep_read_fixed(sqe, conn.file->fixed_fd, conn.body.data(), len, conn.file_offset);
        }
        else
        {
            io_uring_ring::prep_read(sqe, conn.file->fd, conn.body.data(), len, conn.file_offset);
        }

        sqe->user_data = encode_user_data(OpKind::ReadBody, index);
    }

    void submit_splice_in(std::uint32_t index)
    {
        connection &conn = connections_[index];
        conn.state = ConnState::SplicingIn;
        conn.splice_target = std::min<std::size_t>(
                                 config_.splice_chunk_size,
                                 static_cast<std::size_t>(conn.file_end - conn.file_offset));
        conn.pipe_ready = 0;

        io_uring_sqe *sqe = wait_for_sqe();
        const unsigned flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK |
                               ((conn.file->fixed_fd >= 0) ? SPLICE_F_FD_IN_FIXED : 0U);
        io_uring_ring::prep_splice(
            sqe,
            conn.file->fixed_fd >= 0 ? conn.file->fixed_fd : conn.file->fd,
            static_cast<std::int64_t>(conn.file_offset),
            splice_pipe_[1],
            -1,
            static_cast<unsigned>(conn.splice_target),
            flags);
        sqe->user_data = encode_user_data(OpKind::SpliceIn, index);
    }

    void submit_socket_poll(std::uint32_t index, short events)
    {
        connection &conn = connections_[index];

        if (conn.poll_armed)
        {
            return;
        }

        conn.state = ConnState::WaitingSocket;
        conn.poll_armed = true;
        conn.poll_events = events;
        io_uring_sqe *sqe = wait_for_sqe();
        io_uring_ring::prep_poll_add(sqe, conn.fd, static_cast<unsigned>(events));
        sqe->user_data = encode_user_data(OpKind::PollSocket, index);
    }

    void submit_close(std::uint32_t index)
    {
        connection &conn = connections_[index];

        if (conn.fd < 0 || conn.state == ConnState::Closing)
        {
            return;
        }

        conn.state = ConnState::Closing;
        io_uring_sqe *sqe = wait_for_sqe();
        io_uring_ring::prep_close(sqe, conn.fd);
        sqe->user_data = encode_user_data(OpKind::Close, index);
    }

    void submit_shutdown_poll()
    {
        if (g_shutdown_pipe[0] < 0)
        {
            return;
        }

        io_uring_sqe *sqe = wait_for_sqe();
        io_uring_ring::prep_poll_add(sqe, g_shutdown_pipe[0], POLLIN);
        sqe->user_data = encode_user_data(OpKind::Shutdown, 0);
    }

    void submit_timer()
    {
        timer_spec_.tv_sec = static_cast<__kernel_time64_t>(config_.idle_scan_interval_seconds);
        timer_spec_.tv_nsec = 0;
        io_uring_sqe *sqe = wait_for_sqe();
        io_uring_ring::prep_timeout(sqe, &timer_spec_);
        sqe->user_data = encode_user_data(OpKind::Timer, 0);
    }

    void handle_completion(OpKind kind, std::uint32_t index, int res, unsigned flags)
    {
        switch (kind)
        {
        case OpKind::Accept:
            handle_accept(res, flags);
            break;

        case OpKind::Recv:
        {
            const unsigned bid = (flags >> IORING_CQE_BUFFER_SHIFT) & 0xFFFF;
            const bool more = (flags & IORING_CQE_F_MORE) != 0;
            handle_recv(index, res, bid, more);
            break;
        }

        case OpKind::SendParts:
            handle_send_parts(index, res);
            break;

        case OpKind::ReadBody:
            handle_read_body(index, res);
            break;

        case OpKind::SpliceIn:
            handle_splice_in(index, res);
            break;

        case OpKind::SpliceOut:
            handle_splice_out(index, res);
            break;

        case OpKind::PollSocket:
            handle_poll_socket(index, res);
            break;

        case OpKind::Close:
            finish_close(index, res);
            break;

        case OpKind::Shutdown:
            handle_shutdown(res);
            break;

        case OpKind::Timer:
            handle_timer(res);
            break;
        }
    }

    bool tls_enabled() const
    {
        return tls_ != nullptr && static_cast<bool>(*tls_);
    }

    const char* inline_body_data(const connection &conn) const
    {
        if (conn.file != nullptr && conn.file->embedded_body != nullptr)
        {
            return conn.file->embedded_body;
        }

        if (conn.inline_response_ptr != nullptr)
        {
            return conn.inline_response_ptr->body;
        }

        return conn.dynamic_body.c_str();
    }

    std::size_t inline_body_size(const connection &conn) const
    {
        if (conn.file != nullptr && conn.file->embedded_body != nullptr)
        {
            return conn.file->embedded_body_len;
        }

        if (conn.inline_response_ptr != nullptr)
        {
            return conn.inline_response_ptr->body_len;
        }

        return conn.dynamic_body.size();
    }

    std::size_t inline_send_offset(const connection &conn) const
    {
        if (conn.file != nullptr && conn.file->embedded_body != nullptr)
        {
            return static_cast<std::size_t>(conn.file_offset);
        }

        return conn.inline_body_sent;
    }

    std::size_t inline_send_remaining(const connection &conn) const
    {
        if (conn.file != nullptr && conn.file->embedded_body != nullptr)
        {
            return static_cast<std::size_t>(conn.file_end - conn.file_offset);
        }

        return inline_body_size(conn) - conn.inline_body_sent;
    }

    SSL* create_tls_session(int fd) const
    {
        SSL *ssl = SSL_new(tls_->ctx);

        if (ssl == nullptr)
        {
            throw_openssl_error("SSL_new");
        }

        BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);

        if (bio == nullptr)
        {
            SSL_free(ssl);
            throw_openssl_error("BIO_new_socket");
        }

        SSL_set_bio(ssl, bio, bio);
        SSL_set_accept_state(ssl);
        SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        return ssl;
    }

    void handle_tls_want(std::uint32_t index, int ssl_error)
    {
        switch (ssl_error)
        {
        case SSL_ERROR_WANT_READ:
            submit_socket_poll(index, POLLIN);
            return;

        case SSL_ERROR_WANT_WRITE:
            submit_socket_poll(index, POLLOUT);
            return;

        default:
            submit_close(index);
            return;
        }
    }

    bool write_tls_bytes(std::uint32_t index, const void* buf, std::size_t len, std::size_t& written_total)
    {
        connection &conn = connections_[index];

        while (written_total < len)
        {
            std::size_t written = 0;
            const int rc = SSL_write_ex(
                               conn.ssl,
                               static_cast<const char*>(buf) + written_total,
                               len - written_total,
                               &written);

            if (rc == 1)
            {
                if (written == 0)
                {
                    break;
                }

                written_total += written;
                mark_activity(conn);
                continue;
            }

            handle_tls_want(index, SSL_get_error(conn.ssl, rc));
            return false;
        }

        return true;
    }

    bool send_tls_file(std::uint32_t index)
    {
        connection &conn = connections_[index];

        while (conn.file_offset < conn.file_end)
        {
            const std::size_t remaining = static_cast<std::size_t>(conn.file_end - conn.file_offset);
            const std::size_t chunk = std::min<std::size_t>(remaining, config_.splice_chunk_size);
            const ossl_ssize_t rc = SSL_sendfile(conn.ssl, conn.file->fd, static_cast<off_t>(conn.file_offset), chunk, 0);

            if (rc > 0)
            {
                conn.file_offset += static_cast<std::size_t>(rc);
                mark_activity(conn);
                continue;
            }

            handle_tls_want(index, SSL_get_error(conn.ssl, static_cast<int>(rc)));
            return false;
        }

        return true;
    }

    bool drive_tls_handshake(connection &conn, std::uint32_t index)
    {
        conn.state = ConnState::TlsHandshake;
        const int rc = SSL_accept(conn.ssl);

        if (rc == 1)
        {
            conn.tls_handshake_done = true;
            conn.tls_ktls_ready = BIO_get_ktls_send(SSL_get_wbio(conn.ssl)) == 1;

            if (!conn.tls_ktls_ready)
            {
                submit_close(index);
                return false;
            }

            return true;
        }

        handle_tls_want(index, SSL_get_error(conn.ssl, rc));
        return false;
    }

    bool drive_tls_parse(connection &conn, std::uint32_t index)
    {
        for (;;)
        {
            const parse_result parsed = parse_request(conn.request.data(), conn.request_len);

            if (parsed.complete)
            {
                if (!parsed.valid)
                {
                    if (std::string_view(conn.request.data(), conn.request_len).rfind("GET ", 0) != 0 &&
                            std::string_view(conn.request.data(), conn.request_len).rfind("HEAD ", 0) != 0)
                    {
                        prepare_inline_response(conn, shared_.method_not_allowed, true);
                    }
                    else
                    {
                        prepare_inline_response(conn, shared_.bad_request, true);
                    }

                    conn.send_len = inline_body_size(conn);
                }
                else
                {
                    conn.head_only = parsed.head_only;
                    conn.close_after = parsed.close_after;
                    prepare_request_response(conn, parsed);

                    if (conn.head_only)
                    {
                        conn.send_len = 0;
                    }
                    else if (conn.wants_inline)
                    {
                        conn.send_base_offset = inline_send_offset(conn);
                        conn.send_len = inline_send_remaining(conn);
                        conn.send_sent = 0;
                    }
                    else if (conn.file && conn.buffered_body && conn.send_len == 0)
                    {
                        submit_read_body(index);
                        return false;
                    }
                }

                return true;
            }

            if (conn.request_len == conn.request.size())
            {
                prepare_inline_response(conn, shared_.bad_request, true);
                conn.send_len = inline_body_size(conn);
                return true;
            }

            conn.state = ConnState::Receiving;
            std::size_t nread = 0;
            const int rc = SSL_read_ex(
                               conn.ssl,
                               conn.request.data() + conn.request_len,
                               conn.request.size() - conn.request_len,
                               &nread);

            if (rc == 1)
            {
                if (nread == 0)
                {
                    submit_close(index);
                    return false;
                }

                const std::size_t prior_request_len = conn.request_len;
                conn.request_len += nread;
                mark_request_bytes(conn, prior_request_len);
                continue;
            }

            handle_tls_want(index, SSL_get_error(conn.ssl, rc));
            return false;
        }
    }

    void drive_tls_send(connection &conn, std::uint32_t index)
    {
        if (conn.header && conn.header_sent < conn.header->size())
        {
            if (!write_tls_bytes(index, conn.header->data(), conn.header->size(), conn.header_sent))
            {
                return;
            }
        }

        if (conn.head_only)
        {
            complete_response(index);
            return;
        }

        if (conn.wants_inline)
        {
            const char* body = inline_body_data(conn) + conn.send_base_offset;

            if (!write_tls_bytes(index, body, conn.send_len, conn.send_sent))
            {
                return;
            }

            conn.inline_body_sent += conn.send_len;
            complete_response(index);
            return;
        }

        if (conn.file && conn.buffered_body)
        {
            if (conn.send_len == 0)
            {
                submit_read_body(index);
                return;
            }

            if (!write_tls_bytes(index, conn.body.data(), conn.send_len, conn.send_sent))
            {
                return;
            }

            conn.file_offset += conn.send_len;

            if (conn.file_offset < conn.file_end)
            {
                conn.send_base_offset = 0;
                conn.send_len = 0;
                conn.send_sent = 0;
                submit_read_body(index);
                return;
            }

            complete_response(index);
            return;
        }

        if (conn.file && !send_tls_file(index))
        {
            return;
        }

        complete_response(index);
    }

    void drive_tls(std::uint32_t index)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];

        if (conn.fd < 0 || conn.ssl == nullptr)
        {
            return;
        }

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        for (;;)
        {
            if (!conn.tls_handshake_done)
            {
                if (!drive_tls_handshake(conn, index))
                {
                    return;
                }

                continue;
            }

            if (conn.header == nullptr)
            {
                if (!drive_tls_parse(conn, index))
                {
                    return;
                }
            }

            drive_tls_send(conn, index);
            return;
        }
    }

    void handle_accept(int res, unsigned flags)
    {
        if ((flags & IORING_CQE_F_MORE) == 0 && g_running.load(std::memory_order_relaxed))
        {
            submit_accept_multishot();
        }

        if (res < 0)
        {
            return;
        }

        if (shutting_down_)
        {
            ::close(res);
            return;
        }

        const std::uint32_t index = acquire_connection_slot();

        if (index == kInvalidIndex)
        {
            ::close(res);
            return;
        }

        connection &conn = connections_[index];
        reset_connection(conn);
        conn.fd = res;
        conn.accepted_at = steady_clock::now();
        mark_activity(conn);
        set_client_socket_options(conn.fd);

        if (tls_enabled())
        {
            conn.ssl = create_tls_session(conn.fd);
            drive_tls(index);
            return;
        }

        submit_recv_multishot(index);
    }

    void handle_recv(std::uint32_t index, int res, unsigned buf_id, bool recv_armed)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        if (would_block(res))
        {
            submit_recv_multishot(index);
            return;
        }

        if (res <= 0)
        {
            submit_close(index);
            return;
        }

        // data arrived while response was in flight (i love my life)
        // stash it for pipeline processing in complete_response()
        // instead of parsing out of order
        if (conn.state != ConnState::Receiving)
        {
            conn.pending_buf_id = buf_id;
            conn.pending_bytes = res;
            conn.recv_still_armed = recv_armed;
            return;
        }

        const std::size_t prior_request_len = conn.request_len;

        if (buf_id < buf_ring_entries_)
        {
            const char* data = recv_buffers_.data() + buf_id * config_.request_buffer_size;
            const std::size_t copy_len = std::min<std::size_t>(static_cast<std::size_t>(res),
                                         conn.request.size() - conn.request_len);
            std::memcpy(conn.request.data() + conn.request_len, data, copy_len);
            conn.request_len += copy_len;

            io_uring_ring::buf_ring_add(buf_ring_, const_cast<char*>(data),
                                        static_cast<unsigned>(config_.request_buffer_size), buf_id, buf_ring_mask_, 0);
            io_uring_ring::buf_ring_advance(buf_ring_, 1);
        }

        mark_request_bytes(conn, prior_request_len);
        const parse_result parsed = parse_request(conn.request.data(), conn.request_len);

        if (!parsed.complete)
        {
            if (conn.request_len == conn.request.size())
            {
                prepare_inline_response(conn, shared_.bad_request, true);
                conn.send_len = inline_body_size(conn);
                submit_send_parts(index);
                return;
            }

            if (!recv_armed && conn.fd >= 0 && conn.state != ConnState::Closing)
            {
                submit_recv_multishot(index);
            }

            return;
        }

        if (!parsed.valid)
        {
            if (std::string_view(conn.request.data(), conn.request_len).rfind("GET ", 0) != 0 &&
                    std::string_view(conn.request.data(), conn.request_len).rfind("HEAD ", 0) != 0)
            {
                prepare_inline_response(conn, shared_.method_not_allowed, true);
            }
            else
            {
                prepare_inline_response(conn, shared_.bad_request, true);
            }

            conn.send_len = inline_body_size(conn);
            submit_send_parts(index);
            return;
        }

        conn.head_only = parsed.head_only;
        conn.close_after = parsed.close_after;
        prepare_request_response(conn, parsed);

        if (conn.head_only)
        {
            submit_send_parts(index);
            return;
        }

        if (conn.wants_inline)
        {
            conn.send_base_offset = inline_send_offset(conn);
            conn.send_len = inline_send_remaining(conn);
            conn.send_sent = 0;
            submit_send_parts(index);
            return;
        }

        if (conn.file && conn.buffered_body)
        {
            submit_read_body(index);
            return;
        }

        if (conn.file && !conn.corked)
        {
            set_socket_cork(conn.fd, true);
            conn.corked = true;
        }

        submit_send_parts(index);
    }

    void handle_send_parts(std::uint32_t index, int res)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        if (would_block(res))
        {
            submit_socket_poll(index, POLLOUT);
            return;
        }

        if (res <= 0)
        {
            submit_close(index);
            return;
        }

        mark_activity(conn);

        std::size_t remaining = static_cast<std::size_t>(res);

        if (conn.header && conn.header_sent < conn.header->size())
        {
            const std::size_t header_remaining = conn.header->size() - conn.header_sent;
            const std::size_t header_consumed = std::min(header_remaining, remaining);
            conn.header_sent += header_consumed;
            remaining -= header_consumed;
        }

        if (remaining > 0)
        {
            conn.send_sent += remaining;
        }

        const bool header_done = !conn.header || conn.header_sent >= conn.header->size();

        if (!header_done || conn.send_sent < conn.send_len)
        {
            submit_send_parts(index);
            return;
        }

        if (conn.head_only)
        {
            complete_response(index);
            return;
        }

        if (conn.wants_inline)
        {
            conn.inline_body_sent += conn.send_len;
            complete_response(index);
            return;
        }

        if (conn.file && conn.buffered_body && conn.send_len > 0)
        {
            conn.file_offset += conn.send_len;

            if (conn.file_offset < conn.file_end)
            {
                conn.send_base_offset = 0;
                conn.send_len = 0;
                conn.send_sent = 0;
                submit_read_body(index);
                return;
            }

            complete_response(index);
            return;
        }

        if (conn.file && conn.file_offset < conn.file_end)
        {
            submit_splice_in(index);
            return;
        }

        complete_response(index);
    }

    void handle_read_body(std::uint32_t index, int res)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        if (would_block(res))
        {
            submit_read_body(index);
            return;
        }

        if (res <= 0)
        {
            submit_close(index);
            return;
        }

        mark_activity(conn);

        conn.send_base_offset = 0;
        conn.send_len = static_cast<std::size_t>(res);
        conn.send_sent = 0;
        submit_send_parts(index);
    }

    void handle_splice_in(std::uint32_t index, int res)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        if (would_block(res))
        {
            submit_splice_in(index);
            return;
        }

        if (res < 0)
        {
            submit_close(index);
            return;
        }

        if (res == 0)
        {
            complete_response(index);
            return;
        }

        mark_activity(conn);

        conn.pipe_ready = static_cast<std::size_t>(res);
        conn.splice_target = static_cast<std::size_t>(res);
        conn.state = ConnState::SplicingOut;
        io_uring_sqe *sqe = wait_for_sqe();
        io_uring_ring::prep_splice(
            sqe,
            splice_pipe_[0],
            -1,
            conn.fd,
            -1,
            static_cast<unsigned>(conn.pipe_ready),
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        sqe->user_data = encode_user_data(OpKind::SpliceOut, index);
    }

    void handle_splice_out(std::uint32_t index, int res)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        if (would_block(res))
        {
            submit_socket_poll(index, POLLOUT);
            return;
        }

        if (res <= 0)
        {
            submit_close(index);
            return;
        }

        mark_activity(conn);

        if (conn.pipe_ready == 0)
        {
            conn.pipe_ready = conn.splice_target;
        }

        conn.pipe_ready -= static_cast<std::size_t>(res);

        if (conn.pipe_ready > 0)
        {
            conn.state = ConnState::SplicingOut;
            io_uring_sqe *sqe = wait_for_sqe();
            io_uring_ring::prep_splice(
                sqe,
                splice_pipe_[0],
                -1,
                conn.fd,
                -1,
                static_cast<unsigned>(conn.pipe_ready),
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            sqe->user_data = encode_user_data(OpKind::SpliceOut, index);
            return;
        }

        conn.file_offset += conn.splice_target;

        if (conn.file && conn.file_offset < conn.file_end)
        {
            submit_splice_in(index);
            return;
        }

        complete_response(index);
    }

    void handle_poll_socket(std::uint32_t index, int res)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];
        conn.poll_armed = false;

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        if (res < 0)
        {
            submit_close(index);
            return;
        }

        mark_activity(conn);

        if (conn.ssl != nullptr)
        {
            drive_tls(index);
            return;
        }

        if (conn.header && conn.header_sent < conn.header->size())
        {
            submit_send_parts(index);
            return;
        }

        if (conn.send_sent < conn.send_len)
        {
            submit_send_parts(index);
            return;
        }

        if (!conn.wants_inline && conn.pipe_ready > 0)
        {
            conn.state = ConnState::SplicingOut;
            io_uring_sqe *sqe = wait_for_sqe();
            io_uring_ring::prep_splice(
                sqe,
                splice_pipe_[0],
                -1,
                conn.fd,
                -1,
                static_cast<unsigned>(conn.pipe_ready),
                SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
            sqe->user_data = encode_user_data(OpKind::SpliceOut, index);
            return;
        }

        if (!conn.wants_inline && conn.file && conn.file_offset < conn.file_end)
        {
            submit_splice_in(index);
            return;
        }

        complete_response(index);
    }

    void handle_shutdown(int res)
    {
        if (res < 0)
        {
            return;
        }

        initiate_shutdown();
    }

    void handle_timer(int res)
    {
        if (res == -ETIME || res == 0)
        {
            close_idle_connections();

            if (!shutting_down_ || active_connections() > 0)
            {
                submit_timer();
            }
        }
    }

    void complete_response(std::uint32_t index)
    {
        connection &conn = connections_[index];

        if (conn.corked)
        {
            set_socket_cork(conn.fd, false);
            conn.corked = false;
        }

        if (shutting_down_)
        {
            submit_close(index);
            return;
        }

        if (conn.close_after)
        {
            submit_close(index);
            return;
        }

        if (conn.pending_bytes > 0)
        {
            const auto bid = conn.pending_buf_id;
            const int pbytes = conn.pending_bytes;
            reset_response(conn);
            conn.pending_bytes = 0;
            conn.head_only = false;
            conn.close_after = false;
            conn.corked = false;
            conn.poll_armed = false;
            conn.recv_still_armed = false;
            conn.tls_handshake_done = false;
            conn.tls_ktls_ready = false;
            const auto now = steady_clock::now();
            conn.response_started_at = now;
            conn.request_started_at = now;
            conn.last_activity = now;

            if (bid < buf_ring_entries_)
            {
                char* data = recv_buffers_.data() + bid * config_.request_buffer_size;
                conn.request_len = std::min<std::size_t>(static_cast<std::size_t>(pbytes), conn.request.size());
                std::memcpy(conn.request.data(), data, conn.request_len);
                io_uring_ring::buf_ring_add(buf_ring_, data,
                                            static_cast<unsigned>(config_.request_buffer_size), bid, buf_ring_mask_, 0);
                io_uring_ring::buf_ring_advance(buf_ring_, 1);
            }

            conn.state = ConnState::Receiving;
            mark_request_bytes(conn, 0);
            const parse_result parsed = parse_request(conn.request.data(), conn.request_len);

            if (!parsed.complete)
            {
                return;
            }

            if (!parsed.valid)
            {
                if (std::string_view(conn.request.data(), conn.request_len).rfind("GET ", 0) != 0 &&
                        std::string_view(conn.request.data(), conn.request_len).rfind("HEAD ", 0) != 0)
                {
                    prepare_inline_response(conn, shared_.method_not_allowed, true);
                }
                else
                {
                    prepare_inline_response(conn, shared_.bad_request, true);
                }

                conn.send_len = inline_body_size(conn);
                submit_send_parts(index);
                return;
            }

            conn.head_only = parsed.head_only;
            conn.close_after = parsed.close_after;
            prepare_request_response(conn, parsed);

            if (conn.head_only)
            {
                submit_send_parts(index);
                return;
            }

            if (conn.wants_inline)
            {
                conn.send_base_offset = inline_send_offset(conn);
                conn.send_len = inline_send_remaining(conn);
                conn.send_sent = 0;
                submit_send_parts(index);
                return;
            }

            if (conn.file && conn.buffered_body)
            {
                submit_read_body(index);
                return;
            }

            if (conn.file && !conn.corked)
            {
                set_socket_cork(conn.fd, true);
                conn.corked = true;
            }

            submit_send_parts(index);
            return;
        }

        reset_response(conn);
        conn.request_len = 0;
        conn.head_only = false;
        conn.close_after = false;
        conn.corked = false;
        conn.pending_bytes = 0;
        conn.poll_armed = false;
        conn.recv_still_armed = false;
        conn.tls_handshake_done = false;
        conn.tls_ktls_ready = false;
        const auto now = steady_clock::now();
        conn.response_started_at = now;
        conn.request_started_at = now;
        conn.last_activity = now;

        if (conn.ssl != nullptr)
        {
            drive_tls(index);
            return;
        }

        conn.state = ConnState::Receiving;
    }

    void finish_close(std::uint32_t index, int)
    {
        if (index >= connections_.size())
        {
            return;
        }

        connection &conn = connections_[index];

        if (conn.ssl != nullptr)
        {
            SSL_free(conn.ssl);
            conn.ssl = nullptr;
        }

        if (conn.fd >= 0)
        {
            conn.fd = -1;
        }

        if (conn.pending_bytes > 0 && conn.pending_buf_id < buf_ring_entries_)
        {
            char* data = recv_buffers_.data() + conn.pending_buf_id * config_.request_buffer_size;
            io_uring_ring::buf_ring_add(buf_ring_, data,
                                        static_cast<unsigned>(config_.request_buffer_size), conn.pending_buf_id, buf_ring_mask_, 0);
            io_uring_ring::buf_ring_advance(buf_ring_, 1);
        }

        reset_connection(conn);
        free_list_.push_back(index);
    }

    void prepare_range_not_satisfiable(connection &conn, const file_record *file) const
    {
        reset_response(conn);
        conn.dynamic_body = "416 Range Not Satisfiable\n";
        const std::string content_range = "bytes */" + std::to_string(file ? file->size : 0);
        conn.dynamic_header_keep = build_header(
                                       "416 Range Not Satisfiable",
                                       conn.dynamic_body.size(),
                                       "text/plain; charset=utf-8",
                                       true,
                                       config_.keepalive_timeout_seconds,
                                       true,
                                       content_range);
        conn.dynamic_header_close = build_header(
                                        "416 Range Not Satisfiable",
                                        conn.dynamic_body.size(),
                                        "text/plain; charset=utf-8",
                                        false,
                                        config_.keepalive_timeout_seconds,
                                        true,
                                        content_range);
        conn.wants_inline = true;
        conn.header = conn.close_after ? &conn.dynamic_header_close : &conn.dynamic_header_keep;
        conn.response_started_at = steady_clock::now();
        conn.request_started_at = steady_clock::now();
    }

    void prepare_file_response(connection &conn, const file_record *file, std::string_view range_header) const
    {
        reset_response(conn);
        conn.file = file;
        conn.wants_inline = file && file->embedded_body != nullptr;
        conn.buffered_body = file && file->embedded_body == nullptr && file->size <= config_.buffered_threshold;
        conn.header = conn.close_after ? &file->header_close : &file->header_keep;
        conn.file_end = file ? file->size : 0;
        conn.response_started_at = steady_clock::now();
        conn.request_started_at = steady_clock::now();

        const range_result requested = parse_single_byte_range(range_header, file->size);

        if (requested.status == range_status::Unsatisfiable)
        {
            prepare_range_not_satisfiable(conn, file);
            return;
        }

        if (requested.status != range_status::Satisfiable)
        {
            return;
        }

        const std::uint64_t content_len = requested.range.end - requested.range.start;
        const std::string content_range =
            "bytes " + std::to_string(requested.range.start) + "-" +
            std::to_string(requested.range.end - 1) + "/" + std::to_string(file->size);
        conn.dynamic_header_keep = build_header(
                                       "206 Partial Content",
                                       content_len,
                                       file->mime,
                                       true,
                                       config_.keepalive_timeout_seconds,
                                       true,
                                       content_range);
        conn.dynamic_header_close = build_header(
                                        "206 Partial Content",
                                        content_len,
                                        file->mime,
                                        false,
                                        config_.keepalive_timeout_seconds,
                                        true,
                                        content_range);
        conn.header = conn.close_after ? &conn.dynamic_header_close : &conn.dynamic_header_keep;
        conn.file_offset = requested.range.start;
        conn.file_end = requested.range.end;
        conn.buffered_body = file->embedded_body == nullptr && content_len <= config_.buffered_threshold;
    }

    void prepare_inline_response(connection &conn, const inline_response &response, bool close_after) const
    {
        reset_response(conn);
        conn.inline_response_ptr = &response;
        conn.wants_inline = true;
        conn.close_after = close_after;
        conn.header = close_after ? &response.header_close : &response.header_keep;
        conn.response_started_at = steady_clock::now();
        conn.request_started_at = steady_clock::now();
    }

    void prepare_redirect_response(connection &conn, const parse_result &parsed) const
    {
        reset_response(conn);
        conn.dynamic_body = "308 Permanent Redirect\n";
        const std::string location = redirect_location(config_, parsed.host, parsed.route);
        conn.dynamic_header_keep = build_redirect_header(location, true, config_.keepalive_timeout_seconds, conn.dynamic_body.size());
        conn.dynamic_header_close = build_redirect_header(location, false, config_.keepalive_timeout_seconds, conn.dynamic_body.size());
        conn.wants_inline = true;
        conn.header = conn.close_after ? &conn.dynamic_header_close : &conn.dynamic_header_keep;
        conn.response_started_at = steady_clock::now();
        conn.request_started_at = steady_clock::now();
    }

    void prepare_request_response(connection &conn, const parse_result &parsed) const
    {
        if (mode_ == worker_mode::RedirectToTls)
        {
            prepare_redirect_response(conn, parsed);
            return;
        }

        const std::string_view route = (parsed.route == "/") ? std::string_view("/index.html") : parsed.route;
        auto it = shared_.routes.find(route);

        if (it == shared_.routes.end())
        {
            prepare_file_response(conn, shared_.not_found, {});
        }
        else
        {
            prepare_file_response(conn, it->second, parsed.range);
        }
    }

    std::uint32_t acquire_connection_slot()
    {
        if (free_list_.empty())
        {
            return kInvalidIndex;
        }

        const std::uint32_t index = free_list_.back();
        free_list_.pop_back();
        return index;
    }

    static void set_client_socket_options(int fd)
    {
        int one = 1;
        ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        ::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
    }

    void register_static_files()
    {
        std::vector<int> file_fds;
        file_fds.reserve(shared_.files.size());

        for (const auto &file : shared_.files)
        {
            if (file.fd >= 0)
            {
                file_fds.push_back(file.fd);
            }
        }

        if (file_fds.empty())
        {
            return;
        }

        if (ring_.register_files(file_fds.data(), static_cast<unsigned>(file_fds.size())) != 0)
        {
            return;
        }
    }

    // splice() requires one side of the transfer to be a pipe
    // this per-worker pipe pair is the intermediary for zero-copy file -> socket sends
    void create_splice_pipe()
    {
        if (::pipe2(splice_pipe_.data(), O_CLOEXEC | O_NONBLOCK) != 0)
        {
            throw std::system_error(errno, std::generic_category(), "pipe2");
        }

        (void)::fcntl(splice_pipe_[0], F_SETPIPE_SZ, static_cast<int>(config_.splice_chunk_size));
    }

    void initiate_shutdown()
    {
        if (shutting_down_)
        {
            return;
        }

        shutting_down_ = true;

        if (listener_fd_ >= 0)
        {
            ::close(listener_fd_);
            listener_fd_ = -1;
        }

        for (std::uint32_t index = 0; index < connections_.size(); ++index)
        {
            connection &conn = connections_[index];

            if (conn.fd < 0)
            {
                continue;
            }

            if (conn.corked)
            {
                set_socket_cork(conn.fd, false);
                conn.corked = false;
            }

            ::shutdown(conn.fd, SHUT_RDWR);
            submit_close(index);
        }
    }

    std::size_t active_connections() const
    {
        return connections_.size() - free_list_.size();
    }

    void close_idle_connections()
    {
        if (active_connections() == 0) return;

        const auto keepalive_timeout = std::chrono::seconds(config_.keepalive_timeout_seconds);
        const auto header_timeout = std::chrono::seconds(config_.header_timeout_seconds);
        const auto tls_handshake_timeout = std::chrono::seconds(config_.tls_handshake_timeout_seconds);
        const auto response_timeout = std::chrono::seconds(config_.response_timeout_seconds);
        const auto now = steady_clock::now();

        for (std::uint32_t index = 0; index < connections_.size(); ++index)
        {
            connection &conn = connections_[index];

            if (conn.fd < 0 || conn.state == ConnState::Closing)
            {
                continue;
            }

            if (conn.ssl != nullptr && !conn.tls_handshake_done)
            {
                if (now - conn.accepted_at >= tls_handshake_timeout)
                {
                    submit_close(index);
                }

                continue;
            }

            if (conn.request_len > 0 && conn.header == nullptr)
            {
                if (now - conn.request_started_at >= header_timeout)
                {
                    submit_close(index);
                }

                continue;
            }

            if (response_in_progress(conn))
            {
                if (now - conn.response_started_at >= response_timeout)
                {
                    submit_close(index);
                }

                continue;
            }

            if (now - conn.last_activity >= keepalive_timeout)
            {
                submit_close(index);
            }
        }
    }

    static void mark_activity(connection &conn)
    {
        conn.last_activity = steady_clock::now();
    }

    static void mark_request_bytes(connection &conn, std::size_t prior_request_len)
    {
        const auto now = steady_clock::now();

        if (prior_request_len == 0)
        {
            conn.request_started_at = now;
        }

        conn.last_activity = now;
    }

    static bool response_in_progress(const connection &conn)
    {
        if (conn.header != nullptr)
        {
            return true;
        }

        if (conn.wants_inline || conn.file != nullptr)
        {
            return true;
        }

        if (conn.send_len > 0 || conn.send_sent > 0)
        {
            return true;
        }

        if (conn.pipe_ready > 0 || conn.splice_target > 0)
        {
            return true;
        }

        return conn.state == ConnState::SendingHeader ||
               conn.state == ConnState::SplicingIn ||
               conn.state == ConnState::SplicingOut;
    }

    static void reset_connection(connection &conn)
    {
        reset_response(conn);
        conn.state = ConnState::Idle;
        conn.request_len = 0;
        conn.head_only = false;
        conn.close_after = false;
        conn.poll_armed = false;
        conn.tls_handshake_done = false;
        conn.tls_ktls_ready = false;
        conn.pending_bytes = 0;
        conn.last_activity = steady_clock::now();
        conn.request_started_at = conn.last_activity;
        conn.accepted_at = conn.last_activity;
        conn.response_started_at = conn.last_activity;
    }

    static void reset_response(connection &conn)
    {
        conn.file = nullptr;
        conn.inline_response_ptr = nullptr;
        conn.header = nullptr;
        conn.dynamic_header_keep.clear();
        conn.dynamic_header_close.clear();
        conn.dynamic_body.clear();
        conn.wants_inline = false;
        conn.buffered_body = false;
        conn.corked = false;
        conn.header_sent = 0;
        conn.inline_body_sent = 0;
        conn.file_offset = 0;
        conn.file_end = 0;
        conn.send_base_offset = 0;
        conn.send_len = 0;
        conn.send_sent = 0;
        conn.splice_target = 0;
        conn.pipe_ready = 0;
        conn.poll_events = 0;
    }

    io_uring_sqe* wait_for_sqe()
    {
        for (;;)
        {
            if (io_uring_sqe *sqe = ring_.get_sqe())
            {
                return sqe;
            }

            if (flush_submissions() < 0)
            {
                throw std::system_error(errno, std::generic_category(), "io_uring_enter submit");
            }
        }
    }

    int flush_submissions()
    {
        if (ring_.pending() == 0)
        {
            return 0;
        }

        return ring_.submit();
    }

    void pin_to_cpu() const
    {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(worker_id_ % std::max(1u, std::thread::hardware_concurrency()), &set);
        (void)pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
    }

    static constexpr std::uint32_t kInvalidIndex = UINT32_MAX;

    const config& config_;
    const shared_state& shared_;
    const tls_context* tls_{nullptr};
    worker_mode mode_{worker_mode::StaticFiles};
    unsigned worker_id_{0};
    io_uring_ring ring_;
    int listener_fd_{-1};
    std::array<int, 2> splice_pipe_{-1, -1};
    __kernel_timespec timer_spec_{};
    std::vector<connection> connections_;
    std::vector<std::uint32_t> free_list_;
    io_uring_buf_ring* buf_ring_{nullptr};
    std::vector<char> recv_buffers_;
    unsigned buf_ring_mask_{0};
    unsigned buf_ring_entries_{0};
    static constexpr __u16 kBufGroup = 0;
    bool shutting_down_{false};
};

std::string build_header(
    std::string_view status,
    std::uint64_t size,
    std::string_view mime,
    bool keep_alive,
    unsigned keepalive_timeout_seconds,
    bool accept_ranges,
    std::string_view content_range)
{
    std::string header;
    header.reserve(224 + content_range.size());
    header.append("HTTP/1.1 ");
    header.append(status);
    header.append("\r\nServer: brighttpd\r\nContent-Length: ");
    header.append(std::to_string(size));
    header.append("\r\nContent-Type: ");
    header.append(mime);

    if (accept_ranges)
    {
        header.append("\r\nAccept-Ranges: bytes");
    }

    if (!content_range.empty())
    {
        header.append("\r\nContent-Range: ");
        header.append(content_range);
    }

    if (keep_alive)
    {
        header.append("\r\nConnection: keep-alive\r\nKeep-Alive: timeout=");
        header.append(std::to_string(keepalive_timeout_seconds));
        header.append(", max=1000\r\n\r\n");
    }
    else
    {
        header.append("\r\nConnection: close\r\n\r\n");
    }

    return header;
}

std::string build_redirect_header(
    std::string_view location,
    bool keep_alive,
    unsigned keepalive_timeout_seconds,
    std::size_t body_len)
{
    std::string header;
    header.reserve(256 + location.size());
    header.append("HTTP/1.1 308 Permanent Redirect\r\nServer: brighttpd\r\nLocation: ");
    header.append(location);
    header.append("\r\nContent-Length: ");
    header.append(std::to_string(body_len));
    header.append("\r\nContent-Type: text/plain; charset=utf-8");

    if (keep_alive)
    {
        header.append("\r\nConnection: keep-alive\r\nKeep-Alive: timeout=");
        header.append(std::to_string(keepalive_timeout_seconds));
        header.append(", max=1000\r\n\r\n");
    }
    else
    {
        header.append("\r\nConnection: close\r\n\r\n");
    }

    return header;
}

inline_response build_inline_response(std::string_view status, std::string_view mime, const char* body, unsigned keepalive_timeout_seconds)
{
    inline_response response;
    response.body = body;
    response.body_len = std::strlen(body);
    response.header_keep = build_header(status, response.body_len, mime, true, keepalive_timeout_seconds);
    response.header_close = build_header(status, response.body_len, mime, false, keepalive_timeout_seconds);
    return response;
}

file_record build_embedded_file(
    std::string_view route,
    std::string_view status,
    std::string_view mime,
    const unsigned char* begin,
    const unsigned char* end,
    unsigned keepalive_timeout_seconds,
    bool accept_ranges)
{
    file_record file;
    file.route = std::string(route);
    file.fs_path = "<embedded:" + std::string(route.substr(route.rfind('/') + 1)) + ">";
    file.mime = std::string(mime);
    file.size = static_cast<std::uint64_t>(end - begin);
    file.embedded_body = reinterpret_cast<const char*>(begin);
    file.embedded_body_len = static_cast<std::size_t>(end - begin);
    file.header_keep = build_header(
                           status,
                           file.size,
                           file.mime,
                           true,
                           keepalive_timeout_seconds,
                           accept_ranges);
    file.header_close = build_header(
                            status,
                            file.size,
                            file.mime,
                            false,
                            keepalive_timeout_seconds,
                            accept_ranges);
    return file;
}

shared_state build_shared_state(const config &config)
{
    const fs::path &root = config.root;

    if (!fs::exists(root) || !fs::is_directory(root))
    {
        throw std::runtime_error("asset root does not exist: " + root.string());
    }

    shared_state shared;

    for (const auto &entry : fs::recursive_directory_iterator(root))
    {
        if (!entry.is_regular_file())
        {
            continue;
        }

        file_record file;
        file.fs_path = entry.path().string();
        file.route = "/" + fs::relative(entry.path(), root).generic_string();
        file.mime = mime_for(entry.path());
        file.fd = open_static_file(entry.path());
        file.fixed_fd = static_cast<int>(shared.files.size());
        file.size = file_size_for(file.fd);

        const bool is_not_found = (file.route == "/404.html");
        file.header_keep = build_header(
                               is_not_found ? "404 Not Found" : "200 OK",
                               file.size,
                               file.mime,
                               true,
                               config.keepalive_timeout_seconds,
                               !is_not_found);
        file.header_close = build_header(
                                is_not_found ? "404 Not Found" : "200 OK",
                                file.size,
                                file.mime,
                                false,
                                config.keepalive_timeout_seconds,
                                !is_not_found);
        shared.files.push_back(std::move(file));
    }

    const auto has_route = [&](std::string_view route)
    {
        for (const auto &file : shared.files)
        {
            if (file.route == route)
            {
                return true;
            }
        }

        return false;
    };

    if (!has_route("/index.html"))
    {
        shared.files.push_back(build_embedded_file(
                                   "/index.html",
                                   "200 OK",
                                   "text/html; charset=utf-8",
                                   _binary_index_html_start,
                                   _binary_index_html_end,
                                   config.keepalive_timeout_seconds,
                                   true));
    }

    if (!has_route("/404.html"))
    {
        shared.files.push_back(build_embedded_file(
                                   "/404.html",
                                   "404 Not Found",
                                   "text/html; charset=utf-8",
                                   _binary_404_html_start,
                                   _binary_404_html_end,
                                   config.keepalive_timeout_seconds,
                                   false));
    }

    for (const auto &file : shared.files)
    {
        if (file.route == "/index.html")
        {
            shared.index = &file;
        }

        if (file.route == "/404.html")
        {
            shared.not_found = &file;
            continue;
        }

        shared.routes.emplace(file.route, &file);
    }

    shared.bad_request = build_inline_response(
                             "400 Bad Request",
                             "text/plain; charset=utf-8",
                             "400 Bad Request\n",
                             config.keepalive_timeout_seconds);
    shared.method_not_allowed = build_inline_response(
                                    "405 Method Not Allowed",
                                    "text/plain; charset=utf-8",
                                    "405 Method Not Allowed\n",
                                    config.keepalive_timeout_seconds);

    return shared;
}

void validate_configuration_inputs(const config &cfg)
{
    if (cfg.tls_p12_path)
    {
        if (!cfg.tls_listen || cfg.tls_listen->empty())
        {
            throw std::runtime_error("missing required directive: tls_listen");
        }

        if (cfg.tls_redirect && cfg.listen.empty())
        {
            throw std::runtime_error("missing required directive: listen");
        }

        if (!cfg.listen.empty())
        {
            (void)parse_listen_address(cfg.listen);
        }

        (void)parse_listen_address(*cfg.tls_listen);
    }
    else
    {
        if (cfg.listen.empty())
        {
            throw std::runtime_error("missing required directive: listen");
        }

        if (cfg.tls_listen)
        {
            throw std::runtime_error("tls_listen requires tls_p12");
        }

        if (!cfg.tls_redirect)
        {
            throw std::runtime_error("tls_redirect requires tls_p12");
        }

        (void)parse_listen_address(cfg.listen);
    }

    if (cfg.root.empty())
    {
        throw std::runtime_error("missing required directive: root");
    }

    if (cfg.tls_p12_passphrase && !cfg.tls_p12_path)
    {
        throw std::runtime_error("tls_p12_passphrase requires tls_p12");
    }

    if (cfg.workers == 0)
    {
        throw std::runtime_error("workers must be greater than zero");
    }

    if (cfg.ring_entries == 0)
    {
        throw std::runtime_error("ring_entries must be greater than zero");
    }

    if (cfg.request_buffer_size == 0)
    {
        throw std::runtime_error("request_buffer_size must be greater than zero");
    }

    if (cfg.request_buffer_size > static_cast<std::size_t>(std::numeric_limits<unsigned>::max()))
    {
        throw std::runtime_error("request_buffer_size must fit in unsigned");
    }

    if (cfg.body_buffer_size == 0)
    {
        throw std::runtime_error("body_buffer_size must be greater than zero");
    }

    if (cfg.body_buffer_size > static_cast<std::size_t>(std::numeric_limits<unsigned>::max()))
    {
        throw std::runtime_error("body_buffer_size must fit in unsigned");
    }

    if (cfg.max_connections == 0 || cfg.max_connections > UINT32_MAX)
    {
        throw std::runtime_error("max_connections must be between 1 and UINT32_MAX");
    }

    if (cfg.listen_backlog <= 0)
    {
        throw std::runtime_error("listen_backlog must be greater than zero");
    }

    if (cfg.submit_batch_threshold == 0)
    {
        throw std::runtime_error("submit_batch_threshold must be greater than zero");
    }

    if (cfg.splice_chunk_size == 0 || cfg.splice_chunk_size > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        throw std::runtime_error("splice_chunk_size must be between 1 and INT_MAX");
    }

    if (cfg.buffered_threshold == 0)
    {
        throw std::runtime_error("buffered_threshold must be greater than zero");
    }

    if (cfg.idle_scan_interval_seconds == 0)
    {
        throw std::runtime_error("idle_scan_interval must be greater than zero");
    }

    (void)resolve_privilege_drop(cfg);
}

std::string config_error_prefix(const fs::path &path, std::size_t line_number)
{
    return path.string() + ":" + std::to_string(line_number) + ": ";
}

bool parse_yes_no(std::string_view value, std::string_view option)
{
    if (value == "yes")
    {
        return true;
    }

    if (value == "no")
    {
        return false;
    }

    throw std::runtime_error("invalid value for " + std::string(option) + ": expected yes or no");
}

void validate_config_file_permissions(const fs::path &path)
{
    struct stat st {};

    if (::stat(path.c_str(), &st) != 0)
    {
        throw std::system_error(errno, std::generic_category(), "stat config file");
    }

    if (!S_ISREG(st.st_mode))
    {
        throw std::runtime_error("config file is not a regular file: " + path.string());
    }

    const mode_t mode = st.st_mode & 0777;

    if (mode != 0600)
    {
        throw std::runtime_error(
            "config file must have mode 0600, got " + mode_to_octal(mode) + ": " + path.string());
    }

    const uid_t owner = st.st_uid;
    const uid_t expected_owner = ::geteuid();

    if (owner != expected_owner)
    {
        throw std::runtime_error(
            "config file must be owned by uid " + std::to_string(expected_owner) +
            ", got uid " + std::to_string(owner) + ": " + path.string());
    }
}

config load_config_file(const fs::path &path)
{
    validate_config_file_permissions(path);
    std::ifstream file(path);

    if (!file)
    {
        throw std::runtime_error("failed to open config file: " + path.string());
    }

    config cfg;
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(file, line))
    {
        ++line_number;
        const std::size_t comment = line.find('#');
        const std::string_view trimmed = trim_view(std::string_view(line).substr(0, comment));

        if (trimmed.empty())
        {
            continue;
        }

        const auto [directive, value] = split_directive_line(trimmed);

        if (directive.empty())
        {
            continue;
        }

        if (value.empty())
        {
            throw std::runtime_error(config_error_prefix(path, line_number) + "missing value for directive " + std::string(directive));
        }

        const std::string prefix = config_error_prefix(path, line_number);

        try
        {
            if (directive == "listen")
            {
                cfg.listen = std::string(value);
            }
            else if (directive == "tls_listen")
            {
                cfg.tls_listen = std::string(value);
            }
            else if (directive == "root")
            {
                cfg.root = fs::path(std::string(value));
            }
            else if (directive == "mime_types")
            {
                cfg.mime_types_path = fs::path(std::string(value));
            }
            else if (directive == "tls_p12")
            {
                cfg.tls_p12_path = fs::path(std::string(value));
            }
            else if (directive == "tls_p12_passphrase")
            {
                cfg.tls_p12_passphrase = std::string(value);
            }
            else if (directive == "tls_redirect")
            {
                cfg.tls_redirect = parse_yes_no(value, "tls_redirect");
            }
            else if (directive == "user")
            {
                cfg.user = std::string(value);
            }
            else if (directive == "group")
            {
                cfg.group = std::string(value);
            }
            else if (directive == "workers")
            {
                cfg.workers = value == "auto" ? default_worker_count()
                              : std::max(1u, parse_unsigned_option<unsigned>(value, "workers"));
            }
            else if (directive == "ring_entries")
            {
                cfg.ring_entries = parse_unsigned_option<unsigned>(value, "ring_entries");
            }
            else if (directive == "request_buffer_size")
            {
                cfg.request_buffer_size = parse_unsigned_option<std::size_t>(value, "request_buffer_size");
            }
            else if (directive == "body_buffer_size")
            {
                cfg.body_buffer_size = parse_unsigned_option<std::size_t>(value, "body_buffer_size");
            }
            else if (directive == "max_connections")
            {
                cfg.max_connections = parse_unsigned_option<std::size_t>(value, "max_connections");
            }
            else if (directive == "listen_backlog")
            {
                cfg.listen_backlog = parse_unsigned_option<int>(value, "listen_backlog");
            }
            else if (directive == "submit_batch_threshold")
            {
                cfg.submit_batch_threshold = parse_unsigned_option<unsigned>(value, "submit_batch_threshold");
            }
            else if (directive == "splice_chunk_size")
            {
                cfg.splice_chunk_size = parse_unsigned_option<std::size_t>(value, "splice_chunk_size");
            }
            else if (directive == "buffered_threshold")
            {
                cfg.buffered_threshold = parse_unsigned_option<std::size_t>(value, "buffered_threshold");
            }
            else if (directive == "header_timeout")
            {
                cfg.header_timeout_seconds = parse_unsigned_option<unsigned>(value, "header_timeout");
            }
            else if (directive == "tls_handshake_timeout")
            {
                cfg.tls_handshake_timeout_seconds = parse_unsigned_option<unsigned>(value, "tls_handshake_timeout");
            }
            else if (directive == "keepalive_timeout")
            {
                cfg.keepalive_timeout_seconds = parse_unsigned_option<unsigned>(value, "keepalive_timeout");
            }
            else if (directive == "response_timeout")
            {
                cfg.response_timeout_seconds = parse_unsigned_option<unsigned>(value, "response_timeout");
            }
            else if (directive == "idle_scan_interval")
            {
                cfg.idle_scan_interval_seconds = parse_unsigned_option<unsigned>(value, "idle_scan_interval");
            }
            else if (directive == "tcp_defer_accept")
            {
                cfg.tcp_defer_accept = parse_unsigned_option<int>(value, "tcp_defer_accept");
            }
            else if (directive == "tcp_fastopen")
            {
                cfg.tcp_fastopen = parse_unsigned_option<int>(value, "tcp_fastopen");
            }
            else
            {
                throw std::runtime_error("unknown directive: " + std::string(directive));
            }
        }
        catch (const std::exception &ex)
        {
            throw std::runtime_error(prefix + ex.what());
        }
    }

    validate_configuration_inputs(cfg);
    return cfg;
}

cli_options parse_cli(int argc, char** argv)
{
    cli_options cli;

    for (int i = 1; i < argc; ++i)
    {
        const std::string_view arg(argv[i]);

        if (arg == "-h")
        {
            cli.show_help = true;
            return cli;
        }

        if (arg == "-n")
        {
            cli.dry_run = true;
            continue;
        }

        if (arg == "-c")
        {
            if (i + 1 >= argc)
            {
                throw std::runtime_error("missing value for -c");
            }

            cli.config_path = fs::path(argv[++i]);
            continue;
        }

        throw std::runtime_error("unknown argument: " + std::string(arg));
    }

    if (cli.config_path.empty())
    {
        throw std::runtime_error("missing required option: -c /path/to/config");
    }

    return cli;
}

void handle_signal(int signo)
{
    g_running.store(false, std::memory_order_relaxed);

    if (signo == SIGINT)
    {
        (void)::write(STDERR_FILENO, shutdown_sigint_message, sizeof(shutdown_sigint_message) - 1);
    }
    else if (signo == SIGTERM)
    {
        (void)::write(STDERR_FILENO, shutdown_sigterm_message, sizeof(shutdown_sigterm_message) - 1);
    }

    if (g_shutdown_pipe[1] >= 0)
    {
        const std::uint8_t byte = 1;
        (void)::write(g_shutdown_pipe[1], &byte, sizeof(byte));
    }
}

}  // namespace

int main(int argc, char** argv)
{
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    try
    {
        const std::string argv0 = program_name(argc > 0 ? argv[0] : nullptr);
        const cli_options cli = parse_cli(argc, argv);

        if (cli.show_help)
        {
            std::cout << usage_text(argv0) << '\n';
            return 0;
        }

        const config config = load_config_file(cli.config_path);
        const mime_types owned_mimes = config.mime_types_path
                                       ? mime_types::load_from_file(*config.mime_types_path)
                                       : mime_types {};
        g_active_mime_types = config.mime_types_path ? &owned_mimes : &mime_types::load_default();
        const tls_context tls = create_tls_context(config);
        const shared_state shared = build_shared_state(config);

        if (cli.dry_run)
        {
            std::cout << "brighttpd configuration OK\n";
            std::cout << config_summary(config) << '\n';
            std::cout << "indexed_files=" << shared.files.size()
                      << " tls=" << (config.tls_p12_path ? "enabled" : "disabled") << '\n';
            return 0;
        }

        if (::pipe2(g_shutdown_pipe.data(), O_CLOEXEC | O_NONBLOCK) != 0)
        {
            throw std::system_error(errno, std::generic_category(), "pipe2");
        }

        std::cerr << config_summary(config) << '\n';
        struct listener_plan
        {
            worker_mode mode;
            const tls_context* tls;
            std::string_view listen;
        };

        std::vector<listener_plan> plans;

        if (config.tls_p12_path)
        {
            if (config.tls_redirect && !config.listen.empty())
            {
                plans.push_back({worker_mode::RedirectToTls, nullptr, config.listen});
            }

            plans.push_back({worker_mode::StaticFiles, &tls, *config.tls_listen});
        }
        else
        {
            plans.push_back({worker_mode::StaticFiles, nullptr, config.listen});
        }

        struct worker_plan
        {
            worker_mode mode;
            const tls_context* tls;
            int listener_fd;
        };

        std::vector<worker_plan> worker_plans;

        worker_plans.reserve(config.workers * plans.size());

        for (const listener_plan &plan : plans)
        {
            for (unsigned i = 0; i < config.workers; ++i)
            {
                worker_plans.push_back({plan.mode, plan.tls, create_listener_socket(config, plan.listen)});
            }
        }

        harden_process(config);

        std::vector<std::thread> workers;
        workers.reserve(worker_plans.size());

        for (unsigned worker_index = 0; worker_index < worker_plans.size(); ++worker_index)
        {
            const worker_plan plan = worker_plans[worker_index];
            workers.emplace_back([&config, &shared, plan, worker_index]()
            {
                try
                {
                    worker worker_instance(config, shared, plan.tls, plan.mode, worker_index, plan.listener_fd);
                    worker_instance.run();
                }
                catch (const std::exception &ex)
                {
                    std::cerr << "brighttpd worker " << worker_index << ": " << ex.what() << '\n';
                    g_running.store(false, std::memory_order_relaxed);
                }
            });
        }

        for (auto &worker : workers)
        {
            worker.join();
        }

        ::close(g_shutdown_pipe[0]);
        ::close(g_shutdown_pipe[1]);
        g_shutdown_pipe = {-1, -1};
    }
    catch (const std::exception &ex)
    {
        std::cerr << "brighttpd: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
