#pragma once
#include "nlohmann/json.hpp" // even if it's a lib dir, quotes still work
#define WWPDB_DOWNLOAD // comment this out if you do not wish to include downloading

#ifdef WWPDB_DOWNLOAD
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

#pragma pack(push, 1)
struct msf_superblock {
    char magic[32]{};
    std::uint32_t block_sz{}, free_block_map{}, num_blocks{}, num_dir_bytes{}, pad_0{}, block_map_addr{};
};

struct dbi_header {
    std::int32_t version_sig{}; // by spec, always -1
    std::uint32_t version_header{}, age{};
    std::uint16_t global_stream_idx{}, build_number{}, public_stream_idx{}, pdb_dll_version{}, sym_record_stream{}, pdb_dll_rbld{};
    std::int32_t mod_info_sz{}, section_contrib_sz{}, section_map_sz{}, source_info_sz{}, type_server_map_sz{};
    std::uint32_t mfc_type_server_idx{};
    std::int32_t optional_dbg_header_sz{}, ec_substream_sz{};
    std::uint16_t flags{}, machine{}, pad_0{}, pad_1{};
};

struct section_contrib {
    uint16_t section{}, pad_0{};
    int32_t  offset{},size{};
    uint32_t characteristics{};
    uint16_t module_idx{}, pad_1{};
    uint32_t data_crc{}, reloc_crc{};
};

struct mod_info {
    uint32_t pad_0{};
    section_contrib section_contrib{};
    uint16_t flags{}, sym_stream{};
    uint32_t sym_bytes{}, c11_bytes{}, c13_bytes{};
    uint16_t src_file_count{}, pad{};
    uint32_t pad_2{}, src_file_name_idx{}, pdb_file_path_idx{};
    // mod_name and obj_name follow (both null terminated)
};

struct sym_record {
    uint16_t len{}, kind{};
};

struct sym_proc {
    uint32_t p_parent{},p_end{},p_next{},proc_len{},dbg_start{},dbg_end{},type_idx{},offset{};
    uint16_t segment{};
    uint8_t  flags{};
    // symbol name at end of this.
};
#pragma pack(pop)

namespace wwpdb {
    inline nlohmann::json parse(const std::vector<std::uint8_t>& pdb_bytes) {
        constexpr char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";
        const auto pdb_base = pdb_bytes.data();
        if (pdb_bytes.size() < sizeof(msf_superblock) || memcmp(pdb_base, magic, 32) != 0) return {};

        const auto& sb = *reinterpret_cast<const msf_superblock*>(pdb_base);
        const auto block_sz = sb.block_sz;
        const auto cdiv = [&](const uint32_t a) { return (a + block_sz - 1) / block_sz; };

        const auto read_blocks = [&](const uint32_t* blocks, uint32_t byte_len) {
            std::vector<uint8_t> out;
            out.reserve(byte_len);

            for (uint32_t i = 0, n = cdiv(byte_len); i < n; ++i) {
                const auto* src = pdb_base + blocks[i] * block_sz;
                out.insert(out.end(), src, src + (i == n - 1 ? byte_len - out.size() : block_sz));
            }

            return out;
        };

        const auto dir = read_blocks(
            reinterpret_cast<const uint32_t*>(pdb_base + sb.block_map_addr * block_sz),
            sb.num_dir_bytes
        );

        const auto get_stream = [&](const uint32_t idx) -> std::vector<uint8_t> {
            const auto stream_ct = *reinterpret_cast<const uint32_t*>(dir.data());
            const auto* stream_sizes =  reinterpret_cast<const uint32_t*>(dir.data() + 4);
            const auto stream_sz  = stream_sizes[idx];

            if (idx >= stream_ct || !stream_sz || stream_sz == ~0u) return {};

            const auto* stream_blocks = stream_sizes + stream_ct;
            for (uint32_t i = 0; i < idx; ++i)
                stream_blocks += cdiv(stream_sizes[i] == ~0u ? 0 : stream_sizes[i]);

            return read_blocks(stream_blocks, stream_sz);
        };

        const auto dbi_data = get_stream(3);
        if (dbi_data.size() < sizeof(dbi_header)) return {};
        const auto& dbi = *reinterpret_cast<const dbi_header*>(dbi_data.data());
        if (dbi.version_sig != -1) return {};

        nlohmann::json funcs = nlohmann::json::array();

        const auto* mod_ptr = dbi_data.data() + sizeof(dbi_header);
        const auto* mod_end = mod_ptr + dbi.mod_info_sz;

        while (mod_ptr + sizeof(mod_info) <= mod_end) {
            if (const auto& mod = *reinterpret_cast<const mod_info*>(mod_ptr); mod.sym_stream != 0xFFFF) {
                const auto sym = get_stream(mod.sym_stream);
                const auto* p = sym.data() + 4;
                const auto* e = sym.data() + sym.size();

                while (p + sizeof(sym_record) <= e) {
                    const auto* rec  = reinterpret_cast<const sym_record*>(p);
                    const auto* next = p + sizeof(uint16_t) + rec->len;
                    if (next > e) break;

                    if (rec->kind == 0x110F || rec->kind == 0x1110 || rec->kind == 0x1146 || rec->kind == 0x1147) {
                        const auto& proc = *reinterpret_cast<const sym_proc*>(p + sizeof(sym_record));
                        funcs.push_back({
                            {"name", reinterpret_cast<const char*>(&proc + 1)},
                            {"rva", proc.offset},
                            {"segment", proc.segment},
                        });
                    }
                    p = next;
                }
            }

            const auto* n = reinterpret_cast<const char*>(mod_ptr + sizeof(mod_info));
            const auto* o = n + strlen(n) + 1;
            mod_ptr += (sizeof(mod_info) + strlen(n) + 1 + strlen(o) + 1 + 3) & ~3u;
        }

        return funcs;
    }

#ifdef WWPDB_DOWNLOAD
    namespace util {
        inline std::vector<uint8_t> download(const std::wstring_view host, const std::wstring_view path) {
            std::vector<uint8_t> buf{};

            const auto session = WinHttpOpen(L"wwpdb/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
            const auto connect = WinHttpConnect(session, host.data(), INTERNET_DEFAULT_HTTPS_PORT, 0);
            const auto request = WinHttpOpenRequest(connect, L"GET", path.data(), nullptr, nullptr, nullptr, WINHTTP_FLAG_SECURE);

            WinHttpSendRequest(request, nullptr, 0, nullptr, 0, 0, 0);
            WinHttpReceiveResponse(request, nullptr);

            auto bytes_read{0UL};
            do {
                auto available{0UL};
                WinHttpQueryDataAvailable(request, &available);
                if (!available) break;

                const auto offset = buf.size();
                buf.resize(offset + available);
                WinHttpReadData(request, buf.data() + offset, available, &bytes_read);
            } while (bytes_read > 0);

            WinHttpCloseHandle(request);
            WinHttpCloseHandle(connect);
            WinHttpCloseHandle(session);

            return buf;
        }
    }

    inline nlohmann::json parse(const std::wstring_view file_hash, const std::wstring_view base_url = L"msdl.microsoft.com") {
        const auto data = util::download(base_url, file_hash);
        std::printf("Downloaded %llu bytes\r\n", data.size());
        return data.empty() ? nlohmann::json{} : parse(data);
    }
#endif
}