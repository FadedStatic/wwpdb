#pragma once
#include "nlohmann/json.hpp"
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
    std::uint16_t section{}, pad_0{};
    int32_t offset{}, size{};
    std::uint32_t characteristics{};
    std::uint16_t module_idx{}, pad_1{};
    std::uint32_t data_crc{}, reloc_crc{};
};

struct mod_info {
    std::uint32_t pad_0{};
    section_contrib section_contrib{};
    std::uint16_t flags{}, sym_stream{};
    std::uint32_t sym_bytes{}, c11_bytes{}, c13_bytes{};
    std::uint16_t src_file_count{}, pad{};
    std::uint32_t pad_2{}, src_file_name_idx{}, pdb_file_path_idx{};
    // mod_name and obj_name follow (both null terminated)
};

struct sym_record {
    std::uint16_t len{}, kind{};
};

struct sym_proc {
    std::uint32_t p_parent{}, p_end{}, p_next{}, proc_len{}, dbg_start{}, dbg_end{}, type_idx{}, offset{};
    std::uint16_t segment{};
    std::uint8_t flags{};
    // symbol name follows
};

// S_PUB32 (0x110E), different layout
struct sym_pub {
    std::uint32_t flags{};
    std::uint32_t offset{};
    std::uint16_t segment{};
    // symbol name follows
};

// man the PDB format is really amazing sometimes, this is just image_section_header.
struct pe_section {
    char name[8]{};
    std::uint32_t virtual_size{}, virtual_address{}, raw_size{}, raw_offset{}, reloc_offset{}, line_offset{};
    std::uint16_t reloc_count{}, line_count{};
    std::uint32_t characteristics{};
};
#pragma pack(pop)

namespace wwpdb {
    inline nlohmann::json parse(const std::vector<std::uint8_t>& pdb_bytes) {
        constexpr char magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00";
        const auto pdb_base = pdb_bytes.data();
        if (pdb_bytes.size() < sizeof(msf_superblock) || memcmp(pdb_base, magic, 32) != 0) return {};

        const auto& sb = *reinterpret_cast<const msf_superblock*>(pdb_base);
        const auto block_sz = sb.block_sz;
        const auto cdiv = [&](const std::uint32_t a) { return (a + block_sz - 1) / block_sz; };

        const auto read_blocks = [&](const std::uint32_t* blocks, std::uint32_t byte_len) {
            std::vector<uint8_t> out;
            out.reserve(byte_len);

            for (uint32_t i = 0, n = cdiv(byte_len); i < n; ++i) {
                const auto* src = pdb_base + blocks[i] * block_sz;
                out.insert(out.end(), src, src + (i == n - 1 ? byte_len - out.size() : block_sz));
            }

            return out;
        };

        const auto dir = read_blocks(
            reinterpret_cast<const std::uint32_t*>(pdb_base + sb.block_map_addr * block_sz),
            sb.num_dir_bytes
        );

        const auto get_stream = [&](const std::uint32_t idx) -> std::vector<uint8_t> {
            const auto stream_ct = *reinterpret_cast<const std::uint32_t*>(dir.data());
            const auto* stream_sizes = reinterpret_cast<const std::uint32_t*>(dir.data() + 4);

            if (idx >= stream_ct) return {};
            const auto stream_sz = stream_sizes[idx];
            if (!stream_sz || stream_sz == ~0u) return {};

            const auto* stream_blocks = stream_sizes + stream_ct;
            for (uint32_t i = 0; i < idx; ++i)
                stream_blocks += cdiv(stream_sizes[i] == ~0u ? 0 : stream_sizes[i]);

            return read_blocks(stream_blocks, stream_sz);
        };

        const auto dbi_data = get_stream(3);
        if (dbi_data.size() < sizeof(dbi_header)) return {};
        const auto& dbi = *reinterpret_cast<const dbi_header*>(dbi_data.data());
        if (dbi.version_sig != -1) return {};

        // DBI debug header sits after the four DBI substreams per llvm / msvc docs.
        // idx 10 has the section table which is of use to us.
        std::vector<uint32_t> sect_vas;

        {
            const auto dbg_hdr_off = sizeof(dbi_header)
                + static_cast<size_t>(dbi.mod_info_sz)
                + static_cast<size_t>(dbi.section_contrib_sz)
                + static_cast<size_t>(dbi.section_map_sz)
                + static_cast<size_t>(dbi.source_info_sz)
                + static_cast<size_t>(dbi.type_server_map_sz)
                + static_cast<size_t>(dbi.ec_substream_sz);

            constexpr int k_sect_hdr_idx = 5;
            const auto dbg_hdr_bytes = static_cast<size_t>(dbi.optional_dbg_header_sz);

            if (constexpr auto needed = (k_sect_hdr_idx + 1) * sizeof(int16_t);
                    dbg_hdr_off + dbg_hdr_bytes <= dbi_data.size() && dbg_hdr_bytes >= needed) {
                const auto* dbg = reinterpret_cast<const int16_t*>(dbi_data.data() + dbg_hdr_off);

                if (const auto sect_stream_idx = static_cast<uint32_t>(dbg[k_sect_hdr_idx]); sect_stream_idx != 0xFFFF) {
                    const auto sect_data = get_stream(sect_stream_idx);
                    const auto n_sects = sect_data.size() / sizeof(pe_section);
                    const auto* sects = reinterpret_cast<const pe_section*>(sect_data.data());

                    sect_vas.reserve(n_sects);
                    for (size_t i = 0; i < n_sects; ++i)
                        sect_vas.push_back(sects[i].virtual_address);
                }
            }
        }

        const auto to_rva = [&](const std::uint16_t seg, const std::uint32_t off) -> std::uint32_t {
            if (seg == 0 || seg > sect_vas.size()) return off;
            return sect_vas[seg - 1] + off;
        };

        nlohmann::json funcs = nlohmann::json::array();

        const auto scan_sym_stream = [&](const std::vector<uint8_t>& sym) {
            if (sym.size() < 4) return;

            const std::uint32_t first_dword = *reinterpret_cast<const std::uint32_t*>(sym.data());
            const auto* p = sym.data() + (first_dword == 4u ? 4u : 0u);
            const auto* e = sym.data() + sym.size();

            while (p + sizeof(sym_record) <= e) {
                const auto* rec = reinterpret_cast<const sym_record*>(p);
                if (rec->len < sizeof(uint16_t)) break;

                // aligninize this for real
                const auto* next = p + (sizeof(uint16_t) + rec->len + 3u & ~3u);
                if (next > e) break;

                const auto* payload = p + sizeof(sym_record);

                switch (rec->kind) {
                    case 0x110F: // S_LPROC32
                    case 0x1110: // S_GPROC32
                    case 0x1125: // S_LPROC32_DPC
                    case 0x1126: // S_LPROC32_DPC_ID
                    case 0x1146: // S_LPROC32_ID
                    case 0x1147: { // S_GPROC32_ID
                        const auto& proc = *reinterpret_cast<const sym_proc*>(payload);
                        funcs.push_back({
                            {"name", reinterpret_cast<const char*>(&proc + 1)},
                            {"rva", to_rva(proc.segment, proc.offset)},
                            {"segment", proc.segment},
                        });
                        break;
                    }
                    case 0x110E: { // S_PUB32, this one just has to be special man yeah woohooo who even cares about the convention am i right
                        const auto& pub = *reinterpret_cast<const sym_pub*>(payload);
                        funcs.push_back({
                            {"name", reinterpret_cast<const char*>(&pub + 1)},
                            {"rva", to_rva(pub.segment, pub.offset)},
                            {"segment", pub.segment},
                        });
                        break;
                    }
                    default: break;
                }

                p = next;
            }
        };

        const auto* mod_ptr = dbi_data.data() + sizeof(dbi_header);
        const auto* mod_end = mod_ptr + dbi.mod_info_sz;

        while (mod_ptr + sizeof(mod_info) <= mod_end) {
            const auto& mod = *reinterpret_cast<const mod_info*>(mod_ptr);

            if (mod.sym_stream != 0xFFFF)
                scan_sym_stream(get_stream(mod.sym_stream));

            const auto* n = reinterpret_cast<const char*>(mod_ptr + sizeof(mod_info));
            const auto* o = n + strlen(n) + 1;
            mod_ptr += (sizeof(mod_info) + strlen(n) + 1 + strlen(o) + 1 + 3) & ~3u;
        }

        {
            struct publics_header { // honestly if it were between publix and lidl I'd pick lidl every time
                std::uint32_t sym_hash_sz{},addr_map_sz{}, num_thunks{}, thunk_size{};
                std::uint16_t thunk_table_sec{},pad{};
                std::uint32_t thunk_table_off{},sect_count{};
            };

            const auto pub_data = get_stream(dbi.public_stream_idx);
            const auto sym_data = get_stream(dbi.sym_record_stream);

            if (pub_data.size() >= sizeof(publics_header) && !sym_data.empty()) {
                const auto& ph = *reinterpret_cast<const publics_header*>(pub_data.data());

                const auto addr_map_off = sizeof(publics_header) + ph.sym_hash_sz;
                const auto addr_map_cnt = ph.addr_map_sz / sizeof(uint32_t);

                if (addr_map_off + ph.addr_map_sz <= pub_data.size()) {
                    const auto* addr_map = reinterpret_cast<const std::uint32_t*>(pub_data.data() + addr_map_off);

                    for (uint32_t i = 0; i < addr_map_cnt; ++i) {
                        const std::uint32_t off = addr_map[i];
                        if (off + sizeof(sym_record) > sym_data.size()) continue;

                        const auto* rec = reinterpret_cast<const sym_record*>(sym_data.data() + off);
                        if (rec->kind != 0x110E) continue; // only S_PUB32

                        const auto* payload = reinterpret_cast<const std::uint8_t*>(rec + 1);
                        if (off + sizeof(sym_record) + sizeof(sym_pub) > sym_data.size()) continue;

                        const auto& pub = *reinterpret_cast<const sym_pub*>(payload);
                        funcs.push_back({
                            {"name", reinterpret_cast<const char*>(&pub + 1)},
                            {"rva", to_rva(pub.segment, pub.offset)},
                            {"segment", pub.segment},
                        });
                    }
                }
            }
        }

        std::sort(funcs.begin(), funcs.end(), [](const auto& a, const auto& b) {
            if (a["segment"] != b["segment"]) return a["segment"] < b["segment"];
            return a["rva"] < b["rva"];
        });
        funcs.erase(
            std::ranges::unique(funcs, [](const auto& a, const auto& b) {
                return a["segment"] == b["segment"] && a["rva"] == b["rva"];
            }).begin(),
            funcs.end()
        );

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
        return data.empty() ? nlohmann::json{} : parse(data);
    }
#endif
}