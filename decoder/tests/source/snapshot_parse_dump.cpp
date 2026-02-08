/*
 * \file       snapshot_parse_dump.cpp
 * \brief      OpenCSD : Snapshot parse dump tool
 *
 */

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "opencsd.h"
#include "snapshot_parser.h"
#include "snapshot_parser_util.h"

namespace
{
#ifdef WIN32
const char kPathSep = '\\';
#else
const char kPathSep = '/';
#endif

struct IniEntry
{
    std::string key;
    std::string value;
};

using IniSection = std::vector<IniEntry>;
using IniData = std::map<std::string, IniSection>;

struct RegEntry
{
    std::string regname;
    std::string value;
    std::string id;
    std::string size;
    bool has_id = false;
    bool has_size = false;
    bool id_is_numeric = false;
    uint64_t id_num = 0;
    size_t order = 0;
};

struct DumpEntry
{
    std::string section;
    std::string file;
    std::string space;
    std::string address_str;
    std::string length_str;
    std::string offset_str;
    uint64_t address_val = 0;
};

struct DeviceDump
{
    std::string name;
    std::string class_name;
    std::string type_name;
    std::string location;
    std::string ini_path;
    std::vector<RegEntry> regs;
    std::vector<DumpEntry> dumps;
};

struct TraceBufferDump
{
    std::string id;
    std::string name;
    std::string format;
    std::vector<std::string> files;
};

std::string Trim(const std::string &s)
{
    return Util::Trim(s);
}

std::string TrimQuotes(const std::string &s)
{
    return Util::Trim(s, "\"'");
}

void CleanLine(std::string &line)
{
    std::string::size_type endpos = line.find_first_of("\r;#");
    if (endpos != std::string::npos)
    {
        line.erase(endpos);
    }
}

bool IsSectionHeader(const std::string &line, std::string &sectionName)
{
    std::string::size_type openBracket(line.find('['));
    if (openBracket == std::string::npos)
        return false;
    std::string::size_type textStart(openBracket + 1);
    std::string::size_type closeBracket(line.find(']', textStart));
    if (closeBracket == std::string::npos)
        return false;
    sectionName.assign(Trim(line.substr(textStart, closeBracket - textStart)));
    return true;
}

std::pair<std::string, std::string> SplitKeyValue(const std::string &kv)
{
    std::string::size_type eq(kv.find('='));
    if (eq == std::string::npos)
    {
        throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                        "Couldn't parse '" + kv + "' as key=value");
    }
    return std::make_pair(Trim(kv.substr(0, eq)), Trim(kv.substr(eq + 1)));
}

IniData ParseIniFile(const std::string &filePath)
{
    std::ifstream in(filePath.c_str());
    if (!in.is_open())
    {
        throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                        "Failed to open ini file: " + filePath);
    }

    IniData data;
    std::string line;
    std::string current_section;
    bool have_section = false;

    while (std::getline(in, line))
    {
        CleanLine(line);
        std::string sectionName;
        if (IsSectionHeader(line, sectionName))
        {
            current_section = sectionName;
            have_section = true;
            if (data.find(current_section) == data.end())
            {
                data[current_section] = IniSection();
            }
        }
        else
        {
            if (Trim(line).empty())
                continue;
            if (!have_section)
            {
                throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                "Definition before section header in ini file: " + filePath);
            }
            std::pair<std::string, std::string> kv = SplitKeyValue(line);
            data[current_section].push_back({kv.first, kv.second});
        }
    }

    return data;
}

std::string NormalizePathForOutput(const std::string &path, bool strip_trailing)
{
    std::string out = path;
    std::replace(out.begin(), out.end(), '\\', '/');
    if (strip_trailing)
    {
        while (!out.empty() && out.back() == '/')
            out.pop_back();
    }
    return out;
}

bool IsAbsolutePath(const std::string &path)
{
    if (path.empty())
        return false;
    if (path[0] == '/' || path[0] == '\\')
        return true;
    if (path.size() > 1 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':')
        return true;
    return false;
}

std::string JoinPath(const std::string &base, const std::string &rel)
{
    if (rel.empty())
        return base;
    if (IsAbsolutePath(rel))
        return rel;
    if (base.empty())
        return rel;
    std::string out = base;
    if (out.back() != kPathSep && out.back() != '/' && out.back() != '\\')
        out.push_back(kPathSep);
    out += rel;
    return out;
}

std::vector<std::string> SplitCommaList(const std::string &value)
{
    std::vector<std::string> out;
    std::string remaining = value;
    std::string::size_type pos;
    while ((pos = remaining.find(',')) != std::string::npos)
    {
        std::string item = Trim(remaining.substr(0, pos));
        if (!item.empty())
            out.push_back(item);
        remaining = remaining.substr(pos + 1);
    }
    std::string last = Trim(remaining);
    if (!last.empty())
        out.push_back(last);
    return out;
}

bool ParseUnsigned(const std::string &value, uint64_t &out)
{
    char *endptr = 0;
#ifdef WIN32
    uint64_t result = _strtoui64(value.c_str(), &endptr, 0);
#else
    uint64_t result = std::strtoull(value.c_str(), &endptr, 0);
#endif
    if (!endptr || *endptr != '\0')
        return false;
    out = result;
    return true;
}

void ParseRegMetadata(const std::string &raw, RegEntry &entry)
{
    std::string::size_type open = raw.find('(');
    std::string::size_type close = raw.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close <= open)
    {
        entry.regname = Trim(raw);
        return;
    }

    entry.regname = Trim(raw.substr(0, open));
    std::string meta = raw.substr(open + 1, close - open - 1);
    std::vector<std::string> tokens = SplitCommaList(meta);
    for (size_t i = 0; i < tokens.size(); ++i)
    {
        std::string token = Trim(tokens[i]);
        if (token.empty())
            continue;
        std::string::size_type colon = token.find(':');
        if (colon != std::string::npos)
        {
            std::string key = Trim(token.substr(0, colon));
            std::string value = Trim(token.substr(colon + 1));
            if (key == "id")
            {
                entry.id = value;
                entry.has_id = true;
            }
            else if (key == "size")
            {
                entry.size = value;
                entry.has_size = true;
            }
        }
        else if (!entry.has_id)
        {
            entry.id = token;
            entry.has_id = true;
        }
    }

    if (entry.has_id)
    {
        uint64_t id_num = 0;
        if (ParseUnsigned(entry.id, id_num))
        {
            entry.id_is_numeric = true;
            entry.id_num = id_num;
        }
    }
}

void ValidateWithParser(const std::string &snapshot_ini_path,
                        const std::vector<std::string> &device_paths,
                        const std::string &trace_ini_path)
{
    std::ifstream in(snapshot_ini_path.c_str());
    if (!in.is_open())
    {
        throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                        "Failed to open snapshot.ini: " + snapshot_ini_path);
    }
    Parser::ParseDeviceList(in);
    in.close();

    for (size_t i = 0; i < device_paths.size(); ++i)
    {
        std::ifstream din(device_paths[i].c_str());
        if (!din.is_open())
        {
            throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                            "Failed to open device ini: " + device_paths[i]);
        }
        Parser::ParseSingleDevice(din);
    }

    if (!trace_ini_path.empty())
    {
        std::ifstream tin(trace_ini_path.c_str());
        if (!tin.is_open())
        {
            throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                            "Failed to open trace metadata ini: " + trace_ini_path);
        }
        Parser::ParseTraceMetaData(tin);
    }
}

void WriteLine(std::ostream &out, const std::string &line)
{
    out << line << "\n";
}

int RunSnapshotDump(int argc, char *argv[])
{
    std::string ss_dir;
    std::string output_file;
    bool quiet = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-ss_dir" && i + 1 < argc)
        {
            ss_dir = argv[++i];
        }
        else if (arg == "-o" && i + 1 < argc)
        {
            output_file = argv[++i];
        }
        else if (arg == "-quiet")
        {
            quiet = true;
        }
        else
        {
            std::ostringstream oss;
            oss << "Unknown or incomplete argument: " << arg;
            throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE, oss.str());
        }
    }

    if (ss_dir.empty() || output_file.empty())
    {
        throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                        "Usage: snapshot_parse_dump -ss_dir <snapshot_dir> -o <output_file> [-quiet]");
    }

    std::string ss_dir_output = NormalizePathForOutput(ss_dir, true);
    std::string snapshot_ini_path = JoinPath(ss_dir, "snapshot.ini");

    IniData snapshot_ini = ParseIniFile(snapshot_ini_path);

    std::string snapshot_version;
    std::string snapshot_description;

    if (snapshot_ini.find("snapshot") != snapshot_ini.end())
    {
        bool got_version = false;
        bool got_description = false;
        const IniSection &entries = snapshot_ini["snapshot"];
        for (size_t i = 0; i < entries.size(); ++i)
        {
            if (entries[i].key == "version")
            {
                if (got_version)
                    throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                    "Duplicate version key in [snapshot]");
                snapshot_version = entries[i].value;
                got_version = true;
            }
            else if (entries[i].key == "description")
            {
                if (got_description)
                    throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                    "Duplicate description key in [snapshot]");
                snapshot_description = entries[i].value;
                got_description = true;
            }
        }
    }

    if (snapshot_version.empty())
    {
        throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                        "Missing required [snapshot] version");
    }

    if (snapshot_ini.find("device_list") == snapshot_ini.end())
    {
        throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                        "Missing required [device_list] section");
    }

    std::vector<std::pair<std::string, std::string>> device_list;
    {
        const IniSection &entries = snapshot_ini["device_list"];
        for (size_t i = 0; i < entries.size(); ++i)
        {
            device_list.push_back(std::make_pair(entries[i].key, entries[i].value));
        }
    }

    std::string trace_metadata;
    if (snapshot_ini.find("trace") != snapshot_ini.end())
    {
        const IniSection &entries = snapshot_ini["trace"];
        for (size_t i = 0; i < entries.size(); ++i)
        {
            if (entries[i].key == "metadata")
            {
                trace_metadata = entries[i].value;
                break;
            }
        }
    }

    std::vector<std::pair<std::string, std::string>> clusters;
    if (snapshot_ini.find("clusters") != snapshot_ini.end())
    {
        const IniSection &entries = snapshot_ini["clusters"];
        for (size_t i = 0; i < entries.size(); ++i)
        {
            clusters.push_back(std::make_pair(entries[i].key, entries[i].value));
        }
    }

    std::vector<std::string> device_ini_paths;
    for (size_t i = 0; i < device_list.size(); ++i)
    {
        device_ini_paths.push_back(JoinPath(ss_dir, device_list[i].second));
    }

    std::string trace_ini_path;
    if (!trace_metadata.empty())
    {
        trace_ini_path = JoinPath(ss_dir, trace_metadata);
    }

    ValidateWithParser(snapshot_ini_path, device_ini_paths, trace_ini_path);

    std::vector<DeviceDump> devices;
    devices.reserve(device_list.size());

    for (size_t i = 0; i < device_list.size(); ++i)
    {
        const std::string device_ini_rel = device_list[i].second;
        const std::string device_ini_path = JoinPath(ss_dir, device_ini_rel);
        IniData device_ini = ParseIniFile(device_ini_path);

        DeviceDump device;
        device.ini_path = NormalizePathForOutput(device_ini_rel, false);

        if (device_ini.find("device") != device_ini.end())
        {
            bool got_name = false;
            const IniSection &entries = device_ini["device"];
            for (size_t j = 0; j < entries.size(); ++j)
            {
                if (entries[j].key == "name")
                {
                    device.name = entries[j].value;
                    got_name = true;
                }
                else if (entries[j].key == "class")
                {
                    device.class_name = entries[j].value;
                }
                else if (entries[j].key == "type")
                {
                    device.type_name = entries[j].value;
                }
                else if (entries[j].key == "location")
                {
                    device.location = entries[j].value;
                }
            }
            if (!got_name)
            {
                throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                "Device ini missing [device] name: " + device_ini_rel);
            }
        }
        else
        {
            throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                            "Device ini missing [device] section: " + device_ini_rel);
        }

        if (device_ini.find("regs") != device_ini.end())
        {
            const IniSection &entries = device_ini["regs"];
            for (size_t j = 0; j < entries.size(); ++j)
            {
                RegEntry reg;
                reg.value = TrimQuotes(entries[j].value);
                reg.order = j;
                ParseRegMetadata(entries[j].key, reg);
                device.regs.push_back(reg);
            }
        }

        for (IniData::const_iterator it = device_ini.begin(); it != device_ini.end(); ++it)
        {
            const std::string &section_name = it->first;
            if (section_name.rfind("dump", 0) == 0)
            {
                DumpEntry dump;
                dump.section = section_name;
                bool got_address = false;
                bool got_file = false;

                const IniSection &entries = it->second;
                for (size_t j = 0; j < entries.size(); ++j)
                {
                    if (entries[j].key == "file")
                    {
                        dump.file = NormalizePathForOutput(TrimQuotes(entries[j].value), false);
                        got_file = true;
                    }
                    else if (entries[j].key == "space")
                    {
                        dump.space = TrimQuotes(entries[j].value);
                    }
                    else if (entries[j].key == "address")
                    {
                        dump.address_str = Trim(entries[j].value);
                        if (!ParseUnsigned(dump.address_str, dump.address_val))
                        {
                            throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                            "Invalid dump address: " + dump.address_str);
                        }
                        got_address = true;
                    }
                    else if (entries[j].key == "length")
                    {
                        dump.length_str = Trim(entries[j].value);
                    }
                    else if (entries[j].key == "offset")
                    {
                        dump.offset_str = Trim(entries[j].value);
                    }
                }

                if (!got_address || !got_file)
                {
                    throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                    "Dump section missing file or address: " + device_ini_rel + "/" + section_name);
                }

                device.dumps.push_back(dump);
            }
        }

        std::sort(device.regs.begin(), device.regs.end(),
                  [](const RegEntry &a, const RegEntry &b) {
                      if (a.regname != b.regname)
                          return a.regname < b.regname;
                      if (a.has_id != b.has_id)
                          return !a.has_id;
                      if (a.has_id)
                      {
                          if (a.id_is_numeric && b.id_is_numeric && a.id_num != b.id_num)
                              return a.id_num < b.id_num;
                          if (a.id != b.id)
                              return a.id < b.id;
                      }
                      return a.order < b.order;
                  });

        std::sort(device.dumps.begin(), device.dumps.end(),
                  [](const DumpEntry &a, const DumpEntry &b) {
                      if (a.section != b.section)
                          return a.section < b.section;
                      return a.address_val < b.address_val;
                  });

        devices.push_back(device);
    }

    std::sort(devices.begin(), devices.end(),
              [](const DeviceDump &a, const DeviceDump &b) {
                  return a.name < b.name;
              });

    std::sort(device_list.begin(), device_list.end(),
              [](const std::pair<std::string, std::string> &a,
                 const std::pair<std::string, std::string> &b) {
                  return a.first < b.first;
              });

    std::sort(clusters.begin(), clusters.end(),
              [](const std::pair<std::string, std::string> &a,
                 const std::pair<std::string, std::string> &b) {
                  return a.first < b.first;
              });

    std::vector<TraceBufferDump> trace_buffers;
    std::vector<std::pair<std::string, std::string>> core_trace_sources;
    std::vector<std::pair<std::string, std::string>> source_buffers;
    std::vector<std::string> trace_buffer_ids;

    if (!trace_metadata.empty())
    {
        IniData trace_ini = ParseIniFile(trace_ini_path);
        if (trace_ini.find("trace_buffers") == trace_ini.end())
        {
            throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                            "Missing required [trace_buffers] section in " + trace_metadata);
        }

        const IniSection &trace_buffers_section = trace_ini["trace_buffers"];
        for (size_t i = 0; i < trace_buffers_section.size(); ++i)
        {
            if (trace_buffers_section[i].key == "buffers")
            {
                trace_buffer_ids = SplitCommaList(trace_buffers_section[i].value);
                break;
            }
        }

        if (trace_buffer_ids.empty())
        {
            throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                            "Trace metadata missing buffers list: " + trace_metadata);
        }

        std::sort(trace_buffer_ids.begin(), trace_buffer_ids.end());
        trace_buffer_ids.erase(std::unique(trace_buffer_ids.begin(), trace_buffer_ids.end()),
                               trace_buffer_ids.end());

        for (size_t i = 0; i < trace_buffer_ids.size(); ++i)
        {
            const std::string &buffer_id = trace_buffer_ids[i];
            if (trace_ini.find(buffer_id) == trace_ini.end())
            {
                throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                "Missing buffer section: " + buffer_id);
            }
            const IniSection &entries = trace_ini[buffer_id];
            TraceBufferDump buffer;
            buffer.id = buffer_id;
            bool got_name = false;
            bool got_file = false;
            for (size_t j = 0; j < entries.size(); ++j)
            {
                if (entries[j].key == "name")
                {
                    buffer.name = entries[j].value;
                    got_name = true;
                }
                else if (entries[j].key == "file")
                {
                    buffer.files = SplitCommaList(entries[j].value);
                    for (size_t f = 0; f < buffer.files.size(); ++f)
                        buffer.files[f] = NormalizePathForOutput(TrimQuotes(buffer.files[f]), false);
                    got_file = true;
                }
                else if (entries[j].key == "format")
                {
                    buffer.format = entries[j].value;
                }
            }
            if (!got_name || !got_file)
            {
                throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                                "Trace buffer section missing name or file: " + buffer_id);
            }
            trace_buffers.push_back(buffer);
        }

        if (trace_ini.find("core_trace_sources") != trace_ini.end())
        {
            const IniSection &entries = trace_ini["core_trace_sources"];
            for (size_t i = 0; i < entries.size(); ++i)
            {
                core_trace_sources.push_back(std::make_pair(entries[i].key, entries[i].value));
            }
        }

        if (trace_ini.find("source_buffers") != trace_ini.end())
        {
            const IniSection &entries = trace_ini["source_buffers"];
            for (size_t i = 0; i < entries.size(); ++i)
            {
                std::vector<std::string> buffers = SplitCommaList(entries[i].value);
                std::ostringstream joined;
                for (size_t b = 0; b < buffers.size(); ++b)
                {
                    if (b > 0)
                        joined << ",";
                    joined << buffers[b];
                }
                source_buffers.push_back(std::make_pair(entries[i].key, joined.str()));
            }
        }

        std::sort(core_trace_sources.begin(), core_trace_sources.end(),
                  [](const std::pair<std::string, std::string> &a,
                     const std::pair<std::string, std::string> &b) {
                      return a.first < b.first;
                  });

        std::sort(source_buffers.begin(), source_buffers.end(),
                  [](const std::pair<std::string, std::string> &a,
                     const std::pair<std::string, std::string> &b) {
                      return a.first < b.first;
                  });
    }

    std::ofstream out(output_file.c_str(), std::ios::out | std::ios::trunc);
    if (!out.is_open())
    {
        throw ocsdError(OCSD_ERR_SEV_ERROR, OCSD_ERR_TEST_SNAPSHOT_PARSE,
                        "Failed to open output file: " + output_file);
    }

    WriteLine(out, "snapshot_dir = " + ss_dir_output);
    WriteLine(out, "snapshot_ini = snapshot.ini");
    WriteLine(out, "snapshot.version = " + snapshot_version);
    WriteLine(out, "snapshot.description = " + snapshot_description);

    WriteLine(out, "device_list.count = " + std::to_string(device_list.size()));
    for (size_t i = 0; i < device_list.size(); ++i)
    {
        std::string key = device_list[i].first;
        std::string path = NormalizePathForOutput(device_list[i].second, false);
        WriteLine(out, "device_list." + key + " = " + path);
    }

    for (size_t i = 0; i < devices.size(); ++i)
    {
        const DeviceDump &device = devices[i];
        WriteLine(out, "[[device]]");
        WriteLine(out, "name = " + device.name);
        WriteLine(out, "class = " + device.class_name);
        WriteLine(out, "type = " + device.type_name);
        WriteLine(out, "location = " + device.location);
        WriteLine(out, "ini = " + device.ini_path);
        WriteLine(out, "regs.count = " + std::to_string(device.regs.size()));
        WriteLine(out, "dump.count = " + std::to_string(device.dumps.size()));

        for (size_t r = 0; r < device.regs.size(); ++r)
        {
            const RegEntry &reg = device.regs[r];
            std::string id_value = reg.has_id ? reg.id : "";
            std::string size_value = reg.has_size ? reg.size : "";
            std::string line = "reg." + reg.regname + " = " + reg.value +
                               " ; meta: id=" + id_value + " size=" + size_value;
            WriteLine(out, line);
        }

        for (size_t d = 0; d < device.dumps.size(); ++d)
        {
            const DumpEntry &dump = device.dumps[d];
            WriteLine(out, "[[dump]]");
            WriteLine(out, "section = " + dump.section);
            WriteLine(out, "file = " + dump.file);
            WriteLine(out, "space = " + dump.space);
            WriteLine(out, "address = " + dump.address_str);
            WriteLine(out, "length = " + dump.length_str);
            WriteLine(out, "offset = " + dump.offset_str);
        }
    }

    if (!clusters.empty())
    {
        WriteLine(out, "clusters.count = " + std::to_string(clusters.size()));
        for (size_t i = 0; i < clusters.size(); ++i)
        {
            std::vector<std::string> devices_in_cluster = SplitCommaList(clusters[i].second);
            std::ostringstream joined;
            for (size_t d = 0; d < devices_in_cluster.size(); ++d)
            {
                if (d > 0)
                    joined << ",";
                joined << devices_in_cluster[d];
            }
            WriteLine(out, "cluster." + clusters[i].first + " = " + joined.str());
        }
    }

    if (!trace_metadata.empty())
    {
        WriteLine(out, "trace.metadata = " + NormalizePathForOutput(trace_metadata, false));
        std::ostringstream ids_joined;
        for (size_t i = 0; i < trace_buffer_ids.size(); ++i)
        {
            if (i > 0)
                ids_joined << ",";
            ids_joined << trace_buffer_ids[i];
        }
        WriteLine(out, "trace_buffers.ids = " + ids_joined.str());

        for (size_t i = 0; i < trace_buffers.size(); ++i)
        {
            const TraceBufferDump &buf = trace_buffers[i];
            WriteLine(out, "[[trace_buffer]]");
            WriteLine(out, "id = " + buf.id);
            WriteLine(out, "name = " + buf.name);
            WriteLine(out, "format = " + buf.format);
            std::ostringstream files_joined;
            for (size_t f = 0; f < buf.files.size(); ++f)
            {
                if (f > 0)
                    files_joined << ",";
                files_joined << buf.files[f];
            }
            WriteLine(out, "files = " + files_joined.str());
        }

        for (size_t i = 0; i < core_trace_sources.size(); ++i)
        {
            WriteLine(out, "[[core_trace_source]]");
            WriteLine(out, "core = " + core_trace_sources[i].first);
            WriteLine(out, "source = " + core_trace_sources[i].second);
        }

        for (size_t i = 0; i < source_buffers.size(); ++i)
        {
            WriteLine(out, "[[source_buffer]]");
            WriteLine(out, "source = " + source_buffers[i].first);
            WriteLine(out, "buffers = " + source_buffers[i].second);
        }
    }

    out.close();

    if (!quiet)
    {
        std::cout << "snapshot_parse_dump: wrote " << output_file << "\n";
    }

    return 0;
}

} // namespace

int main(int argc, char *argv[])
{
    try
    {
        return RunSnapshotDump(argc, argv);
    }
    catch (const ocsdError &err)
    {
        std::string msg = ocsdError::getErrorString(err);
        std::cerr << "snapshot_parse_dump error: " << msg << "\n";
        return 1;
    }
    catch (const std::exception &ex)
    {
        std::cerr << "snapshot_parse_dump error: " << ex.what() << "\n";
        return 1;
    }
    catch (...)
    {
        std::cerr << "snapshot_parse_dump error: unknown exception\n";
        return 1;
    }
}
