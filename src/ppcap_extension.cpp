#define DUCKDB_EXTENSION_MAIN

#include "ppcap_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

namespace duckdb {

struct PCAPPacket {
    Timestamp timestamp;
    string source_ip;
    string dest_ip;
    int32_t length;
};

struct PCAPData : public TableFunctionData {
  pcap_t *handle;
  string filename;

  PCAPData(string filename) : filename(filename), handle(nullptr) {}

  ~PCAPData() {
    if (handle) {
      pcap_close(handle);
    }
  }
};

static void PCAPReaderFunction(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
    auto &pcap_data = (PCAPData &)*data_p.bind_data;

    struct pcap_pkthdr *header;
    const u_char *packet;
    int result;

    Vector &timestamp_vector = output.data[0];
    Vector &source_ip_vector = output.data[1];
    Vector &dest_ip_vector = output.data[2];
    Vector &length_vector = output.data[3];

    idx_t index = 0;
    while (index < STANDARD_VECTOR_SIZE) {
        result = pcap_next_ex(pcap_data.handle, &header, &packet);
        if (result == -2) {
            // End of file
            break;
        } else if (result == -1) {
            throw std::runtime_error(pcap_geterr(pcap_data.handle));
        } else if (result == 0) {
            // Timeout, continue
            continue;
        }

        struct ip *ip_header = (struct ip*)(packet + 14); // Skip Ethernet header

        double epoch_seconds = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
        timestamp_vector.SetValue(index, Value::TIMESTAMP(Timestamp::FromEpochSeconds(epoch_seconds)));
        source_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_src)));
        dest_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_dst)));
        length_vector.SetValue(index, Value::INTEGER(header->len));

        index++;
    }

    output.SetCardinality(index);
}

static unique_ptr<FunctionData> PCAPReaderBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<string> &names) {
    return_types = {LogicalType::TIMESTAMP, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::INTEGER};
    names = {"timestamp", "source_ip", "dest_ip", "length"};

    auto result = make_uniq<PCAPData>(input.inputs[0].GetValue<string>());
    char errbuf[PCAP_ERRBUF_SIZE];
    result->handle = pcap_open_offline(result->filename.c_str(), errbuf);
    if (result->handle == nullptr) {
        throw std::runtime_error(errbuf);
    }

    return result;
}

static void LoadInternal(DatabaseInstance &instance) {
  TableFunction pcap_reader("read_pcap", {LogicalType::VARCHAR}, PCAPReaderFunction, PCAPReaderBind);
  ExtensionUtil::RegisterFunction(instance, pcap_reader);
}

void PpcapExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string PpcapExtension::Name() {
	return "ppcap";
}

std::string PpcapExtension::Version() const {
#ifdef EXT_VERSION_PPCAP
	return EXT_VERSION_PPCAP;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void ppcap_init(duckdb::DatabaseInstance &db) {
    duckdb::DuckDB db_wrapper(db);
    db_wrapper.LoadExtension<duckdb::PpcapExtension>();
}

DUCKDB_EXTENSION_API const char *ppcap_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
