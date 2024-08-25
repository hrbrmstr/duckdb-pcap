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

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace duckdb {

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

bool is_http(const uint8_t *payload, size_t payload_length) {
  // If payload is too short, it's probably not HTTP
  if (payload_length < 16) {
    return false;
  }

  // Convert the start of the payload to a string for easier parsing
  std::string start(reinterpret_cast<const char *>(payload),
                    std::min(payload_length, size_t(16)));
  std::transform(start.begin(), start.end(), start.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Check for HTTP methods
  static const char *http_methods[] = {"get ",     "post ",    "head ",
                                       "put ",     "delete ",  "trace ",
                                       "options ", "connect ", "patch "};
  for (const auto &method : http_methods) {
    if (start.compare(0, strlen(method), method) == 0) {
      return true;
    }
  }

  // Check for HTTP responses
  if (start.compare(0, 5, "http/") == 0) {
    return true;
  }

  return false;
}

static void IsHTTPFunction(DataChunk &args, ExpressionState &state,
                           Vector &result) {
  auto &payload_vector = args.data[0];

  auto payload_data = FlatVector::GetData<string_t>(payload_vector);
  auto result_data = FlatVector::GetData<bool>(result);

  auto &payload_validity = FlatVector::Validity(payload_vector);
  auto &result_validity = FlatVector::Validity(result);

  for (idx_t i = 0; i < args.size(); i++) {
    if (!payload_validity.RowIsValid(i)) {
      result_validity.SetInvalid(i);
      continue;
    }

    result_data[i] = is_http(
        reinterpret_cast<const uint8_t *>(payload_data[i].GetDataUnsafe()),
        payload_data[i].GetSize());
  }
}

static string mac_to_string(const unsigned char *mac) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (int i = 0; i < 6; ++i) {
    ss << std::setw(2) << static_cast<int>(mac[i]);
    if (i != 5)
      ss << ":";
  }
  return ss.str();
}

static string generate_tcp_session(const struct ip *ip_header,
                                   const struct tcphdr *tcp_header) {
  std::stringstream ss;
  ss << inet_ntoa(ip_header->ip_src) << ":" << ntohs(tcp_header->th_sport)
     << "-" << inet_ntoa(ip_header->ip_dst) << ":"
     << ntohs(tcp_header->th_dport);
  return ss.str();
}

static void PCAPReaderFunction(ClientContext &context,
                               TableFunctionInput &data_p, DataChunk &output) {
  auto &pcap_data = (PCAPData &)*data_p.bind_data;

  struct pcap_pkthdr *header;
  const u_char *packet;
  int result;

  Vector &timestamp_vector = output.data[0];
  Vector &source_ip_vector = output.data[1];
  Vector &dest_ip_vector = output.data[2];
  Vector &source_port_vector = output.data[3];
  Vector &dest_port_vector = output.data[4];
  Vector &length_vector = output.data[5];
  Vector &tcp_session_vector = output.data[6];
  Vector &source_mac_vector = output.data[7];
  Vector &dest_mac_vector = output.data[8];
  Vector &protocols_vector = output.data[9];
  Vector &payload_vector = output.data[10];

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

    double epoch_seconds = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
    timestamp_vector.SetValue(
        index, Value::TIMESTAMP(Timestamp::FromEpochSeconds(epoch_seconds)));

    vector<string> protocols;
    protocols.push_back("Ethernet");

    // Parse Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    source_mac_vector.SetValue(index,
                               Value(mac_to_string(eth_header->ether_shost)));
    dest_mac_vector.SetValue(index,
                             Value(mac_to_string(eth_header->ether_dhost)));

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    protocols.push_back("IP");

    source_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_src)));
    dest_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_dst)));
    length_vector.SetValue(index, Value::INTEGER(header->len));

    int source_port = 0;
    int dest_port = 0;
    string tcp_session;
    const u_char *payload;
    size_t payload_length;

    // Determine the transport layer protocol
    switch (ip_header->ip_p) {
    case IPPROTO_TCP: {
      protocols.push_back("TCP");
      struct tcphdr *tcp_header =
          (struct tcphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
      source_port = ntohs(tcp_header->th_sport);
      dest_port = ntohs(tcp_header->th_dport);
      tcp_session = generate_tcp_session(ip_header, tcp_header);
      payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2) +
                (tcp_header->th_off << 2);
      payload_length = header->len - (payload - packet);
      break;
    }
    case IPPROTO_UDP: {
      protocols.push_back("UDP");
      struct udphdr *udp_header =
          (struct udphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
      source_port = ntohs(udp_header->uh_sport);
      dest_port = ntohs(udp_header->uh_dport);
      payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2) +
                sizeof(struct udphdr);
      payload_length = header->len - (payload - packet);
      break;
    }
    case IPPROTO_ICMP:
      protocols.push_back("ICMP");
      payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2);
      payload_length = header->len - (payload - packet);
      break;
    default:
      protocols.push_back("Unknown");
      payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2);
      payload_length = header->len - (payload - packet);
    }

    source_port_vector.SetValue(index, Value::INTEGER(source_port));
    dest_port_vector.SetValue(index, Value::INTEGER(dest_port));
    tcp_session_vector.SetValue(
        index, tcp_session.empty() ? Value() : Value(tcp_session));

    // Set the payload as a BLOB
    payload_vector.SetValue(index, Value::BLOB(payload, payload_length));

    // Create a DuckDB list value from the protocols vector
    vector<Value> protocol_values;
    for (const auto &protocol : protocols) {
      protocol_values.push_back(Value(protocol));
    }
    protocols_vector.SetValue(
        index, Value::LIST(LogicalType::VARCHAR, protocol_values));

    index++;
  }

  output.SetCardinality(index);
}

static unique_ptr<FunctionData>
PCAPReaderBind(ClientContext &context, TableFunctionBindInput &input,
               vector<LogicalType> &return_types, vector<string> &names) {
  return_types = {
      LogicalType::TIMESTAMP, LogicalType::VARCHAR,
      LogicalType::VARCHAR,   LogicalType::INTEGER,
      LogicalType::INTEGER,   LogicalType::INTEGER,
      LogicalType::VARCHAR,   LogicalType::VARCHAR,
      LogicalType::VARCHAR,   LogicalType::LIST(LogicalType::VARCHAR),
      LogicalType::BLOB};
  names = {"timestamp", "source_ip", "dest_ip",     "source_port",
           "dest_port", "length",    "tcp_session", "source_mac",
           "dest_mac",  "protocols", "payload"};

  auto result = make_uniq<PCAPData>(input.inputs[0].GetValue<string>());
  char errbuf[PCAP_ERRBUF_SIZE];
  result->handle = pcap_open_offline(result->filename.c_str(), errbuf);
  if (result->handle == nullptr) {
    throw std::runtime_error(errbuf);
  }

  return result;
}

static void LoadInternal(DatabaseInstance &instance) {
  TableFunction pcap_reader("read_pcap", {LogicalType::VARCHAR},
                            PCAPReaderFunction, PCAPReaderBind);
  ExtensionUtil::RegisterFunction(instance, pcap_reader);
  ScalarFunction is_http_func("is_http", {LogicalType::BLOB},
                              LogicalType::BOOLEAN, IsHTTPFunction);
  ExtensionUtil::RegisterFunction(instance, is_http_func);
}

void PpcapExtension::Load(DuckDB &db) { LoadInternal(*db.instance); }
std::string PpcapExtension::Name() { return "ppcap"; }

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
