#define DUCKDB_EXTENSION_MAIN

#include "ppcap_extension.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>

#include <glob.h>

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
#include <vector>

namespace duckdb {

struct PCAPData : public TableFunctionData {
  vector<string> filenames;
  size_t current_file_index;
  pcap_t *handle;

  PCAPData() : current_file_index(0), handle(nullptr) {}

  ~PCAPData() {
    if (handle) {
      pcap_close(handle);
    }
  }
};

struct TransportLayerInfo {
  vector<string> protocols;
  int source_port;
  int dest_port;
  string tcp_session;
  const u_char *payload;
  size_t payload_length;
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

TransportLayerInfo determineTransportLayer(const struct ip *ip_header,
                                           const u_char *packet,
                                           const struct pcap_pkthdr *header) {
  TransportLayerInfo info;
  info.source_port = 0;
  info.dest_port = 0;

  switch (ip_header->ip_p) {
  case IPPROTO_TCP: {
    info.protocols.push_back("TCP");
    struct tcphdr *tcp_header =
        (struct tcphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
    info.source_port = ntohs(tcp_header->th_sport);
    info.dest_port = ntohs(tcp_header->th_dport);
    info.tcp_session = generate_tcp_session(ip_header, tcp_header);
    info.payload = packet + sizeof(struct ether_header) +
                   (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
    info.payload_length = header->len - (info.payload - packet);
    break;
  }
  case IPPROTO_UDP: {
    info.protocols.push_back("UDP");
    struct udphdr *udp_header =
        (struct udphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
    info.source_port = ntohs(udp_header->uh_sport);
    info.dest_port = ntohs(udp_header->uh_dport);
    info.payload = packet + sizeof(struct ether_header) +
                   (ip_header->ip_hl << 2) + sizeof(struct udphdr);
    info.payload_length = header->len - (info.payload - packet);
    break;
  }
  case IPPROTO_ICMP:
    info.protocols.push_back("ICMP");
    info.payload =
        packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2);
    info.payload_length = header->len - (info.payload - packet);
    break;
  default:
    info.protocols.push_back("Unknown");
    info.payload =
        packet + sizeof(struct ether_header) + (ip_header->ip_hl << 2);
    info.payload_length = header->len - (info.payload - packet);
  }

  return info;
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
    if (!pcap_data.handle) {
      // If we don't have an open file, try to open the next one
      if (pcap_data.current_file_index >= pcap_data.filenames.size()) {
        // No more files to process
        break;
      }
      char errbuf[PCAP_ERRBUF_SIZE];
      pcap_data.handle = pcap_open_offline(
          pcap_data.filenames[pcap_data.current_file_index].c_str(), errbuf);
      if (pcap_data.handle == nullptr) {
        throw std::runtime_error("Failed to open PCAP file: " + string(errbuf));
      }
      pcap_data.current_file_index++;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int result = pcap_next_ex(pcap_data.handle, &header, &packet);

    if (result == -2) {
      // End of file, close current file and move to next
      pcap_close(pcap_data.handle);
      pcap_data.handle = nullptr;
      continue;
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

    TransportLayerInfo tl_info =
        determineTransportLayer(ip_header, packet, header);
    protocols.insert(protocols.end(), tl_info.protocols.begin(),
                     tl_info.protocols.end());

    source_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_src)));
    dest_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_dst)));
    source_port_vector.SetValue(index, Value::INTEGER(tl_info.source_port));
    dest_port_vector.SetValue(index, Value::INTEGER(tl_info.dest_port));
    length_vector.SetValue(index, Value::INTEGER(tl_info.payload_length));
    tcp_session_vector.SetValue(index, tl_info.tcp_session.empty()
                                           ? Value()
                                           : Value(tl_info.tcp_session));

    // Set the payload as a BLOB
    payload_vector.SetValue(
        index, Value::BLOB(tl_info.payload, tl_info.payload_length));

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
  auto result = make_uniq<PCAPData>();

  if (input.inputs[0].type().id() == LogicalTypeId::VARCHAR) {
    // Single input: could be a filename or a wildcard
    string file_pattern = input.inputs[0].GetValue<string>();
    glob_t glob_result;
    glob(file_pattern.c_str(), GLOB_TILDE, NULL, &glob_result);
    for (unsigned int i = 0; i < glob_result.gl_pathc; ++i) {
      result->filenames.push_back(string(glob_result.gl_pathv[i]));
    }
    globfree(&glob_result);
  } else if (input.inputs[0].type().id() == LogicalTypeId::LIST) {
    // List input: multiple filenames
    auto file_list = ListValue::GetChildren(input.inputs[0]);
    for (const auto &file : file_list) {
      result->filenames.push_back(file.GetValue<string>());
    }
  } else {
    throw InvalidInputException("Input must be either a string (filename or "
                                "wildcard) or a list of strings (filenames)");
  }

  if (result->filenames.empty()) {
    throw InvalidInputException("No files found matching the input pattern");
  }

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

  return result;
}

static void LoadInternal(DatabaseInstance &instance) {
  TableFunction pcap_reader("read_pcap", {LogicalType::ANY}, PCAPReaderFunction,
                            PCAPReaderBind);
  ExtensionUtil::RegisterFunction(instance, pcap_reader);
  ScalarFunction is_http_func("is_http", {LogicalType::BLOB},
                              LogicalType::BOOLEAN, IsHTTPFunction);
  ExtensionUtil::RegisterFunction(instance, is_http_func);
}

void PpcapExtension::Load(DuckDB &db) { LoadInternal(*db.instance); }
std::string PpcapExtension::Name() { return "pcap"; }

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
