#define DUCKDB_EXTENSION_MAIN

#include "ppcap_extension.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include <glob.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

#ifndef DLT_RAW1
#define DLT_RAW1 101
#endif

#ifndef DLT_LOOP
#define DLT_LOOP 108
#endif

namespace duckdb {

struct PCAPData : public duckdb::FunctionData {
  vector<string> filenames;
  size_t current_file_index;
  pcap_t *handle;

  PCAPData() : current_file_index(0), handle(nullptr) {}

  ~PCAPData() {
    if (handle) {
      pcap_close(handle);
    }
  }

  unique_ptr<FunctionData> Copy() const override {
    auto copy = make_uniq<PCAPData>();
    copy->filenames = filenames;
    copy->current_file_index = current_file_index;
    copy->handle = nullptr; // Don't copy the handle, it will be reopened
    return unique_ptr<FunctionData>(copy.release());
  }

  bool Equals(const FunctionData &other) const override {
    auto &o = (const PCAPData &)other;
    return filenames == o.filenames &&
           current_file_index == o.current_file_index;
  }
};

struct TransportLayerInfo {
  vector<string> protocols;
  int source_port;
  int dest_port;
  string tcp_session;
  const u_char *payload;
  size_t payload_length;
  vector<string> tcp_flags;
  uint32_t tcp_seq_num;
};

struct ICMPInfo {
  uint8_t type;
  uint8_t code;
  std::string type_name;
  std::string additional_info;
  std::string message;
};

// ICMP type definitions
#define ICMP_ECHOREPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_SOURCE_QUENCH 4
#define ICMP_REDIRECT 5
#define ICMP_ECHO 8
#define ICMP_TIME_EXCEEDED 11

static std::string bytes_to_hex(const uint8_t *data, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<int>(data[i]);
  }
  return ss.str();
}

bool starts_with_http_verb(const string &payload) {
  static const vector<string> http_verbs = {"GET ",     "POST ",    "HEAD ",
                                            "PUT ",     "DELETE ",  "TRACE ",
                                            "OPTIONS ", "CONNECT ", "PATCH "};
  for (const auto &verb : http_verbs) {
    if (payload.compare(0, verb.length(), verb) == 0) {
      return true;
    }
  }
  return false;
}

static void ExtractHTTPRequestHeadersFunction(DataChunk &args,
                                              ExpressionState &state,
                                              Vector &result) {
  auto &payload_vector = args.data[0];

  UnifiedVectorFormat payload_data;
  payload_vector.ToUnifiedFormat(args.size(), payload_data);

  auto payloads = (string_t *)payload_data.data;

  for (idx_t i = 0; i < args.size(); i++) {
    idx_t payload_idx = payload_data.sel->get_index(i);

    if (!payload_data.validity.RowIsValid(payload_idx)) {
      result.SetValue(i, Value());
      continue;
    }

    const string_t &payload_str = payloads[payload_idx];
    string payload(payload_str.GetDataUnsafe(), payload_str.GetSize());

    if (!starts_with_http_verb(payload)) {
      result.SetValue(i, Value());
      continue;
    }

    vector<Value> headers;
    size_t pos = payload.find("\r\n");
    size_t last_pos = pos + 2;

    while (pos != string::npos && last_pos < payload.length()) {
      pos = payload.find("\r\n", last_pos);
      if (pos == string::npos)
        break;

      string header_line = payload.substr(last_pos, pos - last_pos);
      size_t colon_pos = header_line.find(':');

      if (colon_pos != string::npos) {
        string key = header_line.substr(0, colon_pos);
        string value = header_line.substr(colon_pos + 1);

        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t"));
        value.erase(value.find_last_not_of(" \t") + 1);

        headers.emplace_back(Value::STRUCT(
            {make_pair("key", Value(key)), make_pair("value", Value(value))}));
      }

      last_pos = pos + 2;
    }

    result.SetValue(
        i, Value::LIST(LogicalType::STRUCT({{"key", LogicalType::VARCHAR},
                                            {"value", LogicalType::VARCHAR}}),
                       headers));
  }
}

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
  auto result_data = FlatVector::GetData<bool>(result);

  UnifiedVectorFormat payload_data;
  payload_vector.ToUnifiedFormat(args.size(), payload_data);

  auto payloads = (string_t *)payload_data.data;

  for (idx_t i = 0; i < args.size(); i++) {
    idx_t payload_idx = payload_data.sel->get_index(i);

    if (!payload_data.validity.RowIsValid(payload_idx)) {
      result_data[i] = false;
      continue;
    }

    const string_t &payload = payloads[payload_idx];

    if (payload.GetSize() < 16) {
      result_data[i] = false;
      continue;
    }

    std::string start(reinterpret_cast<const char *>(payload.GetDataUnsafe()),
                      std::min(payload.GetSize(), (idx_t)16));
    std::transform(start.begin(), start.end(), start.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    static const char *http_methods[] = {"get ",     "post ",    "head ",
                                         "put ",     "delete ",  "trace ",
                                         "options ", "connect ", "patch "};

    result_data[i] = false;
    for (const auto &method : http_methods) {
      if (start.compare(0, strlen(method), method) == 0) {
        result_data[i] = true;
        break;
      }
    }

    if (!result_data[i] && start.compare(0, 5, "http/") == 0) {
      result_data[i] = true;
    }
  }

  result.SetVectorType(VectorType::FLAT_VECTOR);
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

std::string generate_tcp_session(const struct ip *ip_header,
                                 const struct tcphdr *tcp_header) {
  std::stringstream ss;
  ss << inet_ntoa(ip_header->ip_src) << ":"
#ifdef __GLIBC__
     << ntohs(tcp_header->source)
#else
     << ntohs(tcp_header->th_sport)
#endif
     << " -> " << inet_ntoa(ip_header->ip_dst) << ":"
#ifdef __GLIBC__
     << ntohs(tcp_header->dest);
#else
     << ntohs(tcp_header->th_dport);
#endif
  return ss.str();
}

TransportLayerInfo determineTransportLayer(const struct ip *ip_header,
                                           const u_char *packet,
                                           const struct pcap_pkthdr *header) {
  TransportLayerInfo info;
  info.source_port = 0;
  info.dest_port = 0;
  info.tcp_seq_num = 0;

  // std::cout << "IP Header proto: " << ip_header->ip_p << std::endl;

  switch (ip_header->ip_p) {
  case IPPROTO_TCP: {
		// std::cout << "TCP" << std::endl;
    info.protocols.push_back("TCP");
    struct tcphdr *tcp_header = (struct tcphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
#ifdef __GLIBC__
    info.source_port = ntohs(tcp_header->source);
    info.dest_port = ntohs(tcp_header->dest);
    info.payload = packet + (ip_header->ip_hl << 2) + (tcp_header->doff << 2);
    info.tcp_seq_num = ntohl(tcp_header->seq);

    if (tcp_header->syn)
      info.tcp_flags.push_back("SYN");
    if (tcp_header->ack)
      info.tcp_flags.push_back("ACK");
    if (tcp_header->rst)
      info.tcp_flags.push_back("RST");
    if (tcp_header->fin)
      info.tcp_flags.push_back("FIN");
    if (tcp_header->psh)
      info.tcp_flags.push_back("PSH");
    if (tcp_header->urg)
      info.tcp_flags.push_back("URG");
#else
    info.source_port = ntohs(tcp_header->th_sport);
    info.dest_port = ntohs(tcp_header->th_dport);
    info.payload = packet + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2);
    info.tcp_seq_num = ntohl(tcp_header->th_seq);

    if (tcp_header->th_flags & TH_SYN)
      info.tcp_flags.push_back("SYN");
    if (tcp_header->th_flags & TH_ACK)
      info.tcp_flags.push_back("ACK");
    if (tcp_header->th_flags & TH_RST)
      info.tcp_flags.push_back("RST");
    if (tcp_header->th_flags & TH_FIN)
      info.tcp_flags.push_back("FIN");
    if (tcp_header->th_flags & TH_PUSH)
      info.tcp_flags.push_back("PSH");
    if (tcp_header->th_flags & TH_URG)
      info.tcp_flags.push_back("URG");
#endif
    info.tcp_session = generate_tcp_session(ip_header, tcp_header);
    if (info.payload >= packet && info.payload < packet + header->len) {
			info.payload_length = header->len - (info.payload - packet);
		} else {
			// Handle error: payload pointer is out of bounds
			info.payload_length = 0;
			// You might want to set an error flag or log this issue
		}
    break;
  }
  case IPPROTO_UDP: {
    info.protocols.push_back("UDP");
    struct udphdr *udp_header =
        (struct udphdr *)((char *)ip_header + (ip_header->ip_hl << 2));
#ifdef __GLIBC__
    info.source_port = ntohs(udp_header->source);
    info.dest_port = ntohs(udp_header->dest);
#else
    info.source_port = ntohs(udp_header->uh_sport);
    info.dest_port = ntohs(udp_header->uh_dport);
#endif
    info.payload = packet+ (ip_header->ip_hl << 2) + sizeof(struct udphdr);
    info.payload_length = header->len - (info.payload - packet);
    break;
  }
  case IPPROTO_ICMP:
    info.protocols.push_back("ICMP");
    info.payload =
        packet + (ip_header->ip_hl << 2);
    info.payload_length = header->len - (info.payload - packet);
    break;
  default:
    info.protocols.push_back("Unknown");
    info.payload = packet + (ip_header->ip_hl << 2);
    info.payload_length = header->len - (info.payload - packet);
  }

  return info;
}

static ICMPInfo extract_icmp_info(const uint8_t *icmp_packet,
                                  size_t packet_len) {
  if (packet_len < 8) { // Minimum ICMP header size
    return {0, 0, "Invalid", "Packet too short", ""};
  }

  ICMPInfo info;
  info.type = icmp_packet[0];
  info.code = icmp_packet[1];

  auto get_uint16 = [](const uint8_t *data) {
    return (uint16_t)((data[0] << 8) | data[1]);
  };

  switch (info.type) {
  case ICMP_ECHOREPLY:
    info.type_name = "Echo Reply";
    info.additional_info =
        "ID: " + std::to_string(get_uint16(icmp_packet + 4)) +
        ", Sequence: " + std::to_string(get_uint16(icmp_packet + 6));
    if (packet_len > 8) {
      size_t message_len =
          std::min(packet_len - 8, (size_t)32); // Limit to 32 bytes
      info.message = bytes_to_hex(icmp_packet + 8, message_len);
    }
    break;
  case ICMP_DEST_UNREACH:
    info.type_name = "Destination Unreachable";
    switch (info.code) {
    case 0:
      info.additional_info = "Network Unreachable";
      break;
    case 1:
      info.additional_info = "Host Unreachable";
      break;
    case 2:
      info.additional_info = "Protocol Unreachable";
      break;
    case 3:
      info.additional_info = "Port Unreachable";
      break;
    default:
      info.additional_info = "Code: " + std::to_string(info.code);
    }
    break;
  case ICMP_SOURCE_QUENCH:
    info.type_name = "Source Quench";
    info.additional_info = "Request to slow down";
    break;
  case ICMP_REDIRECT:
    info.type_name = "Redirect";
    if (packet_len >= 12) {
      char ip_str[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, icmp_packet + 4, ip_str, INET_ADDRSTRLEN);
      info.additional_info = "Redirect to: " + std::string(ip_str);
    } else {
      info.additional_info = "Incomplete redirect information";
    }
    break;
  case ICMP_ECHO:
    info.type_name = "Echo Request";
    info.additional_info =
        "ID: " + std::to_string(get_uint16(icmp_packet + 4)) +
        ", Sequence: " + std::to_string(get_uint16(icmp_packet + 6));
    if (packet_len > 8) {
      size_t message_len =
          std::min(packet_len - 8, (size_t)32); // Limit to 32 bytes
      info.message = bytes_to_hex(icmp_packet + 8, message_len);
    }
    break;
  case ICMP_TIME_EXCEEDED:
    info.type_name = "Time Exceeded";
    info.additional_info =
        (info.code == 0) ? "TTL exceeded" : "Fragment reassembly time exceeded";
    break;
  default:
    info.type_name = "Other";
    info.additional_info = "Type: " + std::to_string(info.type) + ", Code: " + std::to_string(info.code);
  }

  return info;
}

static void ExtractICMPTypeFunction(DataChunk &args, ExpressionState &state,
                                    Vector &result) {
  auto &payload_vector = args.data[0];

  UnifiedVectorFormat payload_data;
  payload_vector.ToUnifiedFormat(args.size(), payload_data);

  auto payloads = (string_t *)payload_data.data;

  // Prepare the struct type for the result
  child_list_t<LogicalType> struct_children = {
      {"type", LogicalType::UTINYINT},
      {"code", LogicalType::UTINYINT},
      {"type_name", LogicalType::VARCHAR},
      {"additional_info", LogicalType::VARCHAR},
      {"message", LogicalType::VARCHAR}};
  auto struct_type = LogicalType::STRUCT(struct_children);

  for (idx_t i = 0; i < args.size(); i++) {
    idx_t payload_idx = payload_data.sel->get_index(i);

    if (!payload_data.validity.RowIsValid(payload_idx)) {
      result.SetValue(i, Value());
      continue;
    }

    const string_t &payload_str = payloads[payload_idx];
    const uint8_t *payload =
        reinterpret_cast<const uint8_t *>(payload_str.GetDataUnsafe());
    size_t payload_len = payload_str.GetSize();

    ICMPInfo icmp_info = extract_icmp_info(payload, payload_len);

    // Create a struct value with the ICMP information
    child_list_t<Value> struct_values;
    struct_values.push_back(make_pair("type", Value::UTINYINT(icmp_info.type)));
    struct_values.push_back(make_pair("code", Value::UTINYINT(icmp_info.code)));
    struct_values.push_back(make_pair("type_name", Value(icmp_info.type_name)));
    struct_values.push_back(
        make_pair("additional_info", Value(icmp_info.additional_info)));
    struct_values.push_back(make_pair("message", Value(icmp_info.message)));

    result.SetValue(i, Value::STRUCT(struct_values));
  }
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
  Vector &tcp_flags_vector = output.data[11];
  Vector &tcp_seq_num_vector = output.data[12];

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

		int linktype = pcap_datalink(pcap_data.handle);

    struct pcap_pkthdr *header;
    const u_char *packet;
    int result = pcap_next_ex(pcap_data.handle, &header, &packet);

    if (result == -2) { // End of file, close current file and move to next
      pcap_close(pcap_data.handle);
      pcap_data.handle = nullptr;
      continue;
    } else if (result == -1) {
      throw std::runtime_error(pcap_geterr(pcap_data.handle));
    } else if (result == 0) { // Timeout, continue
      continue;
    }

    double epoch_seconds = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;
    timestamp_vector.SetValue(
        index, Value::TIMESTAMP(Timestamp::FromEpochSeconds(epoch_seconds)));

    vector<string> protocols;
		const u_char *ip_packet;

		// std::cout << "Linktype: " << linktype << std::endl;

    if (linktype == DLT_EN10MB) { // Parse Ethernet header
			protocols.push_back("Ethernet");
			struct ether_header *eth_header = (struct ether_header *)packet;
			source_mac_vector.SetValue(index, Value(mac_to_string(eth_header->ether_shost)));
			dest_mac_vector.SetValue(index, Value(mac_to_string(eth_header->ether_dhost)));
			ip_packet = packet + sizeof(struct ether_header);
		} else if (linktype == DLT_RAW || linktype == DLT_IPV4 || linktype == DLT_RAW1 || linktype == DLT_LOOP) {
      source_mac_vector.SetValue(index, Value()); // NULL for Raw IP
      dest_mac_vector.SetValue(index, Value());   // NULL for Raw IP
			ip_packet = packet;
		} else {
			continue;
		}

		// std::cout << "past ether" << std::endl;

    struct ip *ip_header = (struct ip *)(ip_packet);

		// std::cout << "ipv4: " << ip_header->ip_v << std::endl;

    protocols.push_back("IP");

    TransportLayerInfo tl_info =
        determineTransportLayer(ip_header, packet, header);

		// std::cout << "past tl_info" << std::endl;

    protocols.insert(protocols.end(), tl_info.protocols.begin(), tl_info.protocols.end());

    source_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_src)));
    dest_ip_vector.SetValue(index, Value(inet_ntoa(ip_header->ip_dst)));
    source_port_vector.SetValue(index, Value::INTEGER(tl_info.source_port));
    dest_port_vector.SetValue(index, Value::INTEGER(tl_info.dest_port));
    length_vector.SetValue(index, Value::INTEGER(tl_info.payload_length));
    tcp_session_vector.SetValue(index, tl_info.tcp_session.empty() ? Value() : Value(tl_info.tcp_session));

		// std::cout << "past tcp_session_vector" << std::endl;

    // std::cout << "payload length: " << tl_info.payload_length << std::endl;

    // Set the payload as a BLOB
    payload_vector.SetValue(
        index, Value::BLOB(tl_info.payload, tl_info.payload_length));

    // std::cout << "past blob" << std::endl;

    // Set TCP flags
    if (!tl_info.tcp_flags.empty()) {
      vector<Value> flag_values;
      for (const auto &flag : tl_info.tcp_flags) {
        flag_values.push_back(Value(flag));
      }
      tcp_flags_vector.SetValue(index, Value::LIST(LogicalType::VARCHAR, flag_values));
    } else {
      tcp_flags_vector.SetValue(index, Value()); // NULL for non-TCP packets
    }

    // std::cout << "past tcp_flags_vector" << std::endl;

    // Set TCP sequence number
    if (tl_info.protocols.back() == "TCP") {
      tcp_seq_num_vector.SetValue(index, Value::UINTEGER(tl_info.tcp_seq_num));
    } else {
      tcp_seq_num_vector.SetValue(index, Value()); // NULL for non-TCP packets
    }

		// std::cout << "past tcp_seq_num_vector" << std::endl;

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
      LogicalType::BLOB,      LogicalType::LIST(LogicalType::VARCHAR),
      LogicalType::UINTEGER};

  names = {"timestamp", "source_ip",   "dest_ip",    "source_port", "dest_port",
           "length",    "tcp_session", "source_mac", "dest_mac",    "protocols",
           "payload",   "tcp_flags",   "tcp_seq_num"};

  return unique_ptr<FunctionData>(result.release());
}

static void LoadInternal(DatabaseInstance &instance) {
  TableFunction pcap_reader("read_pcap", {LogicalType::ANY}, PCAPReaderFunction,
                            PCAPReaderBind);
  ExtensionUtil::RegisterFunction(instance, pcap_reader);

  ScalarFunction is_http_func("is_http", {LogicalType::BLOB},
                              LogicalType::BOOLEAN, IsHTTPFunction);
  ExtensionUtil::RegisterFunction(instance, is_http_func);

  ScalarFunction extract_http_headers_func(
      "extract_http_request_headers", {LogicalType::BLOB},
      LogicalType::LIST(LogicalType::STRUCT(
          {{"key", LogicalType::VARCHAR}, {"value", LogicalType::VARCHAR}})),
      ExtractHTTPRequestHeadersFunction);
  ExtensionUtil::RegisterFunction(instance, extract_http_headers_func);

  ScalarFunction extract_icmp_type_func(
      "extract_icmp_type", {LogicalType::BLOB},
      LogicalType::STRUCT({{"type", LogicalType::UTINYINT},
                           {"code", LogicalType::UTINYINT},
                           {"type_name", LogicalType::VARCHAR},
                           {"additional_info", LogicalType::VARCHAR},
                           {"message", LogicalType::VARCHAR}}),
      ExtractICMPTypeFunction);
  ExtensionUtil::RegisterFunction(instance, extract_icmp_type_func);
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
