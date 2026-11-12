#include "raw/types.hpp"

#include <iomanip>
#include <iostream>

#include "common/budget.hpp"

static void print_hex_bytes(std::ostream& os, const std::uint8_t* data, std::size_t count) {
  os << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < count; ++i) {
    os << std::setw(2) << static_cast<int>(data[i]);
  }
  os << std::dec;
}

namespace dexsplit::raw {

void Header::print(std::ostream& os) {
  os << "DEX Header:\n";

  os << "  magic               : ";
  print_hex_bytes(os, this->magic, 8);
  os << "\n";

  os << "  checksum            : 0x" << std::hex << std::setw(8) << std::setfill('0') << this->checksum << std::dec
     << "\n";

  os << "  signature           : ";
  print_hex_bytes(os, this->signature, 20);
  os << "\n";

  os << "  file_size           : " << this->file_size << "\n";
  os << "  header_size         : " << this->header_size << "\n";
  os << "  endian_tag          : 0x" << std::hex << this->endian_tag << std::dec << "\n";

  os << "  link_size           : " << this->link_size << "\n";
  os << "  link_off            : " << this->link_off << "\n";
  os << "  map_off             : " << this->map_off << "\n";

  os << "  string_ids_size     : " << this->string_ids_size << "\n";
  os << "  string_ids_off      : " << this->string_ids_off << "\n";

  os << "  type_ids_size       : " << this->type_ids_size << "\n";
  os << "  type_ids_off        : " << this->type_ids_off << "\n";

  os << "  proto_ids_size      : " << this->proto_ids_size << "\n";
  os << "  proto_ids_off       : " << this->proto_ids_off << "\n";

  os << "  field_ids_size      : " << this->field_ids_size << "\n";
  os << "  field_ids_off       : " << this->field_ids_off << "\n";

  os << "  method_ids_size     : " << this->method_ids_size << "\n";
  os << "  method_ids_off      : " << this->method_ids_off << "\n";

  os << "  class_defs_size     : " << this->class_defs_size << "\n";
  os << "  class_defs_off      : " << this->class_defs_off << "\n";

  os << "  data_size           : " << this->data_size << "\n";
  os << "  data_off            : " << this->data_off << "\n";
}

}  // namespace dexsplit::raw
