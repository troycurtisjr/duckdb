#include "ipaddress.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/types/cast_helpers.hpp"
#include "duckdb/common/string_util.hpp"

#include <sstream>
#include <ios>

namespace duckdb {

constexpr static const int32_t HEX_BITSIZE = 4;
constexpr static const int32_t MAX_QUIBBLE_DIGITS = 4;

IPAddress::IPAddress() : type(IPAddressType::IP_ADDRESS_INVALID) {
}

IPAddress::IPAddress(IPAddressType type, hugeint_t address, uint16_t mask) : type(type), address(address), mask(mask) {
}

IPAddress IPAddress::FromIPv4(int32_t address, uint16_t mask) {
	return IPAddress(IPAddressType::IP_ADDRESS_V4, address, mask);
}
IPAddress IPAddress::FromIPv6(hugeint_t address, uint16_t mask) {
	return IPAddress(IPAddressType::IP_ADDRESS_V6, address, mask);
}

static bool IPAddressError(string_t input, string *error_message, string error) {
	string e = "Failed to convert string \"" + input.GetString() + "\" to inet: " + error;
	HandleCastError::AssignError(e, error_message);
	return false;
}

static bool TryParseIPv4(string_t input, IPAddress &result, string *error_message) {
	auto data = input.GetData();
	auto size = input.GetSize();
	idx_t c = 0;
	idx_t number_count = 0;
	uint32_t address = 0;
	result.type = IPAddressType::IP_ADDRESS_V4;
parse_number:
	idx_t start = c;
	while (c < size && data[c] >= '0' && data[c] <= '9') {
		c++;
	}
	if (start == c) {
		return IPAddressError(input, error_message, "Expected a number");
	}
	uint8_t number;
	if (!TryCast::Operation<string_t, uint8_t>(string_t(data + start, c - start), number)) {
		return IPAddressError(input, error_message, "Expected a number between 0 and 255");
	}
	address <<= 8;
	address += number;
	number_count++;
	result.address = address;
	if (number_count == 4) {
		goto parse_mask;
	} else {
		goto parse_dot;
	}
parse_dot:
	if (c == size || data[c] != '.') {
		return IPAddressError(input, error_message, "Expected a dot");
	}
	c++;
	goto parse_number;
parse_mask:
	if (c == size) {
		// no mask, set to default
		result.mask = IPAddress::IPV4_DEFAULT_MASK;
		return true;
	}
	if (data[c] != '/') {
		return IPAddressError(input, error_message, "Expected a slash");
	}
	c++;
	start = c;
	while (c < size && data[c] >= '0' && data[c] <= '9') {
		c++;
	}
	uint8_t mask;
	if (!TryCast::Operation<string_t, uint8_t>(string_t(data + start, c - start), mask)) {
		return IPAddressError(input, error_message, "Expected a number between 0 and 32");
	}
	if (mask > 32) {
		return IPAddressError(input, error_message, "Expected a number between 0 and 32");
	}
	result.mask = mask;
	return true;
}

// A "quibble" is the 16 bit IPv6 value of up to 4 hex digits separated by colons.
static uint16_t parseQuibble(const char *buf, idx_t len) {
	uint16_t result = 0;
	for (idx_t c=0; c < len; ++c) {
		result = (result << HEX_BITSIZE) + StringUtil::GetHexValue(buf[c]);
	}
	return result;
}

static bool TryParseIPv6(string_t input, IPAddress &result, string *error_message) {
	auto data = input.GetData();
	auto size = input.GetSize();
	idx_t c = 0;
	idx_t quibble_count = 0;
	uhugeint_t address = 0;
	result.type = IPAddressType::IP_ADDRESS_V6;
	result.mask = IPAddress::IPV6_DEFAULT_MASK;
	while (c < size && quibble_count < IPAddress::IPV6_NUM_QUIBBLE) {
		// Find and parse the next quibble
		auto start = c;
		while (c < size && StringUtil::CharacterIsHex(data[c])) {
			++c;
		}
		idx_t len = c - start;
		if (len > MAX_QUIBBLE_DIGITS || (c != size && data[c] != ':' && data[c] != '/')) {
			return IPAddressError(input, error_message, "Expected 4 or fewer hex digits");
		}
		address = (address << IPAddress::IPV6_QUIBBLE_BITS) + parseQuibble(&data[start], len);
		++quibble_count;

		// Parse the mask if specified
		if (data[c] == '/') {
			if (quibble_count != IPAddress::IPV6_NUM_QUIBBLE) {
				return IPAddressError(input, error_message, "Expected 8 sets of 4 hex digits.");
			}
			start = ++c;
			while (c < size && StringUtil::CharacterIsDigit(data[c])) {
				++c;
			}
			uint8_t mask;
			if (!TryCast::Operation<string_t, uint8_t>(string_t(&data[start], c - start), mask)) {
				return IPAddressError(input, error_message, "Expected a number between 0 and 128");
			}
			if (mask > IPAddress::IPV6_DEFAULT_MASK) {
				return IPAddressError(input, error_message, "Expected a number between 0 and 128");
			}
			result.address = address;
			result.mask = mask;
			return true;		
		}
		++c;
	}
	if (quibble_count != IPAddress::IPV6_NUM_QUIBBLE) {
		return IPAddressError(input, error_message, "Expected 8 sets of 4 hex digits.");
	}
	if (c < size) {
		return IPAddressError(input, error_message, "Unexpected extra characters");
	}
	result.address = address;
	return true;
}

bool IPAddress::TryParse(string_t input, IPAddress &result, string *error_message) {
	auto data = input.GetData();
	auto size = input.GetSize();
	// Start by detecting whether the string is an IPv4 or IPv6 address, or neither.
	idx_t c = 0;
	while (c < size && StringUtil::CharacterIsHex(data[c])) {
		c++;
	}
	if (c == 0) {
		return IPAddressError(input, error_message, "Expected a number");
	}
	if (c == size) {
		return IPAddressError(input, error_message, "Expected an IP address");
	}
	if (data[c] == '.') {
		return TryParseIPv4(input, result, error_message);
	}
	if (data[c] == ':') {
		return TryParseIPv6(input, result, error_message);
	}

	return IPAddressError(input, error_message, "Expected an IP address");
}

static string ToStringIPv4(const IPAddress &addr) {
	string result;
	for (idx_t i = 0; i < 4; i++) {
		if (i > 0) {
			result += ".";
		}
		uint8_t byte = Hugeint::Cast<uint8_t>((addr.address >> (3 - i) * 8) & 0xFF);
		auto str = to_string(byte);
		result += str;
	}
	if (addr.mask != IPAddress::IPV4_DEFAULT_MASK) {
		result += "/" + to_string(addr.mask);
	}
	return result;
}

static string ToStringIPv6(const IPAddress &addr) {
	std::ostringstream result;
	result << std::hex;
	for (idx_t i=IPAddress::IPV6_NUM_QUIBBLE; i > 0; --i) {
		if (result.tellp() > 0) {
			result << ":";
		}
		int bitshift = (i - 1) * IPAddress::IPV6_QUIBBLE_BITS;
		uint16_t quibble = Hugeint::Cast<uint16_t>((addr.address >> bitshift) & 0xFFFF);
		result << quibble;
	}
	if (addr.mask != IPAddress::IPV6_DEFAULT_MASK) {
		result << "/" << std::dec << addr.mask;
	}
	return result.str();
}

string IPAddress::ToString() const {
	if (type == IPAddressType::IP_ADDRESS_V4) {
		return ToStringIPv4(*this);
	}

	if (type == IPAddressType::IP_ADDRESS_V6) {
		return ToStringIPv6(*this);
	}

	return "Invalid IPAddress";
}

IPAddress IPAddress::FromString(string_t input) {
	IPAddress result;
	string error_message;
	if (!TryParse(input, result, &error_message)) {
		throw ConversionException(error_message);
	}
	return result;
}

} // namespace duckdb
