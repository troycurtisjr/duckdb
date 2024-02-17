#include "inet_functions.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/pair.hpp"
#include "duckdb/common/operator/cast_operators.hpp"
#include "duckdb/common/operator/subtract.hpp"
#include "duckdb/common/operator/add.hpp"
#include "duckdb/common/operator/numeric_cast.hpp"
#include "duckdb/common/types/cast_helpers.hpp"
#include "duckdb/common/vector_operations/generic_executor.hpp"

namespace duckdb {

// The address field is better represented as a uhugeint_t, but the original implementation
// used hugeint_t so maintain backward-compatibility. Operations on the address values will
// use the unsigned variant, so use the functions below to convert to/from the compatible
// representation.
using INET_TYPE = StructTypeTernary<uint8_t, hugeint_t, uint16_t>;

static uhugeint_t from_compat_addr(hugeint_t compat_addr, IPAddressType addr_type) {
	uhugeint_t retval = static_cast<uhugeint_t>(compat_addr);
	// Only flip the bit for order on IPv6 addresses. It can never be set in IPv4
	if (addr_type == IPAddressType::IP_ADDRESS_V6) {
		// Flip the top bit so that the ordering of hugeint works as expected, and
		// not as if was actually a signed value.
		return retval ^ (uhugeint_t(1) << 127);
	}

	return retval;
}

static hugeint_t to_compat_addr(uhugeint_t new_addr, IPAddressType addr_type) {
	if (addr_type == IPAddressType::IP_ADDRESS_V6) {
		// Flip the top bit back so that the bit values are correct for display and
		// operations.
		return static_cast<hugeint_t>(new_addr ^ (uhugeint_t(1) << 127));
	}
	// Don't need to flip the bit for IPv4
	return static_cast<hugeint_t>(new_addr);
}

bool INetFunctions::CastVarcharToINET(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	auto constant = source.GetVectorType() == VectorType::CONSTANT_VECTOR;

	UnifiedVectorFormat vdata;
	source.ToUnifiedFormat(count, vdata);

	auto &entries = StructVector::GetEntries(result);
	auto ip_type = FlatVector::GetData<uint8_t>(*entries[0]);
	auto address_data = FlatVector::GetData<hugeint_t>(*entries[1]);
	auto mask_data = FlatVector::GetData<uint16_t>(*entries[2]);

	auto input = UnifiedVectorFormat::GetData<string_t>(vdata);
	bool success = true;
	for (idx_t i = 0; i < (constant ? 1 : count); i++) {
		auto idx = vdata.sel->get_index(i);

		if (!vdata.validity.RowIsValid(idx)) {
			FlatVector::SetNull(result, i, true);
			continue;
		}
		IPAddress inet;
		if (!IPAddress::TryParse(input[idx], inet, parameters.error_message)) {
			FlatVector::SetNull(result, i, true);
			success = false;
			continue;
		}
		ip_type[i] = uint8_t(inet.type);
		address_data[i] = to_compat_addr(inet.address, inet.type);
		mask_data[i] = inet.mask;
	}
	if (constant) {
		result.SetVectorType(VectorType::CONSTANT_VECTOR);
	}
	return success;
}

bool INetFunctions::CastINETToVarchar(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	GenericExecutor::ExecuteUnary<INET_TYPE, PrimitiveType<string_t>>(source, result, count, [&](INET_TYPE input) {
		auto addr_type = IPAddressType(input.a_val);
		auto unsigned_addr = from_compat_addr(input.b_val, addr_type);
		IPAddress inet(addr_type, unsigned_addr, input.c_val);
		auto str = inet.ToString();
		return StringVector::AddString(result, str);
	});
	return true;
}

void INetFunctions::Host(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_TYPE, PrimitiveType<string_t>>(
	    args.data[0], result, args.size(), [&](INET_TYPE input) {
		    auto inetType = IPAddressType(input.a_val);
		    auto mask =
		        inetType == IPAddressType::IP_ADDRESS_V4 ? IPAddress::IPV4_DEFAULT_MASK : IPAddress::IPV6_DEFAULT_MASK;
		    auto unsigned_addr = from_compat_addr(input.b_val, inetType);
		    IPAddress inet(inetType, unsigned_addr, mask);
		    auto str = inet.ToString();
		    return StringVector::AddString(result, str);
	    });
}

static INET_TYPE add_implementation(INET_TYPE ip, hugeint_t val) {
	INET_TYPE result;
	auto addr_type = IPAddressType(ip.a_val);
	result.a_val = ip.a_val;
	result.c_val = ip.c_val;

	if (val >= 0) {
		result.b_val = to_compat_addr(
		    AddOperatorOverflowCheck::Operation<uhugeint_t, uhugeint_t, uhugeint_t>(
		        from_compat_addr(ip.b_val, addr_type), NumericCast::Operation<hugeint_t, uhugeint_t>(val)),
		    addr_type);
	} else {
		result.b_val = to_compat_addr(
		    SubtractOperatorOverflowCheck::Operation<uhugeint_t, uhugeint_t, uhugeint_t>(
		        from_compat_addr(ip.b_val, addr_type), NumericCast::Operation<hugeint_t, uhugeint_t>(-val)),
		    addr_type);
	}

	return result;
}

void INetFunctions::Subtract(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_TYPE, PrimitiveType<hugeint_t>, INET_TYPE>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](INET_TYPE ip, PrimitiveType<hugeint_t> val) { return add_implementation(ip, -val.val); });
}

void INetFunctions::Add(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_TYPE, PrimitiveType<hugeint_t>, INET_TYPE>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](INET_TYPE ip, PrimitiveType<hugeint_t> val) { return add_implementation(ip, val.val); });
}

} // namespace duckdb
