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

using INET_TYPE = StructTypeTernary<uint8_t, uhugeint_t, uint16_t>;

bool INetFunctions::CastVarcharToINET(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	auto constant = source.GetVectorType() == VectorType::CONSTANT_VECTOR;

	UnifiedVectorFormat vdata;
	source.ToUnifiedFormat(count, vdata);

	auto &entries = StructVector::GetEntries(result);
	auto ip_type = FlatVector::GetData<uint8_t>(*entries[0]);
	auto address_data = FlatVector::GetData<uhugeint_t>(*entries[1]);
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
		address_data[i] = inet.address;
		mask_data[i] = inet.mask;
	}
	if (constant) {
		result.SetVectorType(VectorType::CONSTANT_VECTOR);
	}
	return success;
}

bool INetFunctions::CastINETToVarchar(Vector &source, Vector &result, idx_t count, CastParameters &parameters) {
	GenericExecutor::ExecuteUnary<INET_TYPE, PrimitiveType<string_t>>(source, result, count, [&](INET_TYPE input) {
		IPAddress inet(IPAddressType(input.a_val), input.b_val, input.c_val);
		auto str = inet.ToString();
		return StringVector::AddString(result, str);
	});
	return true;
}

void INetFunctions::Host(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteUnary<INET_TYPE, PrimitiveType<string_t>>(
	    args.data[0], result, args.size(), [&](INET_TYPE input) {
			auto inetType = IPAddressType(input.a_val);
			auto mask = inetType == IPAddressType::IP_ADDRESS_V4 ? IPAddress::IPV4_DEFAULT_MASK : IPAddress::IPV6_DEFAULT_MASK;
		    IPAddress inet(inetType, input.b_val, mask);
		    auto str = inet.ToString();
		    return StringVector::AddString(result, str);
	    });
}

static INET_TYPE add_implementation(INET_TYPE ip, hugeint_t val) {
	INET_TYPE result;
	result.a_val = ip.a_val;
	result.c_val = ip.c_val;

	if (val >= 0) {
		result.b_val = AddOperatorOverflowCheck::Operation<uhugeint_t, uhugeint_t, uhugeint_t>(
			ip.b_val, NumericCast::Operation<hugeint_t, uhugeint_t>(val)
		);
	} else {
		result.b_val = SubtractOperatorOverflowCheck::Operation<uhugeint_t, uhugeint_t, uhugeint_t>(
			ip.b_val, NumericCast::Operation<hugeint_t, uhugeint_t>(-val)
		);
	}
	
	return result;
}

void INetFunctions::Subtract(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_TYPE, PrimitiveType<hugeint_t>, INET_TYPE>(
	    args.data[0], args.data[1], result, args.size(), [&](INET_TYPE ip, PrimitiveType<hugeint_t> val) {
			return add_implementation(ip, -val.val);
	    });
}

void INetFunctions::Add(DataChunk &args, ExpressionState &state, Vector &result) {
	GenericExecutor::ExecuteBinary<INET_TYPE, PrimitiveType<hugeint_t>, INET_TYPE>(
	    args.data[0], args.data[1], result, args.size(), [&](INET_TYPE ip, PrimitiveType<hugeint_t> val) {
			return add_implementation(ip, val.val);
	    });
}

} // namespace duckdb
