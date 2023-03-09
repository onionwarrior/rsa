#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/integer.hpp>
#include <boost/multiprecision/cpp_int/serialize.hpp>

#include <boost/integer/mod_inverse.hpp>
#include <boost/math/special_functions/pow.hpp>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>

#include <filesystem>
#include <format>
#include <streambuf>
#include <iostream>
#include <fstream>
#include <concepts>
#include <span>
#include <variant>

namespace mp = boost::multiprecision;
namespace io = boost::iostreams;
namespace ba = boost::archive;
namespace fs = std::filesystem;

using u256 = mp::checked_uint256_t;
using u512 = mp::checked_uint512_t;
using i512 = mp::checked_int512_t;

template <typename T>
requires std::is_unsigned_v<T>
auto make_signed_span(std::span<T> s)
{
    using signed_t  = std::make_signed_t<T>;
    return std::span<signed_t>{reinterpret_cast<signed_t*>(s.data()), s.size()});
}

template <typename Bytes,typename BigInt>
Bytes to_bytes(const BigInt& i) {

    std::vector<char> chars;
    io::stream_buffer<io::back_insert_device<std::vector<char>>> bb(chars);
    ba::binary_oarchive oa{bb, ba::no_header | ba::no_tracking | ba::no_codecvt};
    oa << i;
    return { chars.begin(), chars.end() };
}

template <typename BigInt, typename Bytes>
BigInt to_bigint(const Bytes & v) {

    BigInt i{};
    std::vector<char> chars{ v.begin(), v.end() };
    io::stream_buffer<io::array_source> bb{chars.data(), chars.size()};
    ba::binary_iarchive ia {bb, ba::no_header | ba::no_tracking | ba::no_codecvt};
    ia >> i;
    return i;
}


template <typename BigInt>
auto rsa_derive(const BigInt& e)
{

}
template <typename BigInt>
auto coprime(const BigInt& a, const BigInt& b) -> bool
{
    return mp::gcd(a, b) == 1;
}

template <typename BigInt>
auto bit_length(const BigInt& v) -> std::size_t
{
    return mp::msb(v) + 1;
}

namespace rsa
{
    struct pub
    {
        u512 exp;
        u512 mod;
    };
    struct priv
    {
        u512 d;
        u512 mod;
    };
    auto encrypt(const pub&p,std::span<std::uint8_t> plain_bytes) -> u512
    {
        if (plain_bytes.size() > 512)
        {
            throw std::logic_error{ "Plaintext does not fit in 512 bits" };

        }
        auto&&[exp,mod] = p;
        const auto as_integer = to_bigint<u512>(make_signed_span(plain_bytes));
        return mp::powm(as_integer, exp, mod);
    }
    auto decrypt(const priv& p, std::span<std::uint8_t> cypher_bytes) -> u512
    {
        if (cypher_bytes.size() > 512)
        {
            throw std::logic_error{ "Cyphertext does not fit in 512 bits" };

        }
        auto&& [d, mod] = p;
        const auto as_integer = to_bigint<u512>(make_signed_span(cypher_bytes));
        return mp::powm(as_integer, d, mod);
    }
}
namespace asn
{
    //closest to 1008 required bytes, soo
    using len_holder_t = mp::checked_uint1024_t;
    using len_bytes_t = std::array<std::uint8_t, 128>;
    using len_encoded_t = std::pair<std::size_t, len_bytes_t>;
    namespace{
        auto encode_wrapper(const len_holder_t&len,const std::size_t size) -> std::array<std::uint8_t,128>
        {
            len_bytes_t bytes{};
            const auto vec = to_bytes<std::vector<std::uint8_t>>(len);
            if (std::size(vec) != size)
            {
                throw std::logic_error{"Serialized value is not the same size as requested write size"};
            }
            std::copy_n(std::begin(vec),size,std::begin(bytes));
            return bytes;
        }
    }
    auto encode_len(const len_holder_t& len) -> len_encoded_t
    {
        if (len < 0x80)
        {
            return {1,{static_cast<std::uint8_t>(len)}};
        }
        const auto length_bits = bit_length(len);
        const auto length_bytes = length_bits / 8 + (length_bits  % 8 != 0 );
        return { length_bytes,encode_wrapper(len,length_bytes)};
    }
    auto decode_len(std::span<std::uint8_t> as_bytes) ->  len_holder_t
    {
        const auto msb = as_bytes.front();
        if (msb & 0x80)
        {
            return msb;
        }
        return to_bigint<len_holder_t>(make_signed_span(as_bytes));
    }
    auto encode_rsa(rsa::pub&pub) -> std::vector<std::uint8_t>
    {
    
    }
}
namespace io
{
    namespace
    {

    }
}
//default to bytes
template <typename TElem=std::uint8_t>
auto read_bytes(const fs::path& p) -> std::optional<std::vector<TElem>>
{
    using fstream = std::basic_ifstream<TElem>;
    if(!fs::exists(p))
    { 
        std::cerr << std::format("Failed to open {}\n",p.string());
        return {};
    }
    auto file_stream = fstream{p,std::ios::binary};
    return std::vector( std::istreambuf_iterator<TElem>{file_stream},std::istreambuf_iterator<TElem>{});
}

auto main(int argc,char**argv) -> int
{
    u512 n;
    u512 phi_n;
    const auto file = read_bytes("file.txt").value_or(std::vector<std::uint8_t>{});
    const auto p = u256{"57896044618658097711785492504343953926634992332820282019728792003956564820109"};
    const auto q = u256{"57896044618658097711785492504343953926634992332820282019728792003956564820063"};

    mp::multiply(n,p,q);
    mp::multiply(phi_n,p-1,q-1);


    const auto e = u512{"1234567"};
    if (!coprime(e, phi_n))
    {
        std::cout << "Bad pubkey\n";
        return -1;
    }
    const auto d = u512{boost::integer::mod_inverse(i512{e},i512{phi_n})};


    std::cout << bit_length(u256{1});
    return 0;
}