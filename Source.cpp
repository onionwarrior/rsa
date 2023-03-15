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
    return std::span<signed_t>{reinterpret_cast<signed_t*>(s.data()), s.size()};
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
namespace utils
{
    template <typename T>
    using helper = std::remove_cvref_t<typename T::value_type>;

    template <typename Destination,typename ... Ts>
    requires std::conjunction_v<std::is_same<helper<Ts>, std::uint8_t> ... >
        && std::is_same_v<std::uint8_t,typename Destination::value_type>

    auto dump_to(const Ts &...seqs)->Destination
    {
        std::size_t size = 0;
        auto add = [&size](auto&&val){ size += std::size(val); };
        std::apply(
            [&size,&add](auto &&...t) { (add(t),...); },
            std::make_tuple(seqs...)
        );
        auto dst = Destination(size);
        std::size_t push_index = 0;
        auto push_elem = [&dst,&push_index](auto&&elem){ 
            std::copy(std::begin(elem),std::end(elem),std::next(std::begin(dst),push_index));
            push_index+=std::size(elem);
        };
        std::apply(
            [&dst, &push_elem](auto &&...t) { (push_elem(t), ...); },
            std::make_tuple(seqs...)
        );
        return dst;
    }
}
namespace rsa
{
    const auto p = u256{ "57896044618658097711785492504343953926634992332820282019728792003956564820109" };
    const auto q = u256{ "57896044618658097711785492504343953926634992332820282019728792003956564820063" };
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
    enum tag : std::uint8_t
    {
        sequence = 0x30
    };
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
        using bytes =std::vector<std::uint8_t>;
    }
    template <typename BigInt>
    auto byte_size(const BigInt& val) -> std::size_t 
    {
        const auto length_bits = bit_length(val);
        const auto length_bytes = length_bits / 8 + (length_bits % 8 != 0);
        return length_bytes;
    }
    auto encode_len(const len_holder_t& len) -> len_encoded_t
    {
        if (len < 0x80)
        {
            return {1,{static_cast<std::uint8_t>(len)}};
        }
        const auto length_bytes = byte_size(len);
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
    /*seq
    * Return a SEQUENCE 
    */
    auto encode_rsa(rsa::pub&pub) -> bytes
    {
        auto&&[exp,mod] = pub;
        auto&&[exp_len,exp_len_as_bytes] = encode_len(exp);
        auto&&[mod_len,mod_len_as_bytes] = encode_len(mod);
        //Size of everything except SEQUENCE len and tag
        const auto inner_size = sizeof(tag) * 2 + byte_size(exp) + byte_size(mod) + exp_len + mod_len;
        auto&&[encoded_seq_len,encoded_seq_len_as_bytes] = encode_len({ inner_size});
        const auto required_size = sizeof(tag) + inner_size + encoded_seq_len;
        auto encoded = std::vector<std::uint8_t>(required_size);
        const auto exp_as_bytes = to_bytes<bytes>(exp);
        const auto mod_as_bytes = to_bytes<bytes>(mod);
        return utils::dump_to<bytes>(
            bytes{0x30}, encoded_seq_len_as_bytes,
            bytes{0x02},mod_len_as_bytes,mod_as_bytes,
            bytes{0x02}, exp_len_as_bytes, exp_as_bytes
        );
    }
}
namespace file_io
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

    mp::multiply(n,rsa::p,rsa::q);
    mp::multiply(phi_n,rsa::p-1,rsa::q-1);


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