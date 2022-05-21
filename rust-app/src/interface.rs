use ledger_parser_combinators::core_parsers::*;
use ledger_parser_combinators::endianness::*;

// Payload for a public key request
pub type Bip32Key = DArray<Byte, U32<{ Endianness::Little }>, 10>;

// Overly generic transaction type; should describe the actual format of the transaction.
pub type Transaction = DArray<U32<{Endianness::Little}>, Byte, { usize::MAX }>;

