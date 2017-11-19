LotsOfHashes plugin version 1.4 for Total Commander by Gamrasni Ariel

A simple 32/64-bit content-plugin that calculates hash values for any file.

The following 47 hash algorithms are currently supported:
 (CRC32), (CRC32b), (eD2k/eMule), (GOST), (HAVAL 128,3),
 (HAVAL 128,4), (HAVAL 128,5), (HAVAL 160,3), (HAVAL 160,4), (HAVAL 160,5),
 (HAVAL 192,3), (HAVAL 192,4), (HAVAL 192,5), (HAVAL 224,3), (HAVAL 224,4),
 (HAVAL 224,5), (HAVAL 256,3), (HAVAL 256,4), (HAVAL 256,5), (MD4),
 (MD5), (Murmur 32), (Murmur 128), (RIPEMD 128), (RIPEMD 160),
 (RIPEMD 256), (RIPEMD 320), (Salsa10), (Salsa20), (SHA1 160),
 (SHA2 224), (SHA2 256), (SHA2 384), (SHA2 512), (SHA3 224),
 (SHA3 256), (SHA3 384), (SHA3 512), (Snefru 128), (Snefru 256),
 (Tiger 128,3), (Tiger 128,4), (Tiger 160,3), (Tiger 160,4), (Tiger 192,3),
 (Tiger 192,4), (Whirlpool)

Notes:
 - The modification of field names in version 1.1 may impact user configured custom columns.
 - LotsOfHashes.ini configuration file is created after the first use in the same location as the LotsOfHashes.wdx file.
 - The in-memory cache has 2 configurable parameters in LotsOfHashes.ini:
    1. FileSizeThreshold - A hash value will be cached only if the file size (in bytes) is bigger than this value.
    2. MaxCacheElements - Maximum number of hash values that will be cached before oldest values are overwritten.

Changelog:
  2013-12-01: v1.4
   * ADDED     SHA3 (Keccak) hash algorithm in now supported (224-bit, 256-bit, 384-bit and 512-bit).
   * CHANGED   Shorted field name format of compare content (removed the "codes" string).

  2013-01-09: v1.3
   * CHANGED   A better way to handle errors after CreateFile.
   * CHANGED   Close the file handle after CreateFileMapping; it's no longer needed.
   * ADDED     MurmurHash3 hash algorithm is now supported (32-bit and 128-bit).
   * ADDED     Salsa10 and Salsa20 hash algorithms are now supported.
   * CHANGED   Code refactoring: Rename methods of hash classes (Crc32,EDonkey2k,Gost,Haval,Md4,Md5).

  2012-10-02: v1.2
   * FIXED    Minor bug in the way memory is freed in the cache mechanism.
   * FIXED    Exception when file is empty. Check for zero file size before accessing cache.
   * CHANGED  Remove dependency in Windows cryptography (Wincrypt). MD5 and SHA1/SHA2 algorithms re-implemented.
   * ADDED    SHA2 224 hash algorithm is now supported.
   * CHANGED  Current CRC32 algorithm was renamed to CRC32b (algorithm used by PKZIP).
   * ADDED    CRC32 hash algorithm (used by ethernet and wdHash) is now supported.
   
  2012-09-23: v1.1
   * FIXED    Missing ANSI functions added in addition to existing Unicode functions.
   * CHANGED  32bit file extension renamed from .uwdx to .wdx. LotsOfHashes.uwdx is obsolete and can safely be deleted.
   * ADDED    MD4 hash algorithm is now supported.
   * ADDED    eD2k/eMule hash algorithm is now supported.
   * CHANGED  Field names slightly modified for better categorization. Format: "hash_name [digest_size],[passes]".
   * ADDED    Two new field units/choices. 'Delimited uppercase' and 'Delimited lowercase'.
   * ADDED    In-memory cache for performance (avoid recalculation of large unchanged files).
   * ADDED    Configuration file (LotsOfHashes.ini) for cache parameters. See Notes.
   * FIXED    Doesn't ignore directories.
  
  2012-08-29: v1.0
   * Initial release.