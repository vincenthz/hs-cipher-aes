{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.AES
    (
    -- * data types
      Key
    , IV(..)

    -- * creation
    , initKey

    -- * misc
    , genCTR

    -- * encryption
    , encryptECB
    , encryptCBC
    , encryptCTR
    , encryptXTS
    , encryptGCM

    -- * decryption
    , decryptECB
    , decryptCBC
    , decryptCTR
    , decryptXTS
    , decryptGCM
    ) where

-- import Data.ByteString (ByteString)
import Data.Word
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Storable
import Foreign.C.Types
import Foreign.C.String
import Foreign.Marshal.Alloc
import Data.ByteString.Internal
import Data.ByteString.Unsafe
import qualified Data.ByteString as B
import System.IO.Unsafe (unsafePerformIO)

-- | AES Key
newtype Key = Key ByteString

-- | AES IV
newtype IV = IV ByteString

-- | GCM Context
newtype GCM = GCM ByteString

sizeGCM :: Int
sizeGCM = 540

instance Storable GCM where
    sizeOf _    = sizeGCM
    alignment _ = 16
    poke ptr (GCM b) = unsafeUseAsCString b (\cs -> memcpy (castPtr ptr) (castPtr cs) (fromIntegral sizeGCM))
    peek ptr         = create sizeGCM (\bptr -> memcpy bptr (castPtr ptr) (fromIntegral sizeGCM)) >>= return . GCM

keyToPtr :: Key -> (Ptr Key -> IO a) -> IO a
keyToPtr (Key b) f = unsafeUseAsCString b (f . castPtr)

ivToPtr :: IV -> (Ptr IV -> IO a) -> IO a
ivToPtr (IV b) f = unsafeUseAsCString b (f . castPtr)

withKeyAndIV :: Key -> IV -> (Ptr Key -> Ptr IV -> IO a) -> IO a
withKeyAndIV key iv f = keyToPtr key $ \kptr -> ivToPtr iv $ \ivp -> f kptr ivp

withKey2AndIV :: Key -> Key -> IV -> (Ptr Key -> Ptr Key -> Ptr IV -> IO a) -> IO a
withKey2AndIV key1 key2 iv f =
    keyToPtr key1 $ \kptr1 -> keyToPtr key2 $ \kptr2 -> ivToPtr iv $ \ivp -> f kptr1 kptr2 ivp

-- | initialize key
{-# NOINLINE initKey #-}
initKey :: ByteString -> Key
initKey b@(B.length -> len)
    | len == 16 = doInit 10
    | len == 24 = doInit 12
    | len == 32 = doInit 14
    | otherwise = error "wrong key size: need to be 16, 24 or 32 bytes."
      where doInit nbR = unsafePerformIO $ unsafeUseAsCString b (allocAndFill nbR)
            allocAndFill nbR ikey = do
                ptr <- mallocBytes (16+2*2*16*nbR)
                c_aes_init ptr (castPtr ikey) (fromIntegral len)
                fptr <- newForeignPtr c_free_finalizer (castPtr ptr)
                return $ Key $ fromForeignPtr fptr 0 (16+2*2*16*nbR)

-- | encrypt using Electronic Code Book (ECB)
{-# NOINLINE encryptECB #-}
encryptECB :: Key -> ByteString -> ByteString
encryptECB = doECB c_aes_encrypt_ecb

-- | encrypt using Cipher Block Chaining (CBC)
{-# NOINLINE encryptCBC #-}
encryptCBC :: Key -> IV -> ByteString -> ByteString
encryptCBC = doCBC c_aes_encrypt_cbc

-- | generate a counter mode pad. this is generally xor-ed to an input
-- to make the standard counter mode block operations.
--
-- if the length requested is not a multiple of the block cipher size,
-- more data will be returned, so that the returned bytestring is
-- a multiple of the block cipher size.
{-# NOINLINE genCTR #-}
genCTR :: Key        -- ^ Cipher Key.
       -> IV         -- ^ usually a 128 bit integer.
       -> Int        -- ^ length of bytes required.
       -> ByteString
genCTR key iv len = unsafeCreate (nbBlocks * 16) generate
    where
          generate o = withKeyAndIV key iv $ \k i -> c_aes_gen_ctr (castPtr o) k i (fromIntegral nbBlocks)
          (nbBlocks',r) = len `divMod` 16
          nbBlocks = if r == 0 then nbBlocks' else nbBlocks' + 1

-- | encrypt using Counter mode (CTR)
--
-- in CTR mode encryption and decryption is the same operation.
{-# NOINLINE encryptCTR #-}
encryptCTR :: Key -> IV -> ByteString -> ByteString
encryptCTR key iv input = unsafeCreate len doEncrypt
    where doEncrypt o = withKeyAndIV key iv $ \k v -> unsafeUseAsCString input $ \i ->
                            c_aes_encrypt_ctr (castPtr o) k v i (fromIntegral len)
          len = B.length input

-- | encrypt using Galois counter mode (GCM)
-- return the encrypted bytestring and the tag associated
--
-- note: encrypted data is identical to CTR mode in GCM, however
-- a tag is also computed.
encryptGCM :: Key        -- ^ Key
           -> IV         -- ^ initial vector
           -> ByteString -- ^ data to authenticate (AAD)
           -> ByteString -- ^ data to encrypt
           -> (ByteString, ByteString) -- ^ ciphertext and tag
encryptGCM = doGCM gcmAppendEncrypt

-- | encrypt using XTS
--
-- the first key is the normal block encryption key
-- the second key is used for the initial block tweak
{-# NOINLINE encryptXTS #-}
encryptXTS :: (Key,Key) -> IV -> Word32 -> ByteString -> ByteString
encryptXTS = doXTS c_aes_encrypt_xts

-- | decrypt using Electronic Code Book (ECB)
{-# NOINLINE decryptECB #-}
decryptECB :: Key -> ByteString -> ByteString
decryptECB = doECB c_aes_decrypt_ecb

-- | decrypt using Cipher block chaining (CBC)
{-# NOINLINE decryptCBC #-}
decryptCBC :: Key -> IV -> ByteString -> ByteString
decryptCBC = doCBC c_aes_decrypt_cbc

-- | decrypt using Counter mode (CTR).
--
-- in CTR mode encryption and decryption is the same operation.
decryptCTR :: Key -> IV -> ByteString -> ByteString
decryptCTR = encryptCTR

-- | decrypt using XTS
{-# NOINLINE decryptXTS #-}
decryptXTS :: (Key,Key) -> IV -> Word32 -> ByteString -> ByteString
decryptXTS = doXTS c_aes_decrypt_xts

-- | decrypt using Galois Counter Mode (GCM)
{-# NOINLINE decryptGCM #-}
decryptGCM :: Key -> IV -> ByteString -> ByteString -> (ByteString, ByteString)
decryptGCM = doGCM gcmAppendDecrypt

{-# INLINE doECB #-}
doECB :: (Ptr b -> Ptr Key -> CString -> CUInt -> IO ())
      -> Key -> ByteString -> ByteString
doECB f key input
    | r /= 0    = error "cannot use with non multiple of block size"
    | otherwise = unsafeCreate len $ \o -> keyToPtr key $ \k -> unsafeUseAsCString input $ \i ->
            f (castPtr o) k i (fromIntegral nbBlocks)
    where (nbBlocks, r) = len `divMod` 16
          len           = (B.length input)


{-# INLINE doCBC #-}
doCBC :: (Ptr b -> Ptr Key -> Ptr IV -> CString -> CUInt -> IO ())
      -> Key -> IV -> ByteString -> ByteString
doCBC f key iv input
    | r /= 0    = error "cannot use with non multiple of block size"
    | otherwise = unsafeCreate len $ \o -> withKeyAndIV key iv $ \k v -> unsafeUseAsCString input $ \i ->
            f (castPtr o) k v i (fromIntegral nbBlocks)
    where (nbBlocks, r) = len `divMod` 16
          len           = (B.length input)

{-# INLINE doXTS #-}
doXTS :: (Ptr b -> Ptr Key -> Ptr Key -> Ptr IV -> CUInt -> CString -> CUInt -> IO ())
      -> (Key, Key) -> IV -> Word32 -> ByteString -> ByteString
doXTS f (key1,key2) iv spoint input
    | r /= 0    = error "cannot use with non multiple of block size (yet)"
    | otherwise = unsafeCreate len $ \o -> withKey2AndIV key1 key2 iv $ \k1 k2 v -> unsafeUseAsCString input $ \i ->
            f (castPtr o) k1 k2 v (fromIntegral spoint) i (fromIntegral nbBlocks)
    where (nbBlocks, r) = len `divMod` 16
          len           = (B.length input)

{-# INLINE doGCM #-}
doGCM :: (GCM -> ByteString -> (ByteString, GCM)) -> Key -> IV -> ByteString -> ByteString -> (ByteString, ByteString)
doGCM f key iv aad input = (cipher, tag)
    where
          tag             = gcmFinish after 16
          (cipher, after) = f afterAAD input
          afterAAD        = gcmAppendAAD ini aad
          ini             = gcmInit key iv

allocaFrom :: Storable a => a -> (Ptr a -> IO b) -> IO b
allocaFrom z f = alloca $ \ptr -> poke ptr z >> f ptr

-- | initialize a gcm context
{-# NOINLINE gcmInit #-}
gcmInit :: Key -> IV -> GCM
gcmInit key iv@(IV b) = unsafePerformIO $ alloca doInit
    where doInit gcm = withKeyAndIV key iv (\k v -> c_aes_gcm_init gcm k v (fromIntegral $ B.length b)) >> peek gcm

-- | append data which is going to just be authentified to the GCM context.
--
-- need to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE gcmAppendAAD #-}
gcmAppendAAD :: GCM -> ByteString -> GCM
gcmAppendAAD gcm input = unsafePerformIO $ allocaFrom gcm doAppend
    where doAppend p = do
                unsafeUseAsCString input $ \i -> c_aes_gcm_aad p i (fromIntegral $ B.length input) 
                peek p

-- | append data to encrypt and append to the GCM context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendEncrypt #-}
gcmAppendEncrypt :: GCM -> ByteString -> (ByteString, GCM)
gcmAppendEncrypt gcm input = unsafePerformIO $ allocaFrom gcm doEnc
    where len = B.length input
          doEnc p = do
                output <- create len $ \o -> unsafeUseAsCString input $ \i -> c_aes_gcm_encrypt (castPtr o) p i (fromIntegral len)
                ngcm   <- peek p
                return (output, ngcm)

-- | append data to decrypt and append to the GCM context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendDecrypt #-}
gcmAppendDecrypt :: GCM -> ByteString -> (ByteString, GCM)
gcmAppendDecrypt gcm input = unsafePerformIO $ allocaFrom gcm doDec
    where len = B.length input
          doDec p = do
                output <- create len $ \o -> unsafeUseAsCString input $ \i -> c_aes_gcm_decrypt (castPtr o) p i (fromIntegral len)
                ngcm   <- peek p
                return (output, ngcm)

-- | Generate the Tag from GCM context
{-# NOINLINE gcmFinish #-}
gcmFinish :: GCM -> Int -> ByteString
gcmFinish gcm taglen = B.take taglen (unsafeCreate 16 $ \t -> allocaFrom gcm (finish t))
    where finish t p = c_aes_gcm_finish (castPtr t) p

foreign import ccall "aes.h aes_init"
    c_aes_init :: Ptr Key -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_ecb"
    c_aes_encrypt_ecb :: CString -> Ptr Key -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_ecb"
    c_aes_decrypt_ecb :: CString -> Ptr Key -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_cbc"
    c_aes_encrypt_cbc :: CString -> Ptr Key -> Ptr IV -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_cbc"
    c_aes_decrypt_cbc :: CString -> Ptr Key -> Ptr IV -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_xts"
    c_aes_encrypt_xts :: CString -> Ptr Key -> Ptr Key -> Ptr IV -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_xts"
    c_aes_decrypt_xts :: CString -> Ptr Key -> Ptr Key -> Ptr IV -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gen_ctr"
    c_aes_gen_ctr :: CString -> Ptr Key -> Ptr IV -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_ctr"
    c_aes_encrypt_ctr :: CString -> Ptr Key -> Ptr IV -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_init"
    c_aes_gcm_init :: Ptr GCM -> Ptr Key -> Ptr IV -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_aad"
    c_aes_gcm_aad :: Ptr GCM -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_encrypt"
    c_aes_gcm_encrypt :: CString -> Ptr GCM -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_decrypt"
    c_aes_gcm_decrypt :: CString -> Ptr GCM -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_finish"
    c_aes_gcm_finish :: CString -> Ptr GCM -> IO ()
