{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ViewPatterns #-}
-- |
-- Module      : Crypto.Cipher.AES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
module Crypto.Cipher.AES
    (
    -- * data types
      AES
    , AES128
    , AES192
    , AES256

    -- * creation
    , initAES
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
import Foreign.C.Types
import Foreign.C.String
import Data.ByteString.Internal
import Data.ByteString.Unsafe
import Data.Byteable
import qualified Data.ByteString as B
import System.IO.Unsafe (unsafePerformIO)

import Crypto.Cipher.Types hiding (iv)
import Data.SecureMem

-- | AES Context (pre-processed key)
newtype AES = AES SecureMem

newtype AES128 = AES128 AES
newtype AES192 = AES192 AES
newtype AES256 = AES256 AES

instance Cipher AES128 where
    cipherKeySize _ = Just 16
    cipherInit k    = AES128 $ initAES k

instance Cipher AES192 where
    cipherKeySize _ = Just 24
    cipherInit k    = AES192 $ initAES k

instance Cipher AES256 where
    cipherKeySize _ = Just 32
    cipherInit k    = AES256 $ initAES k

instance BlockCipher AES128 where
    blockSize _ = 16
    blockEncrypt (AES128 aes) (Block blk) = Block $ encryptECB aes blk
    blockDecrypt (AES128 aes) (Block blk) = Block $ decryptECB aes blk

instance BlockCipher AES192 where
    blockSize _ = 16
    blockEncrypt (AES192 aes) (Block blk) = Block $ encryptECB aes blk
    blockDecrypt (AES192 aes) (Block blk) = Block $ decryptECB aes blk

instance BlockCipher AES256 where
    blockSize _ = 16
    blockEncrypt (AES256 aes) (Block blk) = Block $ encryptECB aes blk
    blockDecrypt (AES256 aes) (Block blk) = Block $ decryptECB aes blk

-- | GCM Context
data GCM = GCM AES GCMState

-- | GCM State
newtype GCMState = GCMState SecureMem

sizeGCM :: Int
sizeGCM = 80

keyToPtr :: AES -> (Ptr AES -> IO a) -> IO a
keyToPtr (AES b) f = withSecureMemPtr b (f . castPtr)

ivToPtr :: Byteable iv => iv -> (Ptr Word8 -> IO a) -> IO a
ivToPtr iv f = withBytePtr iv (f . castPtr)

withKeyAndIV :: Byteable iv => AES -> iv -> (Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKeyAndIV ctx iv f = keyToPtr ctx $ \kptr -> ivToPtr iv $ \ivp -> f kptr ivp

withKey2AndIV :: Byteable iv => AES -> AES -> iv -> (Ptr AES -> Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKey2AndIV key1 key2 iv f =
    keyToPtr key1 $ \kptr1 -> keyToPtr key2 $ \kptr2 -> ivToPtr iv $ \ivp -> f kptr1 kptr2 ivp

withGCMKeyAndCopySt :: GCM -> (Ptr GCMState -> Ptr AES -> IO a) -> IO (a, GCM)
withGCMKeyAndCopySt (GCM aes (GCMState gcmSt)) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- secureMemCopy gcmSt
        a     <- withSecureMemPtr newSt $ \gcmStPtr -> f (castPtr gcmStPtr) aesPtr
        return (a, GCM aes (GCMState newSt))

withNewGCMSt :: GCMState -> (Ptr GCMState -> IO ()) -> IO GCMState
withNewGCMSt (GCMState gcmSt) f = withSecureMemCopy gcmSt (f . castPtr) >>= \sm2 -> return (GCMState sm2)

-- | initialize key
--
-- rounds need to be 10 / 12 / 14. any other values will cause undefined behavior
initAES :: Byteable b => b -> AES
initAES k
    | len == 16 = initWithRounds 10
    | len == 24 = initWithRounds 12
    | len == 32 = initWithRounds 14
    | otherwise = error "not a valid key length"
  where len = byteableLength k
        initWithRounds nbR = AES $ unsafeCreateSecureMem (16+2*2*16*nbR) aesInit
        aesInit ptr = withBytePtr k $ \ikey ->
            c_aes_init (castPtr ptr) (castPtr ikey) (fromIntegral len)

{-# DEPRECATED initKey "use initAES" #-}
initKey :: Byteable b => b -> AES
initKey = initAES

-- | encrypt using Electronic Code Book (ECB)
{-# NOINLINE encryptECB #-}
encryptECB :: AES -> ByteString -> ByteString
encryptECB = doECB c_aes_encrypt_ecb

-- | encrypt using Cipher Block Chaining (CBC)
{-# NOINLINE encryptCBC #-}
encryptCBC :: Byteable iv => AES -> iv -> ByteString -> ByteString
encryptCBC = doCBC c_aes_encrypt_cbc

-- | generate a counter mode pad. this is generally xor-ed to an input
-- to make the standard counter mode block operations.
--
-- if the length requested is not a multiple of the block cipher size,
-- more data will be returned, so that the returned bytestring is
-- a multiple of the block cipher size.
{-# NOINLINE genCTR #-}
genCTR :: Byteable iv
       => AES -- ^ Cipher Key.
       -> iv  -- ^ usually a 128 bit integer.
       -> Int -- ^ length of bytes required.
       -> ByteString
genCTR ctx iv len
    | len <= 0  = B.empty
    | otherwise = unsafeCreate (nbBlocks * 16) generate
  where generate o = withKeyAndIV ctx iv $ \k i -> c_aes_gen_ctr (castPtr o) k i (fromIntegral nbBlocks)
        (nbBlocks',r) = len `quotRem` 16
        nbBlocks = if r == 0 then nbBlocks' else nbBlocks' + 1

-- | encrypt using Counter mode (CTR)
--
-- in CTR mode encryption and decryption is the same operation.
{-# NOINLINE encryptCTR #-}
encryptCTR :: Byteable iv
           => AES
           -> iv
           -> ByteString
           -> ByteString
encryptCTR ctx iv input
    | len <= 0  = B.empty
    | otherwise = unsafeCreate len doEncrypt
  where doEncrypt o = withKeyAndIV ctx iv $ \k v -> unsafeUseAsCString input $ \i ->
                      c_aes_encrypt_ctr (castPtr o) k v i (fromIntegral len)
        len = B.length input

-- | encrypt using Galois counter mode (GCM)
-- return the encrypted bytestring and the tag associated
--
-- note: encrypted data is identical to CTR mode in GCM, however
-- a tag is also computed.
{-# NOINLINE encryptGCM #-}
encryptGCM :: Byteable iv
           => AES        -- ^ Key
           -> iv         -- ^ initial vector
           -> ByteString -- ^ data to authenticate (AAD)
           -> ByteString -- ^ data to encrypt
           -> (ByteString, AuthTag) -- ^ ciphertext and tag
encryptGCM = doGCM gcmAppendEncrypt

-- | encrypt using XTS
--
-- the first key is the normal block encryption key
-- the second key is used for the initial block tweak
{-# NOINLINE encryptXTS #-}
encryptXTS :: Byteable iv => (AES,AES) -> iv -> Word32 -> ByteString -> ByteString
encryptXTS = doXTS c_aes_encrypt_xts

-- | decrypt using Electronic Code Book (ECB)
{-# NOINLINE decryptECB #-}
decryptECB :: AES -> ByteString -> ByteString
decryptECB = doECB c_aes_decrypt_ecb

-- | decrypt using Cipher block chaining (CBC)
{-# NOINLINE decryptCBC #-}
decryptCBC :: Byteable iv => AES -> iv -> ByteString -> ByteString
decryptCBC = doCBC c_aes_decrypt_cbc

-- | decrypt using Counter mode (CTR).
--
-- in CTR mode encryption and decryption is the same operation.
decryptCTR :: Byteable iv => AES -> iv -> ByteString -> ByteString
decryptCTR = encryptCTR

-- | decrypt using XTS
{-# NOINLINE decryptXTS #-}
decryptXTS :: Byteable iv => (AES,AES) -> iv -> Word32 -> ByteString -> ByteString
decryptXTS = doXTS c_aes_decrypt_xts

-- | decrypt using Galois Counter Mode (GCM)
{-# NOINLINE decryptGCM #-}
decryptGCM :: Byteable iv => AES -> iv -> ByteString -> ByteString -> (ByteString, AuthTag)
decryptGCM = doGCM gcmAppendDecrypt

{-# INLINE doECB #-}
doECB :: (Ptr b -> Ptr AES -> CString -> CUInt -> IO ())
      -> AES -> ByteString -> ByteString
doECB f ctx input
    | r /= 0    = error "cannot use with non multiple of block size"
    | otherwise = unsafeCreate len $ \o ->
                  keyToPtr ctx $ \k ->
                  unsafeUseAsCString input $ \i ->
                  f (castPtr o) k i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = (B.length input)


{-# INLINE doCBC #-}
doCBC :: Byteable iv
      => (Ptr b -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ())
      -> AES -> iv -> ByteString -> ByteString
doCBC f ctx iv input
    | len == 0  = B.empty
    | r /= 0    = error "cannot use with non multiple of block size"
    | otherwise = unsafeCreate len $ \o ->
                  withKeyAndIV ctx iv $ \k v ->
                  unsafeUseAsCString input $ \i ->
                  f (castPtr o) k v i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = B.length input

{-# INLINE doXTS #-}
doXTS :: Byteable iv
      => (Ptr b -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ())
      -> (AES, AES) -> iv -> Word32 -> ByteString -> ByteString
doXTS f (key1,key2) iv spoint input
    | len == 0  = B.empty
    | r /= 0    = error "cannot use with non multiple of block size (yet)"
    | otherwise = unsafeCreate len $ \o -> withKey2AndIV key1 key2 iv $ \k1 k2 v -> unsafeUseAsCString input $ \i ->
            f (castPtr o) k1 k2 v (fromIntegral spoint) i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = B.length input

{-# INLINE doGCM #-}
doGCM :: Byteable iv => (GCM -> ByteString -> (ByteString, GCM)) -> AES -> iv -> ByteString -> ByteString -> (ByteString, AuthTag)
doGCM f ctx iv aad input = (cipher, tag)
  where tag             = gcmFinish after 16
        (cipher, after) = f afterAAD input
        afterAAD        = gcmAppendAAD ini aad
        ini             = gcmInit ctx iv

-- | initialize a gcm context
{-# NOINLINE gcmInit #-}
gcmInit :: Byteable iv => AES -> iv -> GCM
gcmInit ctx iv = unsafePerformIO $ do
    sm <- createSecureMem sizeGCM $ \gcmStPtr ->
            withKeyAndIV ctx iv $ \k v ->
            c_aes_gcm_init (castPtr gcmStPtr) k v (fromIntegral $ byteableLength iv)
    return $ GCM ctx (GCMState sm)

-- | append data which is going to just be authentified to the GCM context.
--
-- need to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE gcmAppendAAD #-}
gcmAppendAAD :: GCM -> ByteString -> GCM
gcmAppendAAD (GCM aes gcmSt) input = unsafePerformIO (GCM aes `fmap` doAppend)
  where doAppend =
            withNewGCMSt gcmSt $ \gcmStPtr ->
            unsafeUseAsCString input $ \i ->
            c_aes_gcm_aad gcmStPtr i (fromIntegral $ B.length input)

-- | append data to encrypt and append to the GCM context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendEncrypt #-}
gcmAppendEncrypt :: GCM -> ByteString -> (ByteString, GCM)
gcmAppendEncrypt gcm input = unsafePerformIO $ withGCMKeyAndCopySt gcm doEnc
  where len = B.length input
        doEnc gcmStPtr aesPtr =
            create len $ \o ->
            unsafeUseAsCString input $ \i ->
            c_aes_gcm_encrypt (castPtr o) gcmStPtr aesPtr i (fromIntegral len)

-- | append data to decrypt and append to the GCM context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendDecrypt #-}
gcmAppendDecrypt :: GCM -> ByteString -> (ByteString, GCM)
gcmAppendDecrypt gcm input = unsafePerformIO $ withGCMKeyAndCopySt gcm doDec
  where len = B.length input
        doDec gcmStPtr aesPtr =
            create len $ \o ->
            unsafeUseAsCString input $ \i ->
            c_aes_gcm_decrypt (castPtr o) gcmStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from GCM context
{-# NOINLINE gcmFinish #-}
gcmFinish :: GCM -> Int -> AuthTag
gcmFinish gcm taglen = AuthTag $ B.take taglen computeTag
  where computeTag = unsafeCreate 16 $ \t ->
                        withGCMKeyAndCopySt gcm (c_aes_gcm_finish (castPtr t)) >> return ()

foreign import ccall "aes.h aes_initkey"
    c_aes_init :: Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_ecb"
    c_aes_encrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_ecb"
    c_aes_decrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_cbc"
    c_aes_encrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_cbc"
    c_aes_decrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_xts"
    c_aes_encrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_xts"
    c_aes_decrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gen_ctr"
    c_aes_gen_ctr :: CString -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_ctr"
    c_aes_encrypt_ctr :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_init"
    c_aes_gcm_init :: Ptr GCMState -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_aad"
    c_aes_gcm_aad :: Ptr GCMState -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_encrypt"
    c_aes_gcm_encrypt :: CString -> Ptr GCMState -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_decrypt"
    c_aes_gcm_decrypt :: CString -> Ptr GCMState -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_finish"
    c_aes_gcm_finish :: CString -> Ptr GCMState -> Ptr AES -> IO ()
