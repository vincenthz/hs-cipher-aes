{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE CPP #-}
-- |
-- Module      : Crypto.Cipher.AES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
module Crypto.Cipher.AES
    (
    -- * block cipher data types
      AES
    , AES128
    , AES192
    , AES256

    -- * Authenticated encryption block cipher types
    , AESGCM

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
    , encryptOCB

    -- * decryption
    , decryptECB
    , decryptCBC
    , decryptCTR
    , decryptXTS
    , decryptGCM
    , decryptOCB
    ) where

import Data.Word
import Foreign.Ptr
import Foreign.C.Types
import Foreign.C.String
import Data.ByteString.Internal
import Data.ByteString.Unsafe
import Data.Byteable
import qualified Data.ByteString as B
import System.IO.Unsafe (unsafePerformIO)

import Crypto.Cipher.Types
import Data.SecureMem

-- | AES Context (pre-processed key)
newtype AES = AES SecureMem

-- | AES with 128 bit key
newtype AES128 = AES128 AES

-- | AES with 192 bit key
newtype AES192 = AES192 AES

-- | AES with 256 bit key
newtype AES256 = AES256 AES

instance Cipher AES where
    cipherName    _ = "AES"
    cipherKeySize _ = KeySizeEnum [16,24,32]
    cipherInit k    = initAES k

instance Cipher AES128 where
    cipherName    _ = "AES128"
    cipherKeySize _ = KeySizeFixed 16
    cipherInit k    = AES128 $ initAES k

instance Cipher AES192 where
    cipherName    _ = "AES192"
    cipherKeySize _ = KeySizeFixed 24
    cipherInit k    = AES192 $ initAES k

instance Cipher AES256 where
    cipherName    _ = "AES256"
    cipherKeySize _ = KeySizeFixed 32
    cipherInit k    = AES256 $ initAES k

instance BlockCipher AES where
    blockSize _ = 16
    ecbEncrypt = encryptECB
    ecbDecrypt = decryptECB
    cbcEncrypt = encryptCBC
    cbcDecrypt = decryptCBC
    ctrCombine = encryptCTR
    xtsEncrypt = encryptXTS
    xtsDecrypt = decryptXTS
    aeadInit AEAD_GCM aes iv = Just $ AEAD aes $ AEADState $ gcmInit aes iv
    aeadInit AEAD_OCB aes iv = Just $ AEAD aes $ AEADState $ ocbInit aes iv
    aeadInit _        _    _ = Nothing

instance AEADModeImpl AES AESGCM where
    aeadStateAppendHeader _ = gcmAppendAAD
    aeadStateEncrypt = gcmAppendEncrypt
    aeadStateDecrypt = gcmAppendDecrypt
    aeadStateFinalize = gcmFinish

instance AEADModeImpl AES AESOCB where
    aeadStateAppendHeader = ocbAppendAAD
    aeadStateEncrypt = ocbAppendEncrypt
    aeadStateDecrypt = ocbAppendDecrypt
    aeadStateFinalize = ocbFinish

#define INSTANCE_BLOCKCIPHER(CSTR) \
instance BlockCipher CSTR where \
    { blockSize _ = 16 \
    ; ecbEncrypt (CSTR aes) = encryptECB aes \
    ; ecbDecrypt (CSTR aes) = decryptECB aes \
    ; cbcEncrypt (CSTR aes) = encryptCBC aes \
    ; cbcDecrypt (CSTR aes) = decryptCBC aes \
    ; ctrCombine (CSTR aes) = encryptCTR aes \
    ; xtsEncrypt (CSTR aes1, CSTR aes2) = encryptXTS (aes1,aes2) \
    ; xtsDecrypt (CSTR aes1, CSTR aes2) = decryptXTS (aes1,aes2) \
    ; aeadInit AEAD_GCM cipher@(CSTR aes) iv = Just $ AEAD cipher $ AEADState $ gcmInit aes iv \
    ; aeadInit AEAD_OCB cipher@(CSTR aes) iv = Just $ AEAD cipher $ AEADState $ ocbInit aes iv \
    ; aeadInit _        _                  _ = Nothing \
    }; \
\
instance AEADModeImpl CSTR AESGCM where \
    { aeadStateAppendHeader (CSTR _) gcmState bs = gcmAppendAAD gcmState bs \
    ; aeadStateEncrypt (CSTR aes) gcmState input = gcmAppendEncrypt aes gcmState input \
    ; aeadStateDecrypt (CSTR aes) gcmState input = gcmAppendDecrypt aes gcmState input \
    ; aeadStateFinalize (CSTR aes) gcmState len  = gcmFinish aes gcmState len \
    }; \
\
instance AEADModeImpl CSTR AESOCB where \
    { aeadStateAppendHeader (CSTR aes) ocbState bs = ocbAppendAAD aes ocbState bs \
    ; aeadStateEncrypt (CSTR aes) ocbState input = ocbAppendEncrypt aes ocbState input \
    ; aeadStateDecrypt (CSTR aes) ocbState input = ocbAppendDecrypt aes ocbState input \
    ; aeadStateFinalize (CSTR aes) ocbState len  = ocbFinish aes ocbState len \
    }

INSTANCE_BLOCKCIPHER(AES128)
INSTANCE_BLOCKCIPHER(AES192)
INSTANCE_BLOCKCIPHER(AES256)

-- | AESGCM State
newtype AESGCM = AESGCM SecureMem

-- | AESOCB State
newtype AESOCB = AESOCB SecureMem

sizeGCM :: Int
sizeGCM = 80

sizeOCB :: Int
sizeOCB = 96

keyToPtr :: AES -> (Ptr AES -> IO a) -> IO a
keyToPtr (AES b) f = withSecureMemPtr b (f . castPtr)

ivToPtr :: Byteable iv => iv -> (Ptr Word8 -> IO a) -> IO a
ivToPtr iv f = withBytePtr iv (f . castPtr)

withKeyAndIV :: Byteable iv => AES -> iv -> (Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKeyAndIV ctx iv f = keyToPtr ctx $ \kptr -> ivToPtr iv $ \ivp -> f kptr ivp

withKey2AndIV :: Byteable iv => AES -> AES -> iv -> (Ptr AES -> Ptr AES -> Ptr Word8 -> IO a) -> IO a
withKey2AndIV key1 key2 iv f =
    keyToPtr key1 $ \kptr1 -> keyToPtr key2 $ \kptr2 -> ivToPtr iv $ \ivp -> f kptr1 kptr2 ivp

withGCMKeyAndCopySt :: AES -> AESGCM -> (Ptr AESGCM -> Ptr AES -> IO a) -> IO (a, AESGCM)
withGCMKeyAndCopySt aes (AESGCM gcmSt) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- secureMemCopy gcmSt
        a     <- withSecureMemPtr newSt $ \gcmStPtr -> f (castPtr gcmStPtr) aesPtr
        return (a, AESGCM newSt)

withNewGCMSt :: AESGCM -> (Ptr AESGCM -> IO ()) -> IO AESGCM
withNewGCMSt (AESGCM gcmSt) f = withSecureMemCopy gcmSt (f . castPtr) >>= \sm2 -> return (AESGCM sm2)

withOCBKeyAndCopySt :: AES -> AESOCB -> (Ptr AESOCB -> Ptr AES -> IO a) -> IO (a, AESOCB)
withOCBKeyAndCopySt aes (AESOCB gcmSt) f =
    keyToPtr aes $ \aesPtr -> do
        newSt <- secureMemCopy gcmSt
        a     <- withSecureMemPtr newSt $ \gcmStPtr -> f (castPtr gcmStPtr) aesPtr
        return (a, AESOCB newSt)

-- | Initialize a new context with a key
--
-- Key need to be of length 16, 24 or 32 bytes. any other values will cause undefined behavior
initAES :: Byteable b => b -> AES
initAES k
    | len == 16 = initWithRounds 10
    | len == 24 = initWithRounds 12
    | len == 32 = initWithRounds 14
    | otherwise = error "AES: not a valid key length (valid=16,24,32)"
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
encryptCBC :: Byteable iv
           => AES        -- ^ AES Context
           -> iv         -- ^ Initial vector
           -> ByteString -- ^ plaintext
           -> ByteString -- ^ ciphertext
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
           => AES        -- ^ AES Context
           -> iv         -- ^ initial vector, usually representing a 128 bit integer
           -> ByteString -- ^ plaintext input
           -> ByteString -- ^ ciphertext output
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
           => AES        -- ^ AES Context
           -> iv         -- ^ IV initial vector of any size
           -> ByteString -- ^ data to authenticate (AAD)
           -> ByteString -- ^ data to encrypt
           -> (ByteString, AuthTag) -- ^ ciphertext and tag
encryptGCM = doGCM gcmAppendEncrypt

-- | encrypt using OCB v3
-- return the encrypted bytestring and the tag associated
{-# NOINLINE encryptOCB #-}
encryptOCB :: Byteable iv
           => AES        -- ^ AES Context
           -> iv         -- ^ IV initial vector of any size
           -> ByteString -- ^ data to authenticate (AAD)
           -> ByteString -- ^ data to encrypt
           -> (ByteString, AuthTag) -- ^ ciphertext and tag
encryptOCB = doOCB ocbAppendEncrypt

-- | encrypt using XTS
--
-- the first key is the normal block encryption key
-- the second key is used for the initial block tweak
{-# NOINLINE encryptXTS #-}
encryptXTS :: Byteable iv
           => (AES,AES)  -- ^ AES cipher and tweak context
           -> iv         -- ^ a 128 bits IV, typically a sector or a block offset in XTS
           -> Word32     -- ^ number of rounds to skip, also seen a 16 byte offset in the sector or block.
           -> ByteString -- ^ input to encrypt
           -> ByteString -- ^ output encrypted
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
decryptCTR :: Byteable iv
           => AES        -- ^ AES Context
           -> iv         -- ^ initial vector, usually representing a 128 bit integer
           -> ByteString -- ^ ciphertext input
           -> ByteString -- ^ plaintext output
decryptCTR = encryptCTR

-- | decrypt using XTS
{-# NOINLINE decryptXTS #-}
decryptXTS :: Byteable iv
           => (AES,AES)  -- ^ AES cipher and tweak context
           -> iv         -- ^ a 128 bits IV, typically a sector or a block offset in XTS
           -> Word32     -- ^ number of rounds to skip, also seen a 16 byte offset in the sector or block.
           -> ByteString -- ^ input to decrypt
           -> ByteString -- ^ output decrypted
decryptXTS = doXTS c_aes_decrypt_xts

-- | decrypt using Galois Counter Mode (GCM)
{-# NOINLINE decryptGCM #-}
decryptGCM :: Byteable iv
           => AES        -- ^ Key
           -> iv         -- ^ IV initial vector of any size
           -> ByteString -- ^ data to authenticate (AAD)
           -> ByteString -- ^ data to decrypt
           -> (ByteString, AuthTag) -- ^ plaintext and tag
decryptGCM = doGCM gcmAppendDecrypt

-- | decrypt using Offset Codebook Mode (OCB)
{-# NOINLINE decryptOCB #-}
decryptOCB :: Byteable iv
           => AES        -- ^ Key
           -> iv         -- ^ IV initial vector of any size
           -> ByteString -- ^ data to authenticate (AAD)
           -> ByteString -- ^ data to decrypt
           -> (ByteString, AuthTag) -- ^ plaintext and tag
decryptOCB = doOCB ocbAppendDecrypt

{-# INLINE doECB #-}
doECB :: (Ptr b -> Ptr AES -> CString -> CUInt -> IO ())
      -> AES -> ByteString -> ByteString
doECB f ctx input
    | r /= 0    = error $ "Encryption error: input length must be a multiple of block size (16). Its length is: " ++ (show len)
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
    | r /= 0    = error $ "Encryption error: input length must be a multiple of block size (16). Its length is: " ++ (show len)
    | otherwise = unsafeCreate len $ \o ->
                  withKeyAndIV ctx iv $ \k v ->
                  unsafeUseAsCString input $ \i ->
                  f (castPtr o) k v i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = B.length input

{-# INLINE doXTS #-}
doXTS :: Byteable iv
      => (Ptr b -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ())
      -> (AES, AES)
      -> iv
      -> Word32
      -> ByteString
      -> ByteString
doXTS f (key1,key2) iv spoint input
    | len == 0  = B.empty
    | r /= 0    = error $ "Encryption error: input length must be a multiple of block size (16) for now. Its length is: " ++ (show len)
    | otherwise = unsafeCreate len $ \o -> withKey2AndIV key1 key2 iv $ \k1 k2 v -> unsafeUseAsCString input $ \i ->
            f (castPtr o) k1 k2 v (fromIntegral spoint) i (fromIntegral nbBlocks)
  where (nbBlocks, r) = len `quotRem` 16
        len           = B.length input

------------------------------------------------------------------------
-- GCM
------------------------------------------------------------------------

{-# INLINE doGCM #-}
doGCM :: Byteable iv
      => (AES -> AESGCM -> ByteString -> (ByteString, AESGCM))
      -> AES
      -> iv
      -> ByteString
      -> ByteString
      -> (ByteString, AuthTag)
doGCM f ctx iv aad input = (output, tag)
  where tag             = gcmFinish ctx after 16
        (output, after) = f ctx afterAAD input
        afterAAD        = gcmAppendAAD ini aad
        ini             = gcmInit ctx iv

-- | initialize a gcm context
{-# NOINLINE gcmInit #-}
gcmInit :: Byteable iv => AES -> iv -> AESGCM
gcmInit ctx iv = unsafePerformIO $ do
    sm <- createSecureMem sizeGCM $ \gcmStPtr ->
            withKeyAndIV ctx iv $ \k v ->
            c_aes_gcm_init (castPtr gcmStPtr) k v (fromIntegral $ byteableLength iv)
    return $ AESGCM sm

-- | append data which is going to just be authentified to the GCM context.
--
-- need to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE gcmAppendAAD #-}
gcmAppendAAD :: AESGCM -> ByteString -> AESGCM
gcmAppendAAD gcmSt input = unsafePerformIO doAppend
  where doAppend =
            withNewGCMSt gcmSt $ \gcmStPtr ->
            unsafeUseAsCString input $ \i ->
            c_aes_gcm_aad gcmStPtr i (fromIntegral $ B.length input)

-- | append data to encrypt and append to the GCM context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE gcmAppendEncrypt #-}
gcmAppendEncrypt :: AES -> AESGCM -> ByteString -> (ByteString, AESGCM)
gcmAppendEncrypt ctx gcm input = unsafePerformIO $ withGCMKeyAndCopySt ctx gcm doEnc
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
gcmAppendDecrypt :: AES -> AESGCM -> ByteString -> (ByteString, AESGCM)
gcmAppendDecrypt ctx gcm input = unsafePerformIO $ withGCMKeyAndCopySt ctx gcm doDec
  where len = B.length input
        doDec gcmStPtr aesPtr =
            create len $ \o ->
            unsafeUseAsCString input $ \i ->
            c_aes_gcm_decrypt (castPtr o) gcmStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from GCM context
{-# NOINLINE gcmFinish #-}
gcmFinish :: AES -> AESGCM -> Int -> AuthTag
gcmFinish ctx gcm taglen = AuthTag $ B.take taglen computeTag
  where computeTag = unsafeCreate 16 $ \t ->
                        withGCMKeyAndCopySt ctx gcm (c_aes_gcm_finish (castPtr t)) >> return ()

------------------------------------------------------------------------
-- OCB v3
------------------------------------------------------------------------

{-# INLINE doOCB #-}
doOCB :: Byteable iv
      => (AES -> AESOCB -> ByteString -> (ByteString, AESOCB))
      -> AES
      -> iv
      -> ByteString
      -> ByteString
      -> (ByteString, AuthTag)
doOCB f ctx iv aad input = (output, tag)
  where tag             = ocbFinish ctx after 16
        (output, after) = f ctx afterAAD input
        afterAAD        = ocbAppendAAD ctx ini aad
        ini             = ocbInit ctx iv

-- | initialize an ocb context
{-# NOINLINE ocbInit #-}
ocbInit :: Byteable iv => AES -> iv -> AESOCB
ocbInit ctx iv = unsafePerformIO $ do
    sm <- createSecureMem sizeOCB $ \ocbStPtr ->
            withKeyAndIV ctx iv $ \k v ->
            c_aes_ocb_init (castPtr ocbStPtr) k v (fromIntegral $ byteableLength iv)
    return $ AESOCB sm

-- | append data which is going to just be authentified to the OCB context.
--
-- need to happen after initialization and before appending encryption/decryption data.
{-# NOINLINE ocbAppendAAD #-}
ocbAppendAAD :: AES -> AESOCB -> ByteString -> AESOCB
ocbAppendAAD ctx ocb input = unsafePerformIO (snd `fmap` withOCBKeyAndCopySt ctx ocb doAppend)
  where doAppend ocbStPtr aesPtr =
            unsafeUseAsCString input $ \i ->
            c_aes_ocb_aad ocbStPtr aesPtr i (fromIntegral $ B.length input)

-- | append data to encrypt and append to the OCB context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ocbAppendEncrypt #-}
ocbAppendEncrypt :: AES -> AESOCB -> ByteString -> (ByteString, AESOCB)
ocbAppendEncrypt ctx ocb input = unsafePerformIO $ withOCBKeyAndCopySt ctx ocb doEnc
  where len = B.length input
        doEnc ocbStPtr aesPtr =
            create len $ \o ->
            unsafeUseAsCString input $ \i ->
            c_aes_ocb_encrypt (castPtr o) ocbStPtr aesPtr i (fromIntegral len)

-- | append data to decrypt and append to the OCB context
--
-- bytestring need to be multiple of AES block size, unless it's the last call to this function.
-- need to happen after AAD appending, or after initialization if no AAD data.
{-# NOINLINE ocbAppendDecrypt #-}
ocbAppendDecrypt :: AES -> AESOCB -> ByteString -> (ByteString, AESOCB)
ocbAppendDecrypt ctx ocb input = unsafePerformIO $ withOCBKeyAndCopySt ctx ocb doDec
  where len = B.length input
        doDec ocbStPtr aesPtr =
            create len $ \o ->
            unsafeUseAsCString input $ \i ->
            c_aes_ocb_decrypt (castPtr o) ocbStPtr aesPtr i (fromIntegral len)

-- | Generate the Tag from OCB context
{-# NOINLINE ocbFinish #-}
ocbFinish :: AES -> AESOCB -> Int -> AuthTag
ocbFinish ctx ocb taglen = AuthTag $ B.take taglen computeTag
  where computeTag = unsafeCreate 16 $ \t ->
                        withOCBKeyAndCopySt ctx ocb (c_aes_ocb_finish (castPtr t)) >> return ()

------------------------------------------------------------------------
foreign import ccall "aes.h aes_initkey"
    c_aes_init :: Ptr AES -> CString -> CUInt -> IO ()

------------------------------------------------------------------------
foreign import ccall "aes.h aes_encrypt_ecb"
    c_aes_encrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_ecb"
    c_aes_decrypt_ecb :: CString -> Ptr AES -> CString -> CUInt -> IO ()

------------------------------------------------------------------------
foreign import ccall "aes.h aes_encrypt_cbc"
    c_aes_encrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_cbc"
    c_aes_decrypt_cbc :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

------------------------------------------------------------------------
foreign import ccall "aes.h aes_encrypt_xts"
    c_aes_encrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_decrypt_xts"
    c_aes_decrypt_xts :: CString -> Ptr AES -> Ptr AES -> Ptr Word8 -> CUInt -> CString -> CUInt -> IO ()

------------------------------------------------------------------------
foreign import ccall "aes.h aes_gen_ctr"
    c_aes_gen_ctr :: CString -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "aes.h aes_encrypt_ctr"
    c_aes_encrypt_ctr :: CString -> Ptr AES -> Ptr Word8 -> CString -> CUInt -> IO ()

------------------------------------------------------------------------
foreign import ccall "aes.h aes_gcm_init"
    c_aes_gcm_init :: Ptr AESGCM -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_aad"
    c_aes_gcm_aad :: Ptr AESGCM -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_encrypt"
    c_aes_gcm_encrypt :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_decrypt"
    c_aes_gcm_decrypt :: CString -> Ptr AESGCM -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_gcm_finish"
    c_aes_gcm_finish :: CString -> Ptr AESGCM -> Ptr AES -> IO ()

------------------------------------------------------------------------
foreign import ccall "aes.h aes_ocb_init"
    c_aes_ocb_init :: Ptr AESOCB -> Ptr AES -> Ptr Word8 -> CUInt -> IO ()

foreign import ccall "aes.h aes_ocb_aad"
    c_aes_ocb_aad :: Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_ocb_encrypt"
    c_aes_ocb_encrypt :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_ocb_decrypt"
    c_aes_ocb_decrypt :: CString -> Ptr AESOCB -> Ptr AES -> CString -> CUInt -> IO ()

foreign import ccall "aes.h aes_ocb_finish"
    c_aes_ocb_finish :: CString -> Ptr AESOCB -> Ptr AES -> IO ()
