{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE PackageImports #-}

import Crypto.Classes
import qualified Crypto.Modes as Modes
import Data.Serialize.Get
import Data.Serialize.Put
import Data.Serialize
import qualified "cipher-aes" Crypto.Cipher.AES as A
import Criterion.Main
import Data.Tagged
import qualified Data.ByteString as B

newtype AES256 = A256 { unA256 :: A.Key }

instance BlockCipher AES256 where
    blockSize    = Tagged 128
    encryptBlock = A.encryptECB . unA256
    decryptBlock = A.decryptECB . unA256
    buildKey     = Just . A256 . A.initKey
    keyLength    = Tagged 128

instance Serialize AES256 where
    put = error "put AES256"
    get = error "get AES256"

encryptCAPI :: AES256 -> Modes.IV AES256 -> B.ByteString -> B.ByteString
encryptCAPI key iv x   = fst $ Modes.ctr' Modes.incIV key iv x
encryptNormal :: AES256 -> B.ByteString -> B.ByteString -> B.ByteString
encryptNormal key iv x = A.encryptCTR (unA256 key) (A.IV iv) x

main = do
    let !iv         = Modes.zeroIV
        !ivbs       = encode iv
        !bs32       = B.replicate 16 0
        !bs1024     = B.replicate 1024 0
        !(Just key) = buildKey (B.replicate 16 0)
    defaultMain
        [ bgroup "32 bytes"
            [ bench "capi" $ nf (encryptCAPI key iv) bs32
            , bench "aes"  $ nf (encryptNormal key ivbs) bs32
            ]
        , bgroup "1024 bytes"
            [ bench "capi" $ nf (encryptCAPI key iv) bs1024
            , bench "aes"  $ nf (encryptNormal key ivbs) bs1024
            ]
        ]
