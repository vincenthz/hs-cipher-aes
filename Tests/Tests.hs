{-# LANGUAGE ViewPatterns #-}
module Main where

import Control.Applicative
import Control.Monad

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Data.Byteable
import qualified Data.ByteString as B
import qualified Crypto.Cipher.AES as AES
import Crypto.Cipher.Types -- (iv128, IV(..), AuthTag(..), key128, key192, key256)
import Crypto.Cipher.Tests

import qualified KATECB
import qualified KATCBC
import qualified KATXTS
import qualified KATGCM

toKatECB (k,p,c) = KAT_ECB { ecbKey = k, ecbPlaintext = p, ecbCiphertext = c }
toKatCBC (k,iv,p,c) = KAT_CBC { cbcKey = k, cbcIV = iv, cbcPlaintext = p, cbcCiphertext = c }
toKatXTS (k1,k2,iv,p,_,c) = KAT_XTS { xtsKey1 = k1, xtsKey2 = k2, xtsIV = iv, xtsPlaintext = p, xtsCiphertext = c }
toKatGCM (k,iv,h,p,c,taglen,tag) =
    KAT_AEAD { aeadMode       = AEAD_GCM
             , aeadKey        = k
             , aeadIV         = iv
             , aeadHeader     = h
             , aeadPlaintext  = p
             , aeadCiphertext = c
             , aeadTaglen     = taglen
             , aeadTag        = AuthTag tag
             }

kats128 = defaultKATs
    { kat_ECB  = map toKatECB KATECB.vectors_aes128_enc
    , kat_CBC  = map toKatCBC KATCBC.vectors_aes128_enc
    , kat_XTS  = map toKatXTS KATXTS.vectors_aes128_enc
    , kat_AEAD = map toKatGCM KATGCM.vectors_aes128_enc
    }

kats192 = defaultKATs
    { kat_ECB  = map toKatECB KATECB.vectors_aes192_enc
    , kat_CBC  = map toKatCBC KATCBC.vectors_aes192_enc
    }

kats256 = defaultKATs
    { kat_ECB  = map toKatECB KATECB.vectors_aes256_enc
    , kat_CBC  = map toKatCBC KATCBC.vectors_aes256_enc
    , kat_XTS  = map toKatXTS KATXTS.vectors_aes256_enc
    }

main = defaultMain
    [ testBlockCipher kats128 (undefined :: AES.AES128)
    , testBlockCipher kats192 (undefined :: AES.AES192)
    , testBlockCipher kats256 (undefined :: AES.AES256)
    ]
