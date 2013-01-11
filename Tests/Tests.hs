{-# LANGUAGE ViewPatterns #-}
module Main where

import Control.Applicative
import Control.Monad

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.Framework.Providers.QuickCheck2 (testProperty)

import qualified Data.ByteString as B
import qualified Crypto.Cipher.AES as AES

import qualified KATECB
import qualified KATCBC
import qualified KATXTS
import qualified KATGCM

encryptBlock initF encryptF key plaintext =
    B.unpack $ encryptF (initF (B.pack key)) plaintext

katECBTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
               where makeTest (AES.initKey -> key,plaintext,expected) = assertEq expected $ f key plaintext

katCBCTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
            where makeTest (AES.initKey -> key,AES.IV -> iv,plaintext,expected) = assertEq expected $ f key iv plaintext

katXTSTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
              where makeTest (AES.initKey -> key1,AES.initKey -> key2, AES.IV -> iv,plaintext,_,expected) =
                        (assertEq expected $ f (key1,key2) iv 0 plaintext)

katGCMTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
            where makeTest (AES.initKey -> key, AES.IV -> iv, aad, plaintext, expectedOutput, taglen, expectedTag) =
                        let (output,tag) = f key iv aad plaintext in
                        assertEq expectedOutput output && (assertEq tag expectedTag)


data ECBUnit = ECBUnit B.ByteString B.ByteString
    deriving (Show,Eq)
data CBCUnit = CBCUnit B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)
data CTRUnit = CTRUnit B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)
data XTSUnit = XTSUnit B.ByteString B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)
data GCMUnit = GCMUnit B.ByteString B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)
data KeyUnit = KeyUnit B.ByteString
    deriving (Show,Eq)

generateKeyOf size = B.pack <$> replicateM size arbitrary
generateKey = elements [16,24,32] >>= generateKeyOf

generateIv = B.pack <$> replicateM 16 arbitrary
generateIvGCM = choose (12,90) >>= \sz -> (B.pack <$> replicateM sz arbitrary)

generatePlaintextMultiple16 = choose (1,128) >>= \size -> replicateM (size*16) arbitrary >>= return . B.pack

generatePlaintext = choose (0,324) >>= \size -> replicateM size arbitrary >>= return . B.pack

instance Arbitrary ECBUnit where
    arbitrary = ECBUnit <$> generateKey
                        <*> generatePlaintextMultiple16

instance Arbitrary CBCUnit where
    arbitrary = CBCUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultiple16

instance Arbitrary CTRUnit where
    arbitrary = CTRUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintext

instance Arbitrary GCMUnit where
    arbitrary = GCMUnit <$> generateKey
                        <*> generateIvGCM
                        <*> generatePlaintext
                        <*> generatePlaintext

instance Arbitrary XTSUnit where
    arbitrary = do
        size <- elements [16,32]
        XTSUnit <$> generateKeyOf size
                <*> generateKeyOf size
                <*> generateIv
                <*> generatePlaintextMultiple16

instance Arbitrary KeyUnit where
    arbitrary = KeyUnit <$> generateKey

idECBTests (ECBUnit (AES.initKey -> key) plaintext) =
    plaintext `assertEq` AES.decryptECB key (AES.encryptECB key plaintext)

idCBCTests (CBCUnit (AES.initKey -> key) (AES.IV -> iv) plaintext) =
    plaintext `assertEq` AES.decryptCBC key iv (AES.encryptCBC key iv plaintext)

idCTRTests (CTRUnit (AES.initKey -> key) (AES.IV -> iv) plaintext) =
    plaintext `assertEq` AES.decryptCTR key iv (AES.encryptCTR key iv plaintext)

idXTSTests (XTSUnit (AES.initKey -> key1) (AES.initKey -> key2) (AES.IV -> iv) plaintext) =
    plaintext `assertEq` AES.decryptXTS (key1, key2) iv 0 (AES.encryptXTS (key1, key2) iv 0 plaintext)

idGCMTests (GCMUnit (AES.initKey -> key) (AES.IV -> iv) aad plaintext) =
    let (cipherText, tag) = AES.encryptGCM key iv aad plaintext in
    let (plaintext2, tag2) = AES.decryptGCM key iv aad cipherText in
    (plaintext `assertEq` plaintext2) && (tag == tag2)

idKey (KeyUnit keyBs) = keyBs == AES.keyOfCtx (AES.initKey keyBs)

assertEq expected got
	| expected == got = True
	| otherwise       = error ("expected: " ++ showhex expected ++ " got: " ++ showhex got)
    where showhex = concatMap toHex . B.unpack
          toHex b = let (l,r) = b `divMod` 16 in map (toHexChar . fromIntegral) [l,r]
          toHexChar c
                  | c >= 0 && c <= 9   = toEnum (c + fromEnum '0')
                  | c >= 10 && c <= 16 = toEnum (c + fromEnum 'a')
                  | otherwise          = '_'

tests =
    [ testProperty "key-id" idKey
    , testGroup "KAT-ECB-Encrypt" $ katECBTests KATECB.vectors_encrypt AES.encryptECB
    , testGroup "KAT-ECB-Decrypt" $ katECBTests KATECB.vectors_decrypt AES.decryptECB
    , testGroup "KAT-CBC-Encrypt" $ katCBCTests KATCBC.vectors_encrypt AES.encryptCBC
    , testGroup "KAT-CBC-Decrypt" $ katCBCTests KATCBC.vectors_decrypt AES.decryptCBC
    , testGroup "KAT-XTS-Encrypt" $ katXTSTests KATXTS.vectors_encrypt AES.encryptXTS
    , testGroup "KAT-XTS-Decrypt" $ katXTSTests KATXTS.vectors_decrypt AES.decryptXTS
    , testGroup "KAT-GCM-Encrypt" $ katGCMTests KATGCM.vectors_encrypt AES.encryptGCM
    , testGroup "decrypt-encrypt-is-ID"
        [ testProperty "ECB" idECBTests
        , testProperty "CBC" idCBCTests
        , testProperty "CTR" idCTRTests
        , testProperty "XTS" idXTSTests
        , testProperty "GCM" idGCMTests
        ]
    ]

main = defaultMain tests
