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
import Crypto.Cipher.Types hiding (key, iv) -- (iv128, IV(..), AuthTag(..), key128, key192, key256)

import qualified KATECB
import qualified KATCBC
import qualified KATXTS
import qualified KATGCM

encryptBlock initF encryptF key plaintext =
    B.unpack $ encryptF (initF (B.pack key)) plaintext

katECBTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
               where makeTest (AES.initAES -> aes,plaintext,expected) = assertEq expected $ f aes plaintext

katCBCTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
            where makeTest (AES.initAES -> aes,testIV,plaintext,expected) = assertEq expected $ f aes testIV plaintext

katXTSTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
              where makeTest (AES.initAES -> aes1,AES.initAES -> aes2, testIV,plaintext,_,expected) =
                        (assertEq expected $ f (aes1,aes2) testIV 0 plaintext)

katGCMTests vectors f = concatMap makeTests vectors
    where makeTests (name, v) = map (\(z,i) -> testProperty (name ++ " " ++ show i) $ makeTest z) $ zip v [0..]
            where makeTest (AES.initAES -> aes, testIV, aad, plaintext, expectedOutput, taglen, AuthTag -> expectedTag) =
                        let (output,tag) = f aes testIV aad plaintext in
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

idECBTests (ECBUnit (AES.initAES -> aes) plaintext) =
    plaintext `assertEq` AES.decryptECB aes (AES.encryptECB aes plaintext)

idCBCTests (CBCUnit (AES.initAES -> aes) testIV plaintext) =
    plaintext `assertEq` AES.decryptCBC aes testIV (AES.encryptCBC aes testIV plaintext)

idCTRTests (CTRUnit (AES.initAES -> aes) testIV plaintext) =
    plaintext `assertEq` AES.decryptCTR aes testIV (AES.encryptCTR aes testIV plaintext)

idXTSTests (XTSUnit (AES.initAES -> aes1) (AES.initAES -> aes2) testIV plaintext) =
    plaintext `assertEq` AES.decryptXTS (aes1, aes2) testIV 0 (AES.encryptXTS (aes1, aes2) testIV 0 plaintext)

idGCMTests (GCMUnit (AES.initAES -> aes) testIV aad plaintext) =
    let (cipherText, tag) = AES.encryptGCM aes testIV aad plaintext in
    let (plaintext2, tag2) = AES.decryptGCM aes testIV aad cipherText in
    (plaintext `assertEq` plaintext2) && (tag == tag2)

--idKey (KeyUnit keyBs) = keyBs == AES.keyOfCtx (AES.initAES keyBs)

assertEq :: (Byteable b, Eq b) => b -> b -> Bool
assertEq expected got
	| expected == got = True
	| otherwise       = error ("expected: " ++ showhex expected ++ " got: " ++ showhex got)
    where showhex = concatMap toHex . B.unpack . toBytes
          toHex b = let (l,r) = b `divMod` 16 in map (toHexChar . fromIntegral) [l,r]
          toHexChar c
                  | c >= 0 && c <= 9   = toEnum (c + fromEnum '0')
                  | c >= 10 && c <= 16 = toEnum (c + fromEnum 'a')
                  | otherwise          = '_'

tests =
    [ testGroup "KAT-ECB-Encrypt" $ katECBTests KATECB.vectors_encrypt AES.encryptECB
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
