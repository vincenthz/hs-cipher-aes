{-# LANGUAGE CPP #-}
import Criterion
import Criterion.Environment
import Criterion.Config
import Criterion.Monad
import Criterion.Analysis
import Criterion.Measurement

import Text.Printf

import Control.Monad.Trans

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Cipher.AES as AES

key128 = AES.initKey $ B.replicate 16 0
key192 = AES.initKey $ B.replicate 24 0
key256 = AES.initKey $ B.replicate 32 0

nullIV = AES.IV $ B.replicate 16 0
nullIVGCM = AES.IV $ B.replicate 12 0

aesEncrypt128 = AES.encryptECB key128
aesEncrypt128CBC = AES.encryptCBC key128 nullIV
aesEncrypt128CTR = AES.encryptCTR key128 nullIV
aesEncrypt128XTS = AES.encryptXTS (key128,key128) nullIV 0
aesEncrypt128GCM = fst . AES.encryptGCM key128 nullIVGCM B.empty

aesEncrypt192 = AES.encryptECB key192
aesEncrypt192CBC = AES.encryptCBC key192 nullIV
aesEncrypt192CTR = AES.encryptCTR key192 nullIV
aesEncrypt192GCM = fst . AES.encryptGCM key192 nullIVGCM B.empty
aesEncrypt256 = AES.encryptECB key256
aesEncrypt256CBC = AES.encryptCBC key256 nullIV
aesEncrypt256CTR = AES.encryptCTR key256 nullIV
aesEncrypt256XTS = AES.encryptXTS (key256,key256) nullIV 0
aesEncrypt256GCM = fst . AES.encryptGCM key256 nullIVGCM B.empty

b16 f   = whnf f $ B.replicate 16 0
b32 f   = whnf f $ B.replicate 32 0
b128 f  = whnf f $ B.replicate 128 0
b512 f  = whnf f $ B.replicate 512 0
b1024 f = whnf f $ B.replicate 1024 0
b4096 f = whnf f $ B.replicate 4096 0
b16384 f = whnf f $ B.replicate 16384 0

doCipher env f = do
	mean16   <- runBenchmark env (b16 f)   >>= \sample -> analyseMean sample 100
	mean32   <- runBenchmark env (b32 f)   >>= \sample -> analyseMean sample 100
	mean128  <- runBenchmark env (b128 f)  >>= \sample -> analyseMean sample 100
	mean512  <- runBenchmark env (b512 f)  >>= \sample -> analyseMean sample 100
	mean1024 <- runBenchmark env (b1024 f) >>= \sample -> analyseMean sample 100
	mean4096 <- runBenchmark env (b4096 f) >>= \sample -> analyseMean sample 100
	mean16384 <- runBenchmark env (b16384 f) >>= \sample -> analyseMean sample 100
	return (mean16, mean32, mean128, mean512, mean1024, mean4096, mean16384)

norm :: Int -> Double -> Double
norm n time
	| n < 1024  = 1.0 / (time * (1024 / fromIntegral n))
	| n == 1024 = 1.0 / time
	| n > 1024  = 1.0 / (time / (fromIntegral n / 1024))

pn :: Int -> Double -> String
pn n time
    | val > (10 * 1024) = printf "%.1f M/s" (val / 1024)
    | otherwise         = printf "%.1f K/s" val
    where val = norm n time

doOne env (cipherName, f) = do
	(mean16, mean32, mean128, mean512, mean1024, mean4096, mean16384) <- doCipher env f
	let s = printf "%12s: %12s %12s %12s %12s %12s %12s %12s\n              %12s %12s %12s %12s %12s %12s %12s"
	               cipherName
	               (secs mean16) (secs mean32) (secs mean128)
	               (secs mean512) (secs mean1024) (secs mean4096) (secs mean16384)
	               (pn 16 mean16) (pn 32 mean32) (pn 128 mean128)
	               (pn 512 mean512) (pn 1024 mean1024) (pn 4096 mean4096) (pn 16384 mean16384)
	return s

main = withConfig defaultConfig $ do
	env <- measureEnvironment
	l   <- mapM (doOne env)
		[ ("AES128"     , aesEncrypt128)
		, ("AES128-CBC" , aesEncrypt128CBC)
		, ("AES128-CTR" , aesEncrypt128CTR)
		, ("AES128-XTS" , aesEncrypt128XTS)
		, ("AES128-GCM" , aesEncrypt128GCM)
		, ("AES192"     , aesEncrypt192)
		, ("AES192-CBC" , aesEncrypt192CBC)
		, ("AES192-CTR" , aesEncrypt192CTR)
		, ("AES192-GCM" , aesEncrypt192GCM)
		, ("AES256"     , aesEncrypt256)
		, ("AES256-CBC" , aesEncrypt256CBC)
		, ("AES256-CTR" , aesEncrypt256CTR)
		, ("AES256-XTS" , aesEncrypt256XTS)
		, ("AES256-GCM" , aesEncrypt256GCM)
		]
	liftIO $ printf "%12s| %12s %12s %12s %12s %12s %12s %12s\n"
	                "cipher" "16 bytes" "32 bytes" "64 bytes" "512 bytes" "1024 bytes" "4096 bytes" "16384 bytes"
	liftIO $ printf "===================================================================================================\n"
	mapM_ (liftIO . putStrLn) l
