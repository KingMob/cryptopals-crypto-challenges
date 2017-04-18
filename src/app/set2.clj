(ns app.set2
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [app.cipher :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [taoensso.tufte :as tufte :refer (defnp p profiled profile)])
  (:import [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec]))

;; Set 2, challenge 9
(= (string->data "YELLOW SUBMARINE\04\04\04\04") (pkcs7-padding 20 (string->data "YELLOW SUBMARINE")))

;; Set 2, challenge 10
(def test-key-10 (string->data "Octopus's Garden"))
(data->string (ecb-decrypt test-key-10 (ecb-encrypt test-key-10 (string->data "This be random, man"))))

(def key-10 (string->data "YELLOW SUBMARINE"))
(def input-10 (base64-decode (str/join (str/split-lines (slurp (io/file (io/resource "10.txt")))))))
(def iv-10 (repeat 16 0))

(println (data->string (cbc-decrypt key-10 iv-10 input-10)))
;; "Go white boy, go white boy, go."
;; Man, decrypting these lyrics is a real counter-incentive to continuing :)


;;; Set 2, challenge 11
;;; It doesn't say anything about input restrictions, so I'm assuming a chosen
;;; plaintext attack is ok here. Basically, we feed it a huge amount of identical data,
;;; which will bin the ECB output into a small set of possibilities. The CBC output
;;; will be much more randomly distributed, since there's no repetition in the ciphertext

(def p<05-threshold 293.24784) ; See http://www.di-mgt.com.au/chisquare-calculator.html w/ 255 df
(defn predicted-oracle-cipher-mode []
  (let [num-bytes 1000
        chosen-plain-data (repeat num-bytes (unchecked-byte 0))
        cipher-data (encryption-oracle chosen-plain-data)
        chi2-info (chi2-uniform-results 256 (frequencies (:cipher-data cipher-data)))
        X2 (:chi2 chi2-info)]
    (str "Guessed "
         (if (> X2 p<05-threshold)
                      :ecb
                      :cbc)
         " - Actual " (:mode cipher-data))))
