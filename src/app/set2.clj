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
(= (string->data "YELLOW SUBMARINE\04\04\04\04") (pkcs7-pad 20 (string->data "YELLOW SUBMARINE")))

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
;;; Can also check for duplicates with chosen plaintext, since if the plaintext is
;;; a) all the same byte, and b) at least twice as long as the block size, there will
;;; dupes in ECB mode. Chi^2 is not technically necessary, but with repeated text,
;;; the difference in X^2 values is a factor of 1000.

;;; I originally hoped the chi^2 test would pick up differences in real data, and
;;; it does, but the accuracy is much lower.

(def X2-threshold 325) ; See http://www.di-mgt.com.au/chisquare-calculator.html w/ 255 df
; NB: This is ~ p < .001

(defn predicted-oracle-cipher-mode []
  (let [num-bytes 100
        chosen-plain-data (repeat num-bytes (unchecked-byte 0))
        cipher-data (encryption-oracle chosen-plain-data)
        chi2-info (chi2-uniform-byte-results (frequencies (:cipher-data cipher-data)))
        X2 (:chi2 chi2-info)]
    (str "Guessed "
         (if (> X2 X2-threshold)
                      :ecb
                      :cbc)
         " - Actual " (:mode cipher-data))))


;;; Set 2, challenge 12
;;; Byte-at-a-time ECB decryption (Simple)

(def random-key-12 (rand-bytes aes-block-size))
(def secret-string-12 "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")


(defn byte-at-a-time-oracle-12 [d]
  {:pre [(s/valid? :app.util/data d)]}
  (let [plain-data (into [] cat [d (base64-decode secret-string-12)])]
    (ecb-encrypt random-key-12 plain-data)))

(defn decrypt-byte-at-a-time-ecb-simple []
  (let [test-data (byte-at-a-time-oracle-12 (vec (repeat 1000 0)))
        bsize (block-size-w-most-dupes test-data)
        ; chi2-info (chi2-uniform-byte-results (frequencies (:cipher-data test-data)))
        ; X2 (:chi2 chi2-info)
        ;initial-plain-data (repeat (dec bsize) (byte \A))
        ;cipher-data (byte-at-a-time-oracle chosen-plain-data)
        ]
    #_(println "Cipher's block size:" bsize)
    #_(println "Guessed"
             (if (> X2 X2-threshold)
               :ecb
               :cbc)
             "- Actual" (:mode cipher-data))
    (println (data->string (decrypt-secret byte-at-a-time-oracle-12)))))

;;; Kept on pursuing to the next stop

;;; Set 2, challenge 13
(defn profile-for [email]
  (url-encode
   {"email" (str/replace email #"[=&]" "")
    "uid" 10
    "role" "user"}))

(def random-key-13 (rand-bytes aes-block-size))
(defn encrypted-profile [email]
  (ecb-encrypt random-key-13 (string->data (profile-for email))))

(defn decrypted-profile [d]
  {:pre [(s/valid? :app.util/data d)]}
  (url-decode (data->string (ecb-decrypt random-key-13 d))))

(def initial-blocks (into [] cat (butlast (partition-all aes-block-size (encrypted-profile "vanil@ice.com"))))) ; Generates the blocks, splitting after "role="
(def sneaky-email (str "AAAAAAAAAAadmin" (str/join (repeat 11 (char 11))))) ; Generates a block with just "admin" followed by pkcs7 padding
(def admin-padded-block (vec (second (partition-all aes-block-size (encrypted-profile sneaky-email))))) ; extracts that "admin"-only block
(decrypted-profile (apply conj initial-blocks admin-padded-block))


;;; Set 2, challenge 14

(def random-key-14 (rand-bytes aes-block-size))
(def random-prefix-14 (rand-bytes (rand-int 20)))
(def secret-string-14 "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")


(defn byte-at-a-time-oracle-14 [d]
  {:pre [(s/valid? :app.util/data d)]}
  (let [plain-data (into [] cat [random-prefix-14 d (base64-decode secret-string-14)])]
    (ecb-encrypt random-key-14 plain-data)))

(defn decrypt-byte-at-a-time-ecb-harder []
  (let [test-data [(byte 0)]])
  (println (data->string (decrypt-secret byte-at-a-time-oracle-14))))


;;; Set 2, challenge 15

(try
  (pkcs-unpad-ex aes-block-size (repeat 16 (byte 10)))
  (catch Exception e
    "Found correct exception"))

(try
  (pkcs-unpad-ex aes-block-size (into [] cat [(repeat 12 (byte 10)) (repeat 4 (byte 4))]))
  (println "Correctly found no exception")
  (catch Exception e
    "Found incorrect exception"))


;;; Set 2, challenge 16

(def random-key-16 (rand-bytes aes-block-size))
(def random-iv-16 (rand-bytes aes-block-size))
(def prefix-16 "comment1=cooking%20MCs;userdata=")
(def postfix-16 ";comment2=%20like%20a%20pound%20of%20bacon")
(def goal-string ";admin=true;")

(defn quote-16 [s]
  (str/escape s {\; (str "%" (int \;)) \" (str "%" (int \"))}))

(defn encrypt-16 [input]
  (let [s (data->string input)
        s-full (str prefix-16 (quote-16 s) postfix-16)
        d (string->data s-full)]
    (cbc-encrypt random-key-16 random-iv-16 (pkcs7-pad aes-block-size d))))

(defn decrypt-16 [cipher-data]
  (cbc-decrypt random-key-16 random-iv-16 cipher-data))

(defn is-admin? [cipher-data]
  (let [d (decrypt-16 cipher-data)
        s-full (data->string d)]
    (str/includes? s-full goal-string)))

; Requires some knowledge of the decrypted text, so you know what plain text to xor with
(defn cbc-bitflip []
  (let [prefix-length (count prefix-16)
        goal-bytes (string->data goal-string)
        goal-length (count goal-bytes)
        input (repeat goal-length (int 0))
        cipher-data (encrypt-16 input)
        goal-xor (xor goal-bytes input)
        goal-offset (- prefix-length aes-block-size)
        goal-cipher-data (into [] cat [(take goal-offset cipher-data)
                                       goal-xor
                                       (drop (+ goal-offset goal-length) cipher-data)])]
    (println "Input bytes")
    (pretty-print input)
    (println "Goal bytes")
    (pretty-print goal-bytes)
    (println "Goal xor")
    (pretty-print goal-xor)
    (println "Cipher data")
    (pretty-print cipher-data)
    (println "Decrypted cipher data:\n" (data->string (decrypt-16 cipher-data)))
    (pretty-print goal-cipher-data)
    (println "Decrypted goal cipher data:\n" (data->string (decrypt-16 goal-cipher-data)))
    (is-admin? goal-cipher-data)))
