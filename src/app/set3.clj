(ns app.set3
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [app.cipher :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [taoensso.tufte :as tufte :refer (defnp p profiled profile)]))

;;; Set 3, challenge 17

(def tokens-17 (str/split-lines "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"))

(def key-17 (rand-aes-block)) ; hidden
(def iv-17 (rand-aes-block)) ; public (could be generated in enc-17 and returned, but this is simpler)

(defn enc-17 []
  (let [token (string->data (rand-nth tokens-17))
        d (pkcs7-pad aes-block-size token)]
    (cbc-encrypt key-17 iv-17 d)))

(defn padding-oracle-17 [iv cipher-data]
  (let [plain-data (cbc-decrypt key-17 iv cipher-data)]
    (try
      (pkcs7-unpad aes-block-size plain-data)
      true
      (catch Exception e
        false))))

(deftest padding-oracle-test
  (let [plain-data (pkcs7-pad aes-block-size (string->data "abc123"))
        good-data (cbc-encrypt key-17 iv-17 plain-data)
        bad-data (assoc good-data (dec (count good-data)) -1)]
    (is (= true (padding-oracle-17 iv-17 good-data)))
    (is (= false (padding-oracle-17 iv-17 bad-data)))))

(defn pad-oracle-decrypt-byte [pad-oracle-fn iv cipher-block cipher-byte-offset mod-bytes]
  {:pre [(s/valid? #(= aes-block-size (count %)) cipher-block)
         (s/valid? #(= aes-block-size (count %)) iv)
         (s/valid? #(< % (count cipher-block)) cipher-byte-offset)
         (s/valid? #(= cipher-byte-offset (count %)) mod-bytes)]}
  (let [block-index (- aes-block-size cipher-byte-offset 1)
        cipher-byte-to-decrypt (cipher-block block-index)
        original-byte-to-modify (iv block-index)
        original-byte-as-int (Byte/toUnsignedInt original-byte-to-modify)
        candidate-bytes (into [] cat [(range original-byte-as-int)
                                      (range (inc original-byte-as-int) 256)])
        num-candidate-bytes (count candidate-bytes)
        target-val (unchecked-byte (inc cipher-byte-offset))]
    (println "Block index:" block-index)
    (println "Target value:" target-val (bit-string target-val))
    (println "IV or prev block:")
    (pretty-print iv)
    (println "Original cipher data:")
    (pretty-print cipher-block)
    (println "Original byte to modify" (hex-encode [original-byte-to-modify]) (bit-and 0xff original-byte-to-modify) (bit-string original-byte-to-modify))
    (println "Target cipher byte" (hex-encode [cipher-byte-to-decrypt]) cipher-byte-to-decrypt (bit-string cipher-byte-to-decrypt))
    (println "Mod bytes (first):" mod-bytes)
    #_(println "num cand bytes" (count candidate-bytes))
    (loop [b-index 0]
      (if (>= b-index num-candidate-bytes)
        nil
        (let [b (unchecked-byte (candidate-bytes b-index))
              modified-iv (into [] cat [(subvec iv 0 block-index)
                                        [b]
                                        mod-bytes])
              valid-padding (padding-oracle-17 modified-iv cipher-block)]
          #_(println "Byte:" (Byte/toUnsignedInt b) (bit-string (unchecked-byte b)))
          (when (= b 0) (pretty-print modified-iv))
          (if valid-padding
            (do
              (println "Modified byte:" b (bit-string b))
              {:decrypted-bytes (bit-xor original-byte-to-modify
                                         b
                                         target-val)
               :deciphered-but-not-xored-bytes (bit-xor b target-val)})
            (recur (inc b-index))))))))

(defn pad-oracle-decrypt-block [pad-oracle-fn iv cipher-block]
  (let [offsets (vec (range 16))]

    (reduce (fn [res offset]
              (println "Current offset" offset)
              (println "Result so far" res)
              (let [byte-result
                    (pad-oracle-decrypt-byte
                     pad-oracle-fn
                     iv
                     cipher-block
                     offset
                     (mapv #(bit-xor % (inc offset))
                           (:deciphered-but-not-xored-bytes res)))]

                (println "Byte results" byte-result)
                (merge-with #(cons %2 %1) #_(partial apply conj) res byte-result)))
            {:decrypted-bytes []
             :deciphered-but-not-xored-bytes []}
            offsets)

    #_(loop [b-index 0]
      (if (> b-index num-candidate-bytes)
        nil
        (let [b (unchecked-byte (candidate-bytes b-index))
              modified-cipher-data (assoc cipher-data target-byte-index b)
              valid-padding (padding-oracle-17 iv modified-cipher-data)]
          #_(println "Byte:" b (bit-string (unchecked-byte b)))
          #_(pretty-print modified-cipher-data)
          (if valid-padding
            (do
              (println "Byte:" b (bit-string b))
              (bit-xor target-cipher-byte
                       b
                       (unchecked-byte 1)))
            (recur (inc b-index))))))))
