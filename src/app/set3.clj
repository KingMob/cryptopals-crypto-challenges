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
                                      (range (inc original-byte-as-int) 256)
                                      [original-byte-to-modify]]) ; original byte is last, becuase if it deciphers to real PKCS padding, it's probably not 1
        num-candidate-bytes (count candidate-bytes)
        target-val (unchecked-byte (inc cipher-byte-offset))]
    (loop [b-index 0]
      (if (>= b-index num-candidate-bytes)
        (throw (ex-info "Didn't find a byte" {:block-index block-index
                                              :cipher-block cipher-block
                                              :iv iv
                                              :cipher-byte-offset cipher-byte-offset}))
        (let [b (unchecked-byte (candidate-bytes b-index))
              modified-iv (into [] cat [(subvec iv 0 block-index)
                                        [b]
                                        mod-bytes])
              valid-padding (padding-oracle-17 modified-iv cipher-block)]
          (if valid-padding
            {:decrypted-bytes (bit-xor original-byte-to-modify
                                       b
                                       target-val)
             :deciphered-but-not-xored-bytes (bit-xor b target-val)}
            (recur (inc b-index))))))))

(defn pad-oracle-decrypt-block [pad-oracle-fn iv cipher-block]
  (let [offsets (vec (range 16))]
    (reduce
     (fn [res offset]
       (let [byte-result
             (pad-oracle-decrypt-byte
              pad-oracle-fn
              iv
              cipher-block
              offset
              (mapv #(bit-xor % (inc offset))
                    (:deciphered-but-not-xored-bytes res)))]
         (merge-with #(cons %2 %1) res byte-result)))
     {:decrypted-bytes []
      :deciphered-but-not-xored-bytes []}
     offsets)))

(defn pad-oracle-decrypt [pad-oracle-fn]
  (let [initial-iv iv-17
        cipher-data (enc-17)
        cipher-blocks (map vec (partition aes-block-size cipher-data))
        ivs (into [] cat [[initial-iv] (butlast cipher-blocks)])]
    (pkcs7-unpad aes-block-size
                 (vec
                  (:decrypted-bytes
                   (apply merge-with concat
                          (map (partial pad-oracle-decrypt-block pad-oracle-fn)
                               ivs
                               cipher-blocks)))))))

(data->string (pad-oracle-decrypt padding-oracle-17))


;;; Set 3, challenge 18

(def cipher-data-18 (base64-decode "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))
(def key-18 (string->data "YELLOW SUBMARINE"))

(data->string (ctr-crypt 0 key-18 cipher-data-18))
;;; All right stop, Collaborate and listen
