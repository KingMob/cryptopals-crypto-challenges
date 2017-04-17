(ns app.set1
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

;; Set 1, challenge 1
(= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" (app.util/base64-encode (hex->data "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))

;; Set 1, challenge 2
(let [d1 (hex->data "1c0111001f010100061a024b53535009181c")
      d2 (hex->data "686974207468652062756c6c277320657965")
      xords (xor d1 d2)
      res (hex-encode xords)]
  (= "746865206b696420646f6e277420706c6179" res))


;; Set 1, challenge 3
(let [xor-chars (range 32 127)
      cipher-hex "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
      cipher-data (hex->data cipher-hex)]
  #_(most-likely-xor-byte cipher-data)
  (->> (chi2-results xor-chars cipher-data)
       (sort-by :chi2)
       (first)))

;; Set 1, challenge 4
(let [xor-chars (range 32 127)
      lines (str/split-lines (slurp (io/file (io/resource "4.txt"))))]
  (->> lines
       (map hex->data)
       (mapcat (partial chi2-results xor-chars))
       (sort-by :chi2)
       (take 3)))

;; Set 1, challenge 5
(def ice-ice-baby "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
(= (hex-encode (repeating-xor-str "ICE" ice-ice-baby)) "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

;; Set 1, challenge 6
(tufte/add-basic-println-handler! {})

(= 37 (apply hamming (map string->data ["this is a test" "wokka wokka!!!"])))

(def input-6 (base64-decode (str/join (str/split-lines (slurp (io/file (io/resource "6.txt")))))))


(def sorted-hamming-key-sizes
  (sort-by
   :mean
   (hamming-key-sizes 2 41 input-6)))

(def candidate-sizes (map :size (take 3 sorted-hamming-key-sizes)))

(def input-6-candidate-keys
  (doall
   (for [ksize candidate-sizes]
     {:key-size ksize
      :most-likely-key
      (str/join
       (map char
            (doall (for [bitpos (range ksize)]
                     (->> bitpos
                          (nthrest input-6)
                          (take-nth ksize)
                          (most-likely-xor-byte))))))})))

;; But it's the wax that the Terminator X spun

;; Set 1, challenge 7
(def key-7 (string->data "YELLOW SUBMARINE"))
(def input-7 (base64-decode (str/join (str/split-lines (slurp (io/file (io/resource "7.txt")))))))

(println (data->string (ecb-decrypt key-7 input-7)))
;; Reading the output kind of makes wonder... If Suge Knight had threatened
;; Vanilla Ice more, maybe we'd have been rid of him sooner


;; Set 1, challenge 8
;; (tufte/add-basic-println-handler! {})
(def aes-block-size 16)
(def input-8
  (mapv hex-decode
        (str/split-lines (slurp (io/file (io/resource "8.txt"))))))

;; Looking for dupes works because the odds of two random blocks
;; of 16 bytes equaling each other is astronomically low
(def dupe-block-count
  (for [cipher-text input-8]
    (let [blocks (partition aes-block-size cipher-text)]
      (->> blocks
           (frequencies)
           (filter #(< 1 (second %)))
           (count)))))

(def probably-encrypted (input-8 (.indexOf dupe-block-count (apply max dupe-block-count))))

;; Unfortunately, breaking it was quite a bit harder...didn't happen
;; based on most likely xor bytes

;; (def sorted-hamming-key-sizes
;;   (sort-by
;;    :mean
;;    (hamming-key-sizes 2 41 probably-encrypted)))

;; ;; (def probable-key-sizes (map :size (take 3 sorted-hamming-key-sizes)))
;; (def probable-key-sizes [1])
;; (def probable-keys (candidate-keys probable-key-sizes probably-encrypted))

;; (def cipher (Cipher/getInstance "AES/ECB/NoPadding"))
;; (def possible-decryptions
;;   (doall
;;    (for [key probable-keys]
;;      (do
;;        #_(println (data->bytes (string->data (:most-likely-key key))))
;;        (.init cipher Cipher/DECRYPT_MODE (SecretKeySpec. (data->bytes (string->data (:most-likely-key key))) "AES"))
;;        (data->string (bytes->data (.doFinal cipher (data->bytes probably-encrypted)))))
;;      )))
