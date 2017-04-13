(ns app.set1
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.java.io :as io]
            [clojure.string :as str]))

;; Set 1, challenge 1
(= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" (base64-encode (hex->data "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))

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
(= 37 (apply hamming (map string->data ["this is a test" "wokka wokka!!!"])))

(def input-6 (base64-decode (str/join (str/split-lines (slurp (io/file (io/resource "6.txt")))))))

(defn avg-auto-hamming [d size num-blocks]
  {:pre [(s/valid? :app.util/data d)]}
  (mean
   (let [block-data (take (* size num-blocks) d)
         blocks (partition size block-data)]
     (map normalized-hamming (drop-last blocks) (rest blocks)))))

(def sorted-hamming-key-sizes
  (sort-by
   :mean
   (for [k (range 2 41)]
     {:size k
      :initial (float (normalized-hamming
                       (take k input-6)
                       (take k (nthrest input-6 k))))
      :mean (float (avg-auto-hamming input-6 k 4))})))

(def candidate-sizes (map :size (take 3 sorted-hamming-key-sizes)))

(def candidate-keys
  (doall
   (for [ksize candidate-sizes]
     {:key-size ksize
      :most-likely-key
      (str/join
       (map char
            (for [bitpos (range ksize)]
              (->> bitpos
                   (nthrest input-6)
                   (take-nth ksize)
                   (most-likely-xor-byte)))))})))
