(ns app.set1
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [clojure.java.io :as io]
            [clojure.string :as str]))

;; Set 1, challenge 1
(= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" (base64-encode (hex->byte-array "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))

;; Set 1, challenge 2
(let [bs1 (hex->byte-array "1c0111001f010100061a024b53535009181c")
      bs2 (hex->byte-array "686974207468652062756c6c277320657965")
      xorbs (xor bs1 bs2)
      res (hex-encode xorbs)]
  (= "746865206b696420646f6e277420706c6179" res))


;; Set 1, challenge 3
(let [xor-chars (byte-array (range 32 127))
      cipher-hex "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
      cipher-bytes (hex->byte-array cipher-hex)]
  (->> (chi2-results xor-chars cipher-bytes)
       (sort-by second)
       (first)))

;; Set 1, challenge 4
(let [xor-chars (byte-array (range 32 127))
      lines (str/split-lines (slurp (io/file (io/resource "4.txt"))))]
  (->> lines
       (map hex->byte-array)
       (mapcat (partial chi2-results xor-chars))
       (sort-by second)
       (take 3)))

;; Set 1, challenge 5
(def ice-ice-baby "Burning 'em, if you ain't quick and nimble
  I go crazy when I hear a cymbal")
(= (byte-array->hex (repeating-xor-str "ICE" ice-ice-baby)) "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

;; Set 1, challenge 6
(= 37 (hamming "this is a test" "wokka wokka!!!"))

(def input-6 (str/join (str/split-lines (slurp (io/file (io/resource "6.txt"))))))

(defn avg-auto-hamming [s size num-blocks]
  (mean
   (map (fn [block]
          (let [s1 (subs s (* size block) (* size (inc block)))
                s2 (subs s (* size (inc block)) (* size (+ 2 block)))]
            (normalized-hamming s1 s2)))
        (range 0 num-blocks))))

(def sorted-hamming-key-sizes
  (sort-by
   #(nth % 2)
   (for [k (range 2 41)]
     [k (float (normalized-hamming (subs input-6 0 k) (subs input-6 k (* 2 k)))) (float (avg-auto-hamming input-6 k 4))])))

(def candidate-sizes (map first (take 4 sorted-hamming-key-sizes)))
