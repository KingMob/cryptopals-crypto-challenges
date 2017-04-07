(ns app.core
  (:require [app.util :refer :all]
            [clojure.spec :as s]
            [clojure.string :refer [upper-case lower-case]]
            [medley.core :refer [map-vals]]))

(s/def ::probability (s/and number? #(<= 0 %) #(<= % 1)))
(s/def ::hist (s/map-of char? number?))
(s/def ::letter-hist (s/map-of char? ::probability))

(defn normalized-frequencies
  ([hist]
   {:pre [(s/valid? ::hist hist)]}
   (normalized-frequencies hist (reduce-kv (fn [total k v] (+ total v)) 0 hist)))
  ([hist total]
   {:pre [(s/valid? number? total)]}
   (map-vals #(/ % total) hist)))

(defn letter-frequency [hist]
  ;;; Lowercases all letters and removes non-letters
  {:pre [(s/valid? ::hist hist)]}
  (filter-keys Character/isLetter hist))

(def en-letter-probabilities
  (normalized-frequencies {\e 12.02 \t 9.10 \a 8.12 \o 7.68 \i 7.31 \n 6.95 \s 6.28 \r 6.02 \h 5.92 \d 4.32 \l 3.98 \u 2.88 \c 2.71 \m 2.61 \f 2.30 \y 2.11 \w 2.09 \g 2.03 \p 1.82 \b 1.49 \v 1.11 \k 0.69 \x 0.17 \q 0.11 \j 0.10 \z 0.07}))

(defn chi2-for-letter [c num-c num-total-chars]
  {:pre [(s/valid? char? c) (s/valid? number? num-c)]}
  (let [c-prob (en-letter-probabilities c 0.01)
        expected-num-c (* c-prob num-total-chars)]
    (/ (* (- num-c expected-num-c) (- num-c expected-num-c))
       expected-num-c)))

(defn chi2 [hist]
  {:pre [(s/valid? ::hist hist)]}
  (let [num-total-chars (reduce-kv (fn [total k v] (+ total v)) 0 hist)]
    (reduce-kv (fn [X2 k v]
                 (+ X2 (chi2-for-letter k v num-total-chars)))
               0
               hist)))

(defn xor-with-byte-fill [bs b]
  (let [key-bytes (byte-array (count bs) b)]
    (xor bs key-bytes)))

;;; Set 1, challenge 3
(let [alphabet "abcdefghijklmnopqrstuvwxyz"
      xor-chars (str alphabet (upper-case alphabet))
      cipher-text "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
      cipher-bytes (hex->byte-array cipher-text)]
  (for [c xor-chars]
    (let [res (xor-with-byte-fill cipher-bytes (byte c))
          res-string (byte-array->string res)
          hist (frequencies res-string)]
      ;; (byte-array->string res)
      [res-string (chi2 hist)])))
