(ns app.util
  (:require [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.spec.gen :as gen]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [taoensso.tufte :as tufte :refer [defnp p profiled profile]])
  (:import [org.apache.commons.codec.binary Base64 Hex]))

(def hex-re #"[0-9a-fA-F]+")
(s/def ::hex-char (s/and char? #(re-matches hex-re (str %1))))
(s/def ::hex-digits (s/and string? (partial re-matches hex-re)))
(s/def ::hex-string (s/and string? (comp even? count) ::hex-digits))
(s/def ::byte-array bytes?)
(s/def ::data (s/coll-of integer? :into []))


(defn hex-char->number [^Character h]
  {:pre [(s/valid? ::hex-char h)]}
  (case h
    \0 0 \1 1 \2 2 \3 3 \4 4 \5 5 \6 6 \7 7 \8 8 \9 9
    \a 10 \A 10 \b 11 \B 11 \c 12 \C 12 \d 13 \D 13 \e 14 \E 14 \f 15 \F 15))

(defn hex-byte->integer [high low]
  {:pre [(s/valid? ::hex-char high) (s/valid? ::hex-char low)]}
  (+ (* 16 (hex-char->number high)) (hex-char->number low)))

(defn hex->data [h]
  ;;; Why int array and not bytes? Because all bytes in Java are signed.
  ;;; It's sometimes easier to work with signed ints and mask with 0xFF as needed.
  {:pre [(s/valid? ::hex-string h)]}
  (let [hex-bytes (partition 2 h)]
    (mapv (partial apply hex-byte->integer) hex-bytes)))

(defn data->bytes [d]
  {:pre [(s/valid? ::data d)]}
  #_(into-array Byte/TYPE d)
  #_(into-array Byte/TYPE (map #(.byteValue %) d))
  (byte-array d))

(defn bytes->data [bs]
  {:pre [(s/valid? ::byte-array bs)]}
  (vec (aclone bs)))

(defn base64-encode [d]
  ;;; Using Apache common-codec
  {:pre [(s/valid? ::data d)]}
  (Base64/encodeBase64String (data->bytes d)))

(defn base64-decode [s]
  ;;; Using Apache common-codec
  {:pre [(s/valid? string? s)]}
  (bytes->data (Base64/decodeBase64 s)))

(defn data->string [d]
  (str/join (map #(char (bit-and 0xFF %)) d)))

(defn string->data [s]
  (mapv int s))

(defn hex-encode [d]
  {:pre [(s/valid? ::data d)]}
  (Hex/encodeHexString (data->bytes d)))
;; (defn byte-array->hex [bs] (hex-encode bs))

(defn hex-decode [s]
  {:pre [(s/valid? ::hex-string s)]}
  (bytes->data
   (Hex/decodeHex
    (.toCharArray s))))

(defn xor [d1 d2]
  {:pre [(s/valid? ::data d1)
         (s/valid? ::data d2)
         (= (count d1) (count d2))]}
  (map bit-xor d1 d2))

(deftest xor-identity
  (let [sample-str (string->data "abc123")
        id-str (string->data (repeat (count sample-str) 0))]
    (is (= sample-str (xor sample-str id-str)))
    (is (= id-str (xor sample-str sample-str)))))

(defn byte-fill [size b] (take size (repeat b)))

(defn xor-with-byte-fill [d b]
  (let [key-bytes (byte-fill (count d) b)]
    (xor d key-bytes)))

(defn repeating-xor [key-bs bs]
  (xor bs (take (count bs) (cycle key-bs))))

(defn repeating-xor-str [key-str str]
  (repeating-xor (string->data key-str) (string->data str)))

(defn mean [coll]
  (/ (reduce + 0 coll) (count coll)))
