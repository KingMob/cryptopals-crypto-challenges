(ns app.util
  (:require [clojure.spec :as s]
            [clojure.string :as str])
  (:import [org.apache.commons.codec.binary Base64 Hex]))

(def hex-re #"[0-9a-fA-F]+")
(s/def ::hex-char (s/and char? #(re-matches hex-re (str %1))))
(s/def ::hex-digits (s/and string? (partial re-matches hex-re)))
(s/def ::hex-string (s/and string? (comp even? count) ::hex-digits))
(s/def ::byte-array bytes?)

(defn hex-char->number [^Character h]
  {:pre [(s/valid? ::hex-char h)]}
  (case h
    \0 0 \1 1 \2 2 \3 3 \4 4 \5 5 \6 6 \7 7 \8 8 \9 9
    \a 10 \A 10 \b 11 \B 11 \c 12 \C 12 \d 13 \D 13 \e 14 \E 14 \f 15 \F 15))

(defn hex-byte->integer [^Character high ^Character low]
  {:pre [(s/valid? ::hex-char high) (s/valid? ::hex-char low)]}
  (+ (* 16 (hex-char->number high)) (hex-char->number low)))

(defn hex->int-vector [^String h]
  ;;; Why int array and not bytes? Because all bytes in Java are signed.
  ;;; It's sometimes easier to work with signed ints and mask with 0xFF as needed.
  {:pre [(s/valid? ::hex-string h)]}
  (let [hex-bytes (partition 2 h)]
    (mapv (partial apply hex-byte->integer) hex-bytes)))

(defn hex->byte-array [^String h]
  {:pre [(s/valid? ::hex-string h)]}
  (byte-array (hex->int-vector h)))

(defn base64-encode [^bytes bs]
  ;;; Using Apache common-codec because I don't feel'
  {:pre [(s/valid? ::byte-array bs)]}
  (Base64/encodeBase64String bs))

(defn byte-array->string [bs]
  (str/join (map #(char (bit-and 0xFF %)) bs)))

(defn string->byte-array [s]
  (byte-array (map byte s)))

(defn hex-encode [^bytes bs]
  {:pre [(s/valid? ::byte-array bs)]}
  (Hex/encodeHexString bs))
(defn byte-array->hex [^bytes bs] (hex-encode bs))

(defn xor [bs1 bs2]
  {:pre [(s/valid? ::byte-array bs1)
         (s/valid? ::byte-array bs2)
         (= (count bs1) (count bs2))]}
  (byte-array (map bit-xor bs1 bs2)))

(def byte-fill (memoize (fn [size b] (byte-array size b))))

(defn xor-with-byte-fill [bs b]
  (let [key-bytes (byte-fill (count bs) b)]
    (xor bs key-bytes)))

(defn repeating-xor [key-bs bs]
  (xor bs (byte-array (take (count bs) (cycle key-bs)))))

(defn repeating-xor-str [key-str str]
  (repeating-xor (string->byte-array key-str) (string->byte-array str)))

(defn mean [coll]
  (/ (reduce + 0 coll) (count coll)))
