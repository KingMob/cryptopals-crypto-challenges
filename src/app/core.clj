(ns app.core
  (:require [clojure.spec :as s]
            [clojure.test :as t])
  (:import org.apache.commons.codec.binary.Base64))

(def hex-re #"[0-9a-fA-F]+")
(s/def ::hex-char (s/and char? #(re-matches hex-re (str %1))))
(s/def ::hex-digits (s/and string? (partial re-matches hex-re)))

(s/def ::hex-string (s/and string? (comp even? count) ::hex-digits))

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
  ;;; It's actually easier to work with signed ints and mask with 0xFF as needed.
  {:pre [(s/valid? ::hex-string h)]}
  (let [hex-bytes (partition 2 h)]
    (mapv (partial apply hex-byte->integer) hex-bytes)))

(defn hex->byte-array [^String h]
  {:pre [(s/valid? ::hex-string h)]}
  (byte-array (hex->int-vector h)))

(defn base64-encode [^bytes bs]
  {:pre [(s/valid? bytes? bs)]}
  (Base64/encodeBase64String bs))

(= "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" (base64-encode (hex->byte-array "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")))