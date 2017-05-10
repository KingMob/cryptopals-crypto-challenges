(ns app.util
  (:require [byte-streams :as b]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.spec.gen :as gen]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [clojure.pprint :as pp]
            [medley.core :refer [interleave-all]]
            [taoensso.tufte :as tufte :refer [defnp p profiled profile]])
  (:import [org.apache.commons.codec.binary Base64 Hex]))

(defonce hex-re #"[0-9a-fA-F]+")
(s/def ::hex-char (s/and char? #(re-matches hex-re (str %1))))
(s/def ::hex-digits (s/and string? (partial re-matches hex-re)))
(s/def ::hex-string (s/and string? (comp even? count) ::hex-digits))
(s/def ::byte-array bytes?)
(s/def ::data (s/coll-of integer? :into []))
(s/def ::data-w-nils (s/coll-of #(or (integer? %) (nil? %))))

(defn bit-string [b]
  (let [class-name (.getName (class b))
        is-byte (= "java.lang.Byte" class-name)
        num-bits (clojure.lang.Reflector/getStaticField class-name "SIZE")
        format-string (str "~" num-bits "'0b")
        bin-str-fn #(clojure.lang.Reflector/invokeStaticMethod
                     (if is-byte "java.lang.Integer" class-name)
                     "toBinaryString"
                     (to-array [%]))
        bit-string (if is-byte
                     (str/join (take-last 8 (bin-str-fn (Byte/toUnsignedInt b))))
                     (bin-str-fn b))]
    (str (str/join (repeat (- num-bits (count bit-string)) \0))
         bit-string)))

(defn print-bits [b]
  (println (bit-string b)))

(defn hex-char->number [^Character h]
  {:pre [(s/valid? ::hex-char h)]}
  (case h
    \0 0 \1 1 \2 2 \3 3 \4 4 \5 5 \6 6 \7 7 \8 8 \9 9
    \a 10 \A 10 \b 11 \B 11 \c 12 \C 12 \d 13 \D 13 \e 14 \E 14 \f 15 \F 15))

(defn hex-byte->integer [high low]
  {:pre [(s/valid? ::hex-char high) (s/valid? ::hex-char low)]}
  (unchecked-byte (+ (* 16 (hex-char->number high)) (hex-char->number low))))

(defn hex->data [h]
  {:pre [(s/valid? ::hex-string h)]}
  (let [hex-bytes (partition 2 h)]
    (mapv (partial apply hex-byte->integer) hex-bytes)))

(defn data->bytes [d]
  {:pre [(s/valid? ::data d)]}
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
  {:pre [(s/valid? string? s)]}
  (into (vector-of :byte) (byte-streams/to-byte-array s)))

(defn hex-encode [d]
  {:pre [(s/valid? ::data d)]}
  (Hex/encodeHexString (data->bytes d)))

(defn hex-decode [s]
  {:pre [(s/valid? ::hex-string s)]}
  (bytes->data
   (Hex/decodeHex
    (.toCharArray s))))

(defn hex-decode-spaces [s]
  {:pre [(s/valid? string? s)]}
  (hex-decode (str/replace s #"\s" "")))

(defn pretty-print [d]
  {:pre [(s/valid? ::data d)]}
  (b/print-bytes (data->bytes d)))

(defn xor [d1 d2]
  {:pre [(s/valid? ::data d1)
         (s/valid? ::data d2)
         (= (count d1) (count d2))]}
  (mapv bit-xor d1 d2))

(defn xor-unequal
  "Returns the xor of the data, ignoring length differences."
  [d1 d2]
  (let [max-length (min (count d1) (count d2))]
    (xor (take max-length d1) (take max-length d2))))

(deftest xor-identity
  (let [sample-str (string->data "abc123")
        id-str (string->data (repeat (count sample-str) 0))]
    (is (= sample-str (xor sample-str id-str)))
    (is (= id-str (xor sample-str sample-str)))))

(deftest xor-neg
  (let [sample-data (repeat 5 -100)
        id-data (repeat (count sample-data) 0)]
    (is (= sample-data (xor sample-data id-data)))))

(deftest xor-equivalency
  (let [a (repeatedly 10 #(rand-int 256))
        b (repeatedly 10 #(rand-int 256))
        x (xor a b)]
    (is (= a (xor b x)))
    (is (= b (xor a x)))))

(deftest xor-commutativity
  (let [a (repeatedly 10 #(rand-int 256))
        b (repeatedly 10 #(rand-int 256))
        c (repeatedly 10 #(rand-int 256))]
    (is (= (xor a (xor b c)) (xor (xor a b) c)))))

(defn byte-fill [size b] (repeat size b))

(defn xor-with-byte-fill [d b]
  (let [key-bytes (byte-fill (count d) b)]
    (xor d key-bytes)))

(defn repeating-xor [key-bs bs]
  (xor bs (take (count bs) (cycle key-bs))))

(defn repeating-xor-str [key-str str]
  (repeating-xor (string->data key-str) (string->data str)))

(defn mean [coll]
  (/ (reduce + 0 coll) (count coll)))

(defn url-decode [s]
  {:pre [(s/valid? string? s)]}
  (->> (str/split s #"&")
       (map #(str/split % #"="))
       (into {})))

(defn url-encode [m]
  {:pre [(s/valid? map? m)]}
  (->> m
       (reduce-kv (fn [coll k v]
                    (conj coll (str k "=" v))) [])
       (str/join "&")))

(defn common-prefix-length [d1 d2]
  (let [pairs (partition 2 (interleave d1 d2))
        min-size (count pairs)
        identical-pairs (take-while (fn [[a b]]
                                      (= a b))
                                    pairs)]
    (count identical-pairs)))

(defn remove-common-prefix [[d1 d2 :as ds]]
  {:pre [(s/valid? (s/coll-of sequential? :count 2) ds)]}
  (let [pairs (partition 2 (interleave d1 d2))
        min-size (count pairs)
        divergent-pairs (drop-while (fn [[a b]]
                                      (= a b))
                                    pairs)
        d1-unique (apply conj
                         (into [] (map first) divergent-pairs) (nthrest d1 min-size))
        d2-unique (apply conj
                         (into [] (map second) divergent-pairs) (nthrest d2 min-size))]
    [d1-unique d2-unique]))

(defn transpose-all
  "A sort of combination of interleave-all and partition. Returns the first item in each collection in a collection, then the second item in each. Does not stop until it consumes all items."
  [colls]
  (let [max-length (apply max (map count colls))]
    (for [n (range max-length)]
      (->> colls
           (filter #(> (count %) n))
           (mapv #(nth % n))))))
