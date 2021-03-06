(ns app.set3
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [app.rng :refer :all]
            [app.cipher :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            ;[byte-streams :as bs]
            [medley.core :refer [interleave-all]]
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
    (is (true? (padding-oracle-17 iv-17 good-data)))
    (is (false? (padding-oracle-17 iv-17 bad-data)))))

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


;;; Set 3, challenge 19
(def fixed-nonce 0)
(def key-19 (rand-aes-block))
(def cipher-datas-19 (mapv
                      #(ctr-crypt fixed-nonce key-19 (base64-decode %))
                      (str/split-lines "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=")))

;;; Since the nonce was reused, every cipher byte was xored against the same byte in the keystream.
;;; This means we can analyze the bytes statistically

(let [common-cipher-bytes (filterv #(> (count (distinct %)) 1) (transpose-all cipher-datas-19))
      probable-key-stream (mapv #(unchecked-byte (most-likely-xor-byte %)) common-cipher-bytes)
      probable-decodings (mapv (partial xor-unequal probable-key-stream) cipher-datas-19)]
  (map #(println (data->string %)) probable-decodings))

;;; Man, Yeats is a way better poet than Van Winkle


;;; Set 3, challenge 20
;;; I think I was supposed to do challenge 19 by hand, but I already had the automation code...
(def cipher-datas-20 (map base64-decode (str/split-lines (slurp (io/file (io/resource "20.txt"))))))

(let [common-cipher-bytes (filterv #(> (count (distinct %)) 1) (transpose-all cipher-datas-20))
      probable-key-stream (mapv #(unchecked-byte (most-likely-xor-byte %)) common-cipher-bytes)
      probable-decodings (mapv (partial xor-unequal probable-key-stream) cipher-datas-20)]
  (map #(println (data->string %)) probable-decodings))

;;; My method works with later bytes, though the accuracy drops off, so the later bytes are likely wrong


;;; Set 3, challenge 21
;;; See rng.clj


;;; Set 3, challenge 22
(defn sleep-22 [] (Thread/sleep (* 1000 (+ 40 (rand-int 1000)))))

(defn seed-rng-22
  "Waits a while, then seeds the MT with the timestamp, then waits a bit longer and returns the first 32-bit output."
  []
  (sleep-22)
  (mt-seed (int-timestamp))
  (sleep-22)
  (mt-extract-number))

(def rng-output-22 606212249)

(defn compute-timestamp-seed [rng-output]
  (let [curr-timestamp (int-timestamp)
        oldest-timestamp (- curr-timestamp 3600) ; only search up to the last hour
        timestamps (iterate dec curr-timestamp)
        first-rng-for-seed (fn [timestamp]
                             (mt-seed timestamp)
                             (mt-extract-number))]
    (some #(if (= rng-output-22 (first-rng-for-seed %)) %) timestamps)))

;;; (compute-timestamp-seed rng-output-22)


;;; Set 3, challenge 23
;;; There are several ways to tackle inverting the MT19937 temper fn.
;;; 1. While it's implemented as a bunch of bit ops, it can be modeled as a large
;;; matrix multiplication, which is invertible.
;;; 2. Since the tempering steps involve xoring the data with altered versions
;;; of itself, we could build a constraint solver on the bits to find a solution.
;;; Not sure if that would always produce unique values, though.
;;; 3. For 32-bit MT, the various constants heavily constrain the search space. It's
;;; more than feasible to just brute-force the search for each previous datum. Not
;;; sure if that's less work than expressing the constraints in a solver, though.
;;; 4. Compute the bit ops necessary to invert. This is what most people have done,
;;; and what I'll do.

(def rand-seed-23 (rand-int Integer/MAX_VALUE))

(mt-seed rand-seed-23)
(def orig-MT @MT)

(def mt-nums
  (vec
   (for [i (range app.rng/n)]
     (mt-extract-number))))

(def untempered-mt
  (vec
   (for [i (range app.rng/n)]
     (mt-untemper (mt-nums i)))))

(= untempered-mt (@MT :mt))

(def copied-MT {:mt untempered-mt
                :index app.rng/n})

(def next-10 (repeatedly 10 mt-extract-number))
(reset! MT copied-MT)
(def predicted-10 (repeatedly 10 mt-extract-number))

(= next-10 predicted-10)

;;; Follow-up
;;; The problem is that the MT algorithm is invertible. It allows me to reproduce the
;;; MT state with at most 2n-1 outputs. I may not know what the index is, but that's
;;; just a matter of sliding a window across the untempered data until I hit on a
;;; state that reproduces the next outputs.

;;; If a slower, non-invertible transformation is used, like a hash, I shouldn't be
;;; able to reproduce the state this way.


;;; Set 3, challenge 24

(defn- mt-keystream [seed]
  {:pre [(s/valid? #(= java.lang.Short (class %)) seed)]}
  (mt-seed seed)
  (mapcat #(long-bytes % 4) (repeatedly mt-extract-number)))

(defn mt-crypt [seed d]
  (stream-crypt (mt-keystream seed) d))

(def known-plain-data-24 (string->data "AAAAAAAAAAAAAA"))
(def plain-data-24 (into [] cat [(rand-bytes (rand-int 16)) known-plain-data-24]))
(def seed-24 (unchecked-short (rand-int 65536)))
(def cipher-data-24 (mt-crypt seed-24 plain-data-24))

;;; We know there's a bunch of A's in there, and with only a
;;; 16-bit seed, we can simply run through them all
(defn recover-mt-seed [cipher-data]
  (let [num-known-bytes (count known-plain-data-24)
        num-rand-bytes (- (count plain-data-24) (count known-plain-data-24))
        plain-data (into [] cat [(repeat num-rand-bytes 0) known-plain-data-24])
        known-cipher-data (subvec cipher-data num-known-bytes)]
    (->
     (filter
      #(= known-cipher-data (subvec (second %) num-known-bytes))
      (for [i (range 65536)]
        (let [seed (unchecked-short i)]
          [seed (mt-crypt seed plain-data)])))
     (ffirst))))

(let [seed (recover-mt-seed cipher-data-24)]
  (-> seed
      (short)
      (mt-crypt cipher-data-24)
      (data->string)))

(def password-timestamp-known-data (repeat 20 0))
(def password-reset-token (mt-crypt (unchecked-short (int-timestamp)) password-timestamp-known-data))

(defn check-password-token [token]
  (let [timestamp (int-timestamp)
        hour-ago-timestamp (- timestamp 3600)
        timestamps-to-check (range hour-ago-timestamp timestamp)]
    (->
     (filter
      #(= token (second %))
      (for [i timestamps-to-check]
        (let [seed (unchecked-short i)]
          [seed (mt-crypt seed password-timestamp-known-data)])))
     (ffirst))))

(check-password-token password-reset-token)
;;; This last bit seems a bit odd... how is it different from just
;;; using the MT as the token? But several solutions online all
;;; thought the same thing. There's no plaintext being encrypted, really
