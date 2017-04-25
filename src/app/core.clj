(ns app.core
  (:require [app.util :refer :all]
            [app.cipher :refer :all]
            [clojure.spec :as s]
            [clojure.string :as str :refer [upper-case lower-case]]
            [medley.core :refer [filter-keys map-vals map-keys]]
            [taoensso.tufte :as tufte :refer (defnp p profiled profile)]))

(s/def ::probability (s/and number? #(<= 0 %) #(<= % 1)))
(s/def ::hist (s/map-of char? number?))
(s/def ::uniform-hist (s/map-of number? number?))
(s/def ::letter-hist (s/map-of char? ::probability))

(defn normalized-frequencies
  ([hist]
   {:pre [(s/valid? ::hist hist)]}
   (normalized-frequencies hist (reduce-kv (fn [total k v] (+ total v)) 0 hist)))
  ([hist total]
   {:pre [(s/valid? number? total)]}
   (map-vals #(/ % total) hist)))

(def en-letter-probabilities
  (normalized-frequencies {\space 18.29 \e 10.27 \t 7.51 \a 6.53 \o 6.16 \i 5.67 \n 5.71 \s 5.32 \r 4.99 \h 4.98 \l 3.32 \d 3.28 \u 2.28 \c 2.23 \m 2.03 \f 1.98 \w 1.07 \g 1.62 \p 1.50 \y 1.43 \b 1.26 \v 0.80 \k 0.56 \x 0.14 \j 0.10 \q 0.08 \z 0.05 \. 1.39 \, 1.35 \" 0.68 \- 0.48 \' 0.36 \? 0.14 \! 0.10 \; 0.09 \: 0.06}))

(defn chi2-for-letter [c num-c num-total-chars]
  {:pre [(s/valid? char? c)
         (s/valid? pos-int? num-c)
         (s/valid? (s/and pos-int? #(< num-c %)) num-total-chars)]}
  (let [c-prob (en-letter-probabilities c 0.001) ; Non-existent letters cannot have 0 probability
        expected-num-c (* c-prob num-total-chars)]
    (/ (* (- num-c expected-num-c) (- num-c expected-num-c))
       expected-num-c)))

(defn chi2 [hist]
  {:pre [(s/valid? ::hist hist)]}
  (let [total (reduce + (vals hist))]
    (reduce-kv
     (fn [X2 k v] (+ X2 (chi2-for-letter k v total)))
     0
     hist)))

(def num-possible-bytes 256)
(defn chi2-uniform-byte-results [hist]
  {:pre [(s/valid? ::uniform-hist hist)]}
  (let [total (reduce + (vals hist))
        exp (double (/ total num-possible-bytes))]                ; expected count
    {
     :chi2 (reduce
            (fn [X2 b]
              (let [v (hist b 0)]
                (+ X2 (/ (* (- v exp) (- v exp)) exp))))
            0
            (map unchecked-byte (range num-possible-bytes)))
     :df (dec num-possible-bytes)}))

(defn chi2-results [bytes-to-xor cipher-data]
  {:pre [(s/valid? :app.util/data bytes-to-xor)
         (s/valid? :app.util/data cipher-data)]}
  (doall (for [c bytes-to-xor]
           (let [res (p :xor-w-byte-fill (xor-with-byte-fill cipher-data c))
                 res-string (data->string res)
                 hist (frequencies (str/lower-case res-string))]
             {:xor-result res-string
              :chi2 (chi2 hist)
              :char c}))))

(def xor-search-bytes (concat (range 32 127) (range 0 31) (range 128 255))) ; Starts with printable chars

(defn most-likely-xor-byte [d]
  (p :most-likely-xor-byte
     (:char
      (p :min-key (apply min-key :chi2 (chi2-results xor-search-bytes d))))))

(defn hamming [d1 d2]
  #_{:pre [(s/valid? :app.util/data d1)
         (s/valid? :app.util/data d2)
         (= (count d1) (count d2))]}
  (reduce
   +
   0
   (map #(Long/bitCount %)
         (map bit-xor d1 d2))))

(s/fdef hamming
        :args (s/and (s/cat :d1 :app.util/data :d2 :app.util/data)
                     #(= (count (:d1 %)) (count (:d2 %))))
        :ret nat-int?
        :fn #(<= :ret (count (-> % :args :d1))))


(defn normalized-hamming [d1 d2]
  (/ (hamming d1 d2) (count d1)))


(defn avg-auto-hamming [d size num-blocks]
  {:pre [(s/valid? :app.util/data d)]}
  (mean
   (let [block-data (take (* size num-blocks) d)
         blocks (partition size block-data)]
     (map normalized-hamming (drop-last blocks) (rest blocks)))))

(def default-mean-num-hamming-blocks 4)

(defn hamming-key-sizes [kmin kmax input]
  {:pre [(s/valid? :app.util/data input) (s/valid? pos-int? kmin) (s/valid? pos-int? kmax) (s/valid? < kmin kmax)]}
  (for [k (range kmin kmax)]
    {:size k
     :initial (float (normalized-hamming
                      (take k input)
                      (take k (nthrest input k))))
     :mean (float (avg-auto-hamming
                   input
                   k
                   (min default-mean-num-hamming-blocks (/ (count input) k))))}))

(defn sorted-hamming-key-sizes
  ([kmin kmax input]
   (sorted-hamming-key-sizes kmin kmax input :mean))
  ([kmin kmax input metric]
   (sort-by
    metric
    (hamming-key-sizes kmin kmax input))))

(defn candidate-keys [ksizes input]
  (vec
   (for [ksize ksizes]
     {:key-size ksize
      :most-likely-key
      (str/join
       (map char
            (doall (for [bitpos (range ksize)]
                     (->> bitpos
                          (nthrest input)
                          (take-nth ksize)
                          (most-likely-xor-byte))))))})))

(defn dupe-block-counts
  ([cipher-data] (dupe-block-counts cipher-data 2 16))
  ([cipher-data bsize] (dupe-block-counts cipher-data bsize bsize))
  ([cipher-data bmin bmax]
   (for [bsize (range bmin (inc bmax))]
     [bsize (transduce (map dec) + (vals
                                    (frequencies (partition bsize cipher-data))))])))

(defn num-dupe-blocks
  [cipher-data bsize]
  ((first (dupe-block-counts cipher-data bsize)) 1))

(defn block-size-w-most-dupes
 [cipher-data]
 (->> cipher-data
      (dupe-block-counts)
      (apply max-key second)
      (first)))

(defn rand-bytes [n]
  (vec (repeatedly n #(unchecked-byte (rand-int 256)))))

(defn rand-aes-block []
  (rand-bytes aes-block-size))

(defn encryption-oracle [d]
  {:pre [(s/valid? :app.util/data d)]}
  (let [k (rand-aes-block)
        iv (rand-aes-block)
        pre-padding (rand-bytes (+ 5 (rand-int 6)))
        post-padding (rand-bytes (+ 5 (rand-int 6)))
        plain-data (into [] cat [pre-padding d post-padding])]
    (if (zero? (rand-int 2))
      {:mode :ecb :cipher-data (ecb-encrypt k plain-data)}
      {:mode :cbc :cipher-data (cbc-encrypt k iv plain-data)})))

(def ^:private all-bytes (vec (map unchecked-byte (range 256))))
(defn last-byte-map
  [input-block enc-oracle-fn bsize]
  (into {}
        (for [b all-bytes]
          (let [d (vec
                   (enc-oracle-fn
                    (into [] cat [input-block [b]])))]
            [(subvec d 0 bsize) b]))))

(defn decrypt-byte [pad-bytes decrypted-bytes enc-oracle-fn range-min range-max]
  {:pre [(s/valid? :app.util/data pad-bytes)
         (s/valid? :app.util/data-w-nils decrypted-bytes)
         (s/valid? nat-int? range-min)
         (s/valid? nat-int? range-max)
         (> range-max range-min)]}
  (let [input-block (concat pad-bytes decrypted-bytes)
        bmap (last-byte-map input-block enc-oracle-fn (- (inc range-max) range-min))
        #_cipher-data #_(:cipher-data (enc-oracle-fn pad-bytes))
        cipher-data (enc-oracle-fn pad-bytes)]
    (bmap (subvec cipher-data range-min (inc range-max)))))

(defn decrypt-block [enc-oracle-fn initial-input-block [range-min range-max]]
  (let [bsize (- (inc range-max) range-min)]
    (loop [input-block initial-input-block
           block-plain-data []]
      (let [next-byte (decrypt-byte input-block block-plain-data enc-oracle-fn range-min range-max)
            block-plain-data (conj block-plain-data next-byte)]
        (if (and next-byte (seq input-block))
          (recur (rest input-block) block-plain-data)
          (filter some? block-plain-data))))))

(defn decrypt-secret [enc-oracle-fn]
  (let [bsize aes-block-size
        initial-padding (vec (repeat bsize (byte 0)))
        ;cipher-data (:cipher-data (enc-oracle-fn []))
        cipher-data (enc-oracle-fn [])
        secret-length (count cipher-data)
        num-blocks (int (Math/ceil (/ secret-length
                                      bsize)))
        block-ranges (for [i (range num-blocks)] [(* i bsize) (dec (* (inc i) bsize))])]
    #_(println cipher-data)
    (drop (count initial-padding)
          (reduce (fn [decrypted-bytes block-range]
                    (apply conj decrypted-bytes
                           (decrypt-block enc-oracle-fn (take-last (dec bsize) decrypted-bytes) block-range)))
                  initial-padding
                  block-ranges
                  ))))
