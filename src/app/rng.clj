(ns app.rng
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [app.uint32 :as u32 :refer [<< >>> >> uint32]]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.test :refer [deftest is testing run-tests]]
            [medley.core :refer [interleave-all]])
  (:import [org.apache.commons.math3.random MersenneTwister]))


(def ^:const w 32)
(def ^:const n 624)
(def ^:const m 397)
(def ^:const r 31)
(def ^:const f 1812433253)
(def ^:const a 0x9908B0DF)
(def ^:const u 11)
(def ^:const d 0xFFFFFFFF)
(def ^:const s 7)
(def ^:const b 0x9D2C5680)
(def ^:const t 15)
(def ^:const c 0xEFC60000)
(def ^:const l 18)



(def MT (atom {:mt (vector-of :long)
               :index (inc n)}))
(def ^:const lower-mask (dec (<< 1 r)))
(def ^:const upper-mask (u32/bit-not lower-mask))



(defn- mt-seed-i [mt i]
  (let [prev (mt (dec i))]
    (uint32 (+ (* f
                  (u32/bit-xor
                   prev
                   (>> prev (- w 2))))
               i))))

(defn mt-seed [seed]
  (swap! MT (fn [MT seed]
              (let [MT (-> MT
                           (assoc :index n)
                           (assoc-in [:mt 0] seed))]
                (reduce
                 (fn [MT i] (assoc-in MT [:mt i] (mt-seed-i (:mt MT) i)))
                 MT
                 (range 1 n))))
         seed))

(defn- mt-twist-1 [mt]
  (reduce
   (fn [mt i]
     (let [curr (mt i)
           next (mt (mod (inc i) n))
           x (uint32 (+ (u32/bit-and upper-mask curr)
                        (u32/bit-and lower-mask next)))
           x-shifted-1 (>>> x 1)
           xA (if (odd? x)
                (u32/bit-xor x-shifted-1 a)
                x-shifted-1)
           m-index (mod (+ i m) n)]
       (assoc mt i (u32/bit-xor (mt m-index) xA))))
   mt
   (range 0 n)))

(defn mt-twist []
  (swap! MT #(assoc %
              :mt (mt-twist-1 (:mt %))
              :index 0)))

(defn mt-temper [mt-val]
  (as-> (uint32 mt-val) y
    (u32/bit-xor y (u32/bit-and (>>> y u) d))
    (u32/bit-xor y (u32/bit-and (<< y s) b))
    (u32/bit-xor y (u32/bit-and (<< y t) c))
    (u32/bit-xor y (>>> y l))))

(defn mt-extract-number []
  (let [curr-index (:index @MT)]
    (when (>= curr-index n)
      (when (> curr-index n)
        (throw (ex-info "Generator was never seeded" {:MT @MT})))
      (mt-twist))
    (let [index (:index @MT)
          result
          (mt-temper (get-in @MT [:mt index]))]
      (swap! MT update :index inc)
      (uint32 result))))

(deftest compare-w-apache-commons
  (let [seed 0
        apache-mt (MersenneTwister. (int seed))]
    (mt-seed seed)
    (is (= (unchecked-int (mt-extract-number)) (.nextInt apache-mt))))
  (let [seed 5489
        apache-mt (MersenneTwister. (int seed))]
    (mt-seed seed)
    (is (= (unchecked-int (mt-extract-number)) (.nextInt apache-mt))))
  (let [seed Integer/MIN_VALUE
        apache-mt (MersenneTwister. (int seed))]
    (mt-seed seed)
    (is (= (unchecked-int (mt-extract-number)) (.nextInt apache-mt))))
  (let [seed -1000
        apache-mt (MersenneTwister. (int seed))]
    (mt-seed seed)
    (is (= (unchecked-int (mt-extract-number)) (.nextInt apache-mt)))))

(defn- shift-bit-mask [bit-shift-fn num-shift-bits num-shifts]
  (let [inverse-shift-fn (if (= bit-shift-fn <<)
                           >>>
                           <<)]
    (bit-shift-fn
     (inverse-shift-fn
      (uint32 -1) ; All the uint32 calls are because Clojure's bit ops only use Longs
      (- w num-shift-bits))
     (* num-shifts num-shift-bits))))

(deftest shift-bit-mask-test
  (testing "no shift"
    (let [num-offsets 0]
      (is (= 2r1111
             (shift-bit-mask << 4 num-offsets)))
      (is (= 2r11110000000000000000000000000000
             (shift-bit-mask >>> 4 num-offsets)))))
  (testing "1 shift"
    (let [num-offsets 1]
      (is (= 2r11110000
             (shift-bit-mask << 4 num-offsets)))
      (is (= 2r00001111000000000000000000000000
             (shift-bit-mask >>> 4 num-offsets))))))

(defn reverse-untemper-step
  ([y bit-shift-fn num-shift-bits]
   (reverse-untemper-step y bit-shift-fn num-shift-bits 0xFFFFFFFF))
  ([y bit-shift-fn num-shift-bits bit-mask]
   (let [num-repetitions (dec (int (Math/ceil (/ w num-shift-bits))))
         step-fn (fn [i y]
                   (let [part-mask (shift-bit-mask bit-shift-fn num-shift-bits i)
                         y-part (u32/bit-and y part-mask)]
                     (u32/bit-xor y
                                  (u32/bit-and
                                   (bit-shift-fn y-part num-shift-bits)
                                   bit-mask))))]
     (loop [i 0
            y y]
       (if (>= i num-repetitions)
         (uint32 y)
         (recur (inc i)
                (step-fn i y)))))))

(defn mt-untemper [mt-val]
  (as-> (uint32 mt-val) y
    (reverse-untemper-step y >>> l)
    (reverse-untemper-step y << t c)
    (reverse-untemper-step y << s b)
    (reverse-untemper-step y >>> u d)))

(deftest untemper-test
  (testing "- single shift"
    (let [l 20 ; l must be > half the num bits (e.g., 32)
          y 1145720426
          y-right (u32/bit-xor y (>>> y l))
          y-left (u32/bit-xor y (<< y l))]
      (is (= y
             (uint32 (bit-xor y-right (>>> y-right l)))))
      (is (= y
             (uint32 (bit-xor y-left (<< y-left l)))))
      (is (= y
             (uint32 (reverse-untemper-step y-left << l))))
      (is (= y
             (uint32 (reverse-untemper-step y-right >>> l))))))
  (testing "- multiple shifts - right"
    (let [w 32
          shift 7
          y-in 1145720426
          y-out (u32/bit-xor y-in (>>> y-in shift))
          y-right (u32/bit-xor y-out (>>> y-out shift))
          y-rightright (u32/bit-xor y-right (>>> y-right shift))
          y-rrr (u32/bit-xor y-rightright (>>> y-rightright shift))]
      (is (= y-in
             (uint32 (reverse-untemper-step y-out >>> shift))))))
  (testing "- multiple shifts - left"
    (let [w 32
          shift 10; with l=10, must repeat (ceil (/ w l)) = 3 times
          y-in 1145720426
          y-out (u32/bit-xor y-in (<< y-in shift))
          y-left (u32/bit-xor y-out (<< y-out shift))
          y-leftleft (u32/bit-xor y-left (<< y-left shift))]
      (is (= y-in
             (uint32 (u32/bit-xor y-leftleft (<< y-leftleft shift)))))
      (is (= y-in
             (uint32 (reverse-untemper-step y-out << shift))))))
  (testing "- multiple shifts w mask"
    (let [w 32
          shift s ;10 ; with shift=15, must repeat (ceil (/ w l)) = 2 times
          mask c
          y-in 1145720426
          y-out (u32/bit-xor y-in (u32/bit-and (<< y-in shift) mask))]
      (is (= y-in
             (uint32 (reverse-untemper-step y-out << shift mask))))))
  (testing "- negative numbers"
    (let [w 32
          shift 15
          y-in (uint32 -1000)
          y-out-l (u32/bit-xor y-in (<< y-in shift))
          y-out-r (u32/bit-xor y-in (>>> y-in shift))]
      (is (= y-in
             (uint32 (reverse-untemper-step y-out-l << shift))))
      (is (= y-in
               (uint32 (reverse-untemper-step y-out-r >>> shift))))))
  (testing "- untemper"
    (doseq [v [0 5489 Integer/MAX_VALUE -1 Integer/MIN_VALUE]]
      (is (= (unchecked-int v) (unchecked-int (mt-untemper (mt-temper v))))))))
