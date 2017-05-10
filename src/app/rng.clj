(ns app.rng
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            ;[clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [medley.core :refer [interleave-all]]
            [taoensso.tufte :as tufte :refer (defnp p profiled profile)])
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
(def ^:const lower-mask (dec (bit-shift-left 1 r)))
(def ^:const upper-mask (bit-not lower-mask))

(defn- uint32 [x]
  (bit-and 0xFFFFFFFF x))

(defn- mt-seed-i [mt i]
  (let [prev (mt (dec i))]
    (uint32 (+ (* f
                  (bit-xor prev
                           (bit-shift-right prev (- w 2))))
               i))))

(defn- mt-seed-1 [MT seed]
  (let [MT (-> MT
              (assoc :index n)
              (assoc-in [:mt 0] seed))]
    (reduce
     (fn [MT i] (assoc-in MT [:mt i] (mt-seed-i (:mt MT) i)))
     MT
     (range 1 n))))

(defn mt-seed [seed]
  (swap! MT mt-seed-1 seed))

(defn- mt-twist-1 [mt]
  (reduce
   (fn [mt i]
     (let [curr (mt i)
           next (mt (mod (inc i) n))
           x (uint32 (+ (bit-and upper-mask curr)
                        (bit-and lower-mask next)))
           x-shifted-1 (bit-shift-right x 1)
           xA (if (odd? x)
                (bit-xor x-shifted-1 a)
                x-shifted-1)
           m-index (mod (+ i m) n)]
       (assoc mt i (bit-xor (mt m-index) xA))))
   mt
   (range 0 n)))

(defn mt-twist []
  (swap! MT #(assoc %
              :mt (mt-twist-1 (:mt %))
              :index 0)))

(defn mt-extract-number []
  (let [curr-index (:index @MT)]
    (when (>= curr-index n)
      (when (> curr-index n)
        (throw (ex-info "Generator was never seeded" {:MT @MT})))
      (mt-twist))
    (let [index (:index @MT)
          result
          (as-> (get-in @MT [:mt index]) y
            (bit-xor y (bit-and (bit-shift-right y u) d))
            (bit-xor y (bit-and (bit-shift-left y s) b))
            (bit-xor y (bit-and (bit-shift-left y t) c))
            (bit-xor y (bit-shift-right y l)))]
      (swap! MT update :index inc)
      (uint32 result))))
