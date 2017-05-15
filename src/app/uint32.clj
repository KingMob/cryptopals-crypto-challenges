(ns app.uint32
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.test :refer [deftest is testing run-tests]]))


(defn uint32 [x]
  (clojure.core/bit-and 0xFFFFFFFF x))

(defn <<
  "Shifts left, with respect to uint32"
  [x n]
  (uint32 (bit-shift-left x n)))

(defn >>>
  "Shifts right, with respect to uint32. Unsigned, so always shifts in zeros."
  [x n]
  (unsigned-bit-shift-right (uint32 x) n))

(defn >>
  "Shifts right, with respect to uint32. Signed, so shifts in top bit. Not well-defined if you pass in something outside of Integer's range."
  [x n]
  (uint32 (bit-shift-right x n)))

(def bit-not
  "Inverts bits, with respect to uint32."
  (comp uint32 (partial clojure.core/bit-not)))

(def bit-xor
  "XORs bits, with respect to uint32."
  (comp uint32 (partial clojure.core/bit-xor)))

(def bit-and
  "ANDs bits, with respect to uint32."
  (comp uint32 (partial clojure.core/bit-and)))
