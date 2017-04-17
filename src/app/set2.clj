(ns app.set2
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [app.cipher :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [taoensso.tufte :as tufte :refer (defnp p profiled profile)])
  (:import [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec]))

;; Set 2, challenge 9
(= (string->data "YELLOW SUBMARINE\04\04\04\04") (pkcs7-padding 20 (string->data "YELLOW SUBMARINE")))

;; Set 2, challenge 10
(def test-key-10 (string->data "Octopus's Garden"))
(data->string (ecb-decrypt test-key-10 (ecb-encrypt test-key-10 (string->data "This be random, man"))))

(def key-10 (string->data "YELLOW SUBMARINE"))
(def input-10 (base64-decode (str/join (str/split-lines (slurp (io/file (io/resource "10.txt")))))))
(def iv-10 (repeat 16 0))

(println (data->string (cbc-decrypt key-10 iv-10 input-10)))
;; "Go white boy, go white boy, go."
;; Man, decrypting these lyrics is a real counter-incentive :)
