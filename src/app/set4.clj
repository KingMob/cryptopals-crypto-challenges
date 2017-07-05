(ns app.set4
  (:require [app.core :refer :all]
            [app.util :refer :all]
            [app.rng :refer :all]
            [app.cipher :refer :all]
            [clojure.spec :as s]
            [clojure.spec.test :as stest]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            #_[medley.core :refer [interleave-all]]
            #_[taoensso.tufte :as tufte :refer (defnp p profiled profile)]))


;;; Set 4, challenge 25
(def key-25 (string->data "YELLOW SUBMARINE"))
(def input-25 (base64-decode (str/join (str/split-lines (slurp (io/file (io/resource "7.txt")))))))

(def plain-data-25 (pkcs7-unpad aes-block-size (ecb-decrypt key-25 input-25)))
(def key-25 (rand-aes-block))
(def cipher-data-25 (ctr-crypt key-25 plain-data-25))

(defn edit-25 [cipher-data key offset new-plain-data]
  (let [keystream (ctr-keystream key)
        plain-data-length (count new-plain-data)
        window-key-stream (take plain-data-length (drop offset keystream))]
    (into [] cat [(subvec cipher-data 0 offset)
                  (stream-crypt window-key-stream new-plain-data)
                  (subvec cipher-data (+ offset plain-data-length))])))

(defn public-edit-25 [cipher-data offset new-plain-data]
  (edit-25 cipher-data key-25 offset new-plain-data))

(let [cipher-data-length (count cipher-data-25)
      new-plain-data (vec (repeat cipher-data-length (byte \A)))
      offset 0
      edited-cipher-data (public-edit-25 cipher-data-25 offset new-plain-data)
      orig-plain-data (reduce xor [edited-cipher-data
                                   cipher-data-25
                                   new-plain-data])]
  (println (data->string orig-plain-data)))

;;; Using CTR to encrypt a filesystem creates the problem that any given byte
;;; is being XORed the same way, since there's no chaining/feedback. You know
;;; what the encrypted contents are, so if you overwrite any file with chosen
;;; plaintext, you can decrypt the original with simple XORing. It's effectively
;;; key/nonce reuse.
