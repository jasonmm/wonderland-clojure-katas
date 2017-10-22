(ns alphabet-cipher.coder
  (:require [clojure.string :as str]))

;;; ## Encoding
;;;
;;; The position number of the plain text letter plus the position number of the
;;; keyword letter minus 1.
;;;
;;; Example,
;;;  plain text: meetmebythetree
;;;  keyword: scones
;;;  'm' is the first letter of the plain text at position 13
;;;  's' is the first letter of the keyword at position 19
;;;  so 12 + 18 + 1 = 31 => 'e'
;;;
;;; ## Decoding
;;;
;;; The absolute value of the position number of the ciphertext letter
;;; (after the position of the keyword letter) minus the position number of
;;; the keyword letter (after the ciphertext letter) plus 1.
;;;
;;; Example,
;;;  ciphertext: egsgqwtahuiljgs
;;;  keyword: scones
;;;  'n' is the keyword letter and is at position 14
;;;  'g' is the ciphertext letter and is at position 33 (we have to use the 'g' after the 'n')
;;;  so 33 - 14 + 1 = 20 => abs(20) => 't'

;;                      1111111111222222222233333333334
;;             1234567890123456789012345678901234567890
(def alphabet "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz")

(defn letter-at-pos
  "Get the letter in `alphabet` at `position`."
  [position]
  (subs alphabet (dec position) position))

(defn repeat-str
  "Returns `s` repeated over and over and truncated to length `len`."
  [s len]
  (let [repetitions (Math/ceil (/ len (count s)))
        repeated-s  (->> s
                         (repeat repetitions)
                         str/join)]
    (->> len
         (subs repeated-s 0)
         vec)))

(defn encode-letter
  "Given a keyword letter and a corresponding plaintext letter return the
  ciphertext letter."
  [[keyword-letter plaintext-letter]]
  (let [keyword-letter-pos   (str/index-of alphabet keyword-letter)
        plaintext-letter-pos (str/index-of alphabet plaintext-letter)]
    (->> (+ keyword-letter-pos plaintext-letter-pos)
         inc
         letter-at-pos)))

(defn decode-letter
  "Given a keyword letter and corresponding ciphertext letter return the
  plaintext letter."
  [[keyword-letter ciphertext-letter]]
  (let [keyword-letter-pos    (str/index-of alphabet keyword-letter)
        ciphertext-letter-pos (str/index-of alphabet
                                            ciphertext-letter
                                            keyword-letter-pos)]
    (->> (- ciphertext-letter-pos keyword-letter-pos)
         inc
         Math/abs
         letter-at-pos)))

(defn pair-letters
  "Returns a seq of vectors where each vector contains one letter from the
  keyword and the matching letter from the message.
  Example: keyword = 'scones', message = 'meetme' => returns ([s m] [c e] [o e]...)"
  [keyword message]
  (map vector (repeat-str keyword (count message)) (vec message)))

(defn process
  "Processes the keyword and message strings using the `map-letter-fn` to
  decode or encode each letter."
  [keyword message map-letter-fn]
  (str/join (map map-letter-fn (pair-letters keyword message))))

(defn get-first-repetition
  "Returns the first sequence in a string of repeating sequences.
  Example: s = 'runrunrun' will return 'run'."
  [s]
  (loop [n 1]
    (let [s1 (take n s)
          s2 (take n (drop n s))]
      (if (= s1 s2)
        s1
        (recur (inc n))))))

(defn decipher-map-fn
  "Given a `ciphertext-letter` and a `plaintext-letter` return the corresponding
  keyword letter."
  [[ciphertext-letter plaintext-letter]]
  (let [diff (- (str/index-of alphabet ciphertext-letter) (str/index-of alphabet plaintext-letter))]
    (if (> 0 diff)
      (letter-at-pos (inc (+ 26 diff)))
      (letter-at-pos (inc diff)))))

(defn encode [keyword message]
  "Encode `message` using the alphabet ciper with `keyword` as the keyword."
  (process keyword message encode-letter))

(defn decode [keyword message]
  "Decode `message` using the alphabet ciper with `keyword` as the keyword."
  (process keyword message decode-letter))

(defn decipher [cipher message]
  "Return the keyword given cipertext and plaintext. This assumes that the message is longer than the keyword."
  (let [letter-pairs (map vector cipher message)]
    (str/join (get-first-repetition (str/join (map decipher-map-fn letter-pairs))))))
