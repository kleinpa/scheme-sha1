(library (sha1)
  (export
   sha1-hash)
  (import
   (rnrs))

  ;; convert number to bytevector based on its length
  (define (number->bytevector x)
    (let* ([bytes (ceiling (/ (bitwise-length x) 8))]
           [bv (make-bytevector bytes)])
      (do ([n 0 (+ 1 n)]) ((<= bytes n) bv)
        (bytevector-u8-set! bv (- bytes 1 n) (bitwise-bit-field x (* 8 n) (* 8 (+ 1 n)))))))

  ;; convert numbers and strings to bytevectors
  (define (->bytevector x)
    (cond
     [(bytevector? x) x]
     [(string? x) (string->utf8 x)]
     [(number? x) (number->bytevector x)]))

  ;; shortcuts for using a bytevector of 32-bit numbers
  (define (make-bv-u32 n) (make-bytevector (* 4 n)))
  (define (bv-u32 . xs) (uint-list->bytevector xs 'big 4))
  (define (bv-u32-ref bv n) (bytevector-u32-ref bv (* n 4) 'big))
  (define (bv-u32-set! bv n v)
    (bytevector-u32-set! bv (* n 4) v 'big))
  (define (->32 n) (bitwise-and n #xffffffff))

  (define (build-merkle-damgard md-pad md-init md-size md-compress md-finalize)
    (lambda (msg)
      (let ([msg (md-pad (->bytevector msg))])
        (do ([block-start 0 (+ block-start md-size)]
             [state md-init (md-compress state msg block-start)])
            ((>= block-start (bytevector-length msg))
             (md-finalize state))))))

  ;; calculate the sha1 hash of a bytevector, string, or number
  (define sha1-hash
    (let ()
      (define (sha1-pad msg)
        (let* ([length (bytevector-length msg)]
               [pad (make-bytevector (* 64 (ceiling (/ (+ length 9) 64))) 0)])
          (bytevector-copy! msg 0 pad 0 length)
          (bytevector-u8-set! pad length #b10000000)
          (bytevector-u64-set! pad (- (bytevector-length pad) 8) (* 8 length) 'big)
          pad))
      (define (sha1-finalize h)
        (mod (bitwise-ior
              (bitwise-arithmetic-shift (bv-u32-ref h 0) 128)
              (bitwise-arithmetic-shift (bv-u32-ref h 1) 96)
              (bitwise-arithmetic-shift (bv-u32-ref h 2) 64)
              (bitwise-arithmetic-shift (bv-u32-ref h 3) 32)
              (bv-u32-ref h 4))
             (expt 2 160)))
      (define sha1-initial-state (bv-u32 #x67452301 #xEFCDAB89 #x98BADCFE #x10325476 #xC3D2E1F0))
      (define (sha1-compress state msg start)
        (let ([w (make-bv-u32 80)])
          ;; build sequence
          (bytevector-copy! msg start w 0 64)
          ;; generate w[16]..w[79]
          (do ([i 16 (+ i 1)]) ((= i 80))
            (bv-u32-set! w i
                         (bitwise-rotate-bit-field
                          (bitwise-xor
                           (bv-u32-ref w (- i 3))
                           (bv-u32-ref w (- i 8))
                           (bv-u32-ref w (- i 14))
                           (bv-u32-ref w (- i 16))) 0 32 1)))
          ;; main loop
          (let loop ([i 0]
                     [a (bv-u32-ref state 0)]
                     [b (bv-u32-ref state 1)]
                     [c (bv-u32-ref state 2)]
                     [d (bv-u32-ref state 3)]
                     [e (bv-u32-ref state 4)])
            (let ([f (cond
                      [(<= i 19) (bitwise-if b c d)]
                      [(<= i 39) (bitwise-xor b c d)]
                      [(<= i 59) (bitwise-if (bitwise-xor c d) b c)]
                      [(<= i 79) (bitwise-xor b c d)])]
                  [k (cond
                      [(<= i 19) #x5A827999]
                      [(<= i 39) #x6ED9EBA1]
                      [(<= i 59) #x8F1BBCDC]
                      [(<= i 79) #xCA62C1D6])])
              (if (< i 80)
                  (let ([a (->32 (+ (bitwise-rotate-bit-field a 0 32 5) f e k (bv-u32-ref w i)))]
                        [b a]
                        [c (bitwise-rotate-bit-field b 0 32 30)]
                        [d c]
                        [e d])
                    (loop (+ i 1) a b c d e))
                  ;; done with iterations
                  (bv-u32 (->32 (+ a (bv-u32-ref state 0)))
                          (->32 (+ b (bv-u32-ref state 1)))
                          (->32 (+ c (bv-u32-ref state 2)))
                          (->32 (+ d (bv-u32-ref state 3)))
                          (->32 (+ e (bv-u32-ref state 4)))))))))
      (build-merkle-damgard sha1-pad sha1-initial-state 64 sha1-compress sha1-finalize)))

  )
