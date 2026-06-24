;;
;; Linux Kernel Coding Style.
;;
;; C/C++ is formatted with clang-format (.clang-format); Perl with perltidy
;; (.perltidyrc). The mode settings below keep Emacs editing consistent with
;; both: 8-column, tab-based indentation and a 100 column fill.
;;
((nil . ((indent-tabs-mode . t)
         (fill-column . 100)
         (tab-width . 8)))
 (c-mode . ((c-file-style . "linux")
            (c-basic-offset . 8)))
 (c++-mode . ((c-file-style . "linux")
              (c-basic-offset . 8)))
 (cperl-mode . ((cperl-indent-level . 8)
                (cperl-continued-statement-offset . 8)
                (cperl-close-paren-offset . -8)
                (cperl-indent-parens-as-block . t)
                (cperl-tab-always-indent . t)))
 (perl-mode . ((perl-indent-level . 8)
               (perl-continued-statement-offset . 8)
               (perl-continued-brace-offset . 0)
               (perl-brace-offset . 0)
               (perl-label-offset . -8))))
