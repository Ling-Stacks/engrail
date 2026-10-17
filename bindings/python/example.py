#!/usr/bin/env python3
"""Python bindings demo: full activation lifecycle + SM2 from Python.

    ./configure --enable-shared && make      # build libactivation.so
    python3 bindings/python/example.py
    python3 bindings/python/example.py <activation-code>
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))
from activation import Activation  # noqa: E402

# Demo deployment (public values from `engrail-keygen keygen`).
PUBKEY = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
DSALT = "00" * 32


def main():
    act = Activation(PUBKEY, DSALT, product_id=1)

    print("machine code :", act.machine_code())
    print("sm3('abc')   :", Activation.sm3(b"abc").hex()[:32], "...")

    # SM2 national crypto from Python
    priv, pub = Activation.sm2_keypair()
    msg = b"hello SM2 from python"
    sig = act.sm2_sign(priv, msg)
    print("sm2 sign/ver :", "ok" if act.sm2_verify(pub, msg, sig) else "FAIL")
    ct = act.sm2_encrypt(pub, b"secret")
    print("sm2 enc/dec  :", act.sm2_decrypt(priv, ct) == b"secret")

    # License lifecycle (needs a real code for this deployment)
    state = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "demo_state.act")
    if len(sys.argv) > 1:
        st, info = act.verify_code(sys.argv[1])
        print("code check   :", st.text, info or "")
        if st:
            print("activate     :", act.activate(sys.argv[1], state).text)
    st = act.verify_saved(state)
    print("saved state  :", st.text)


if __name__ == "__main__":
    main()
