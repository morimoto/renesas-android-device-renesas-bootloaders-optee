#!/usr/bin/env python
#
# Copyright (c) 2015, 2017, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

def uuid_parse(s):
    from uuid import UUID
    return UUID(s)


def int_parse(str):
    return int(str, 0)


def get_args():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('--uuid', required=True,
                        type=uuid_parse, help='UUID of TA')
    parser.add_argument('--version', type=int_parse, default=0, help='Version')
    parser.add_argument('--key', required=True, help='Name of key file')
    parser.add_argument('--in', required=True, dest='inf',
                        help='Name of in file')
    parser.add_argument('--out', required=True, help='Name of out file')
    return parser.parse_args()


def main():
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
    import struct

    args = get_args()

    f = open(args.key, 'rb')
    key = RSA.importKey(f.read())
    f.close()

    f = open(args.inf, 'rb')
    img = f.read()
    f.close()

    signer = PKCS1_v1_5.new(key)
    h = SHA256.new()

    digest_len = h.digest_size
    sig_len = len(signer.sign(h))
    img_size = len(img)

    magic = 0x4f545348    # SHDR_MAGIC
    img_type = 1        # SHDR_BOOTSTRAP_TA
    algo = 0x70004830    # TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
    shdr = struct.pack('<IIIIHH',
                       magic, img_type, img_size, algo, digest_len, sig_len)
    shdr_uuid = args.uuid.bytes
    shdr_version = struct.pack('<I', args.version)

    h.update(shdr)
    h.update(shdr_uuid)
    h.update(shdr_version)
    h.update(img)
    sig = signer.sign(h)

    f = open(args.out, 'wb')
    f.write(shdr)
    f.write(h.digest())
    f.write(sig)
    f.write(shdr_uuid)
    f.write(shdr_version)
    f.write(img)
    f.close()


if __name__ == "__main__":
    main()
