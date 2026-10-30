# AWS Signature Version 4 test suite (known-answer tests)

These files are copied unchanged from AWS's published Signature Version 4 test
suite, as distributed in botocore,
<https://github.com/boto/botocore>, directory `tests/unit/auth/aws4_testsuite/`
at commit `7f517a30f80daa50e2ab84c9b1cfa073c4d8cf58`, licensed under the
Apache License 2.0 (see `LICENSE` and `NOTICE` here; Copyright Amazon.com, Inc.
or its affiliates).

Each case directory holds:

- `<case>.req`: the request;
- `<case>.creq`: the canonical request;
- `<case>.sts`: the string to sign;
- `<case>.authz`: the `Authorization` header value;
- `<case>.sreq`: the signed request.

Every case uses the access key `AKIDEXAMPLE`, the secret
`wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, the region `us-east-1` and the
service `service`. The files use CRLF line endings; the test reads them with
LF, which is what SigV4 hashes. `TestSigV4Suite` in the parent directory runs
every case. The tests never contact AWS.
