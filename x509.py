import OpenSSL
import utils
import datetime


class X509:
    """Decodes x509 certificates"""

    def __init__(self, x509):
        self.x509 = x509

    @classmethod
    def from_pem(cls, pem_cert):
        """Initialise CSR from a PEM encoded CSR"""

        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, pem_cert)
        return cls(x509)

    @classmethod
    def from_binary(cls, binary_cert):
        """Initialise CSR from a binary CSR"""

        x509 = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_ASN1, binary_cert)
        return cls(x509)


    def to_openssl(self):
        text = OpenSSL.crypto.dump_certificate(\
                OpenSSL.crypto.FILETYPE_TEXT, \
               self.x509)
        return text

    def get_not_after_str(self):
        not_after = datetime.datetime.strptime(
            self.x509.get_notAfter().decode('utf-8'),
            "%Y%m%d%H%M%SZ"
        )
        return not_after.strftime('%d, %b %Y %H:%M:%S')

    def has_expired(self):
        """Returns True if certificate expired and False otherwise"""
        return self.x509.has_expired()

    def get_days_to_expiry(self):
        not_after = datetime.datetime.strptime(
            self.x509.get_notAfter().decode('utf-8'),
            "%Y%m%d%H%M%SZ"
        )
        expire_in = not_after - datetime.datetime.now()
        return expire_in.days

    def get_signature_alg(self):
        """Returns the algorithm used to sign the certificate"""
        return self.x509.get_signature_algorithm().decode('utf-8')

    def get_key_size(self):
        """Returns the size of the key"""
        return self.x509.get_pubkey().bits()

    def get_pubkey_alg(self):
        """Get the public key algorithm

        First try to get the algorithm using the PyOpenSSL
        API; if that is unsuccessful, try parsing it from
        the OpenSSL output.
        """

        key_alg = self.get_pubkey_alg_via_api()
        if "UNKNOWN" in key_alg or "ERROR" in key_alg:
            key_alg = self.get_pubkey_alg_from_openssl_output()
            if b"ecPublicKey" in key_alg:
                key_alg = "EC"
        return key_alg

    def get_pubkey_alg_via_api(self):
        """Get the public key algorithm using PyOpenSSL"""

        try:
            pk = self.x509.get_pubkey()
            type = pk.type()
        except:
            return "ERROR"

        # PyOpenSSL does not yet have a type for EC
        # so google certs, for example, will be UNKNOWN
        types = {
            OpenSSL.crypto.TYPE_RSA: "RSA",
            OpenSSL.crypto.TYPE_DSA: "DSA",
        }
        return types.get(type, "UNKNOWN")

    def get_pubkey_alg_from_openssl_output(self):
        """Get the public key algorithm by parsing OpenSSL output"""

        openssl_output = self.to_openssl()
        return utils.get_pubkey_alg_from_openssl_output(openssl_output)

    @property
    def cn(self):
        """Returns the CN from the subject if present"""

        c = None
        for rdn in self.subject:
            if rdn[0] == b"CN":
                c = rdn[1]
        return c

    @property
    def subject(self):
        """Returns the subject of the CSR"""

        return self.x509.get_subject().get_components()

    @property
    def subject_as_str(self):
        s = utils.stringify_components(self.subject)
        return utils.make_string_raw(s)

    def get_openssl_text(self):
        """Returns the OpenSSL output for the CSR"""

        text = OpenSSL.crypto.dump_certificate(
            OpenSSL.crypto.FILETYPE_TEXT,
            self.x509)
        return text
