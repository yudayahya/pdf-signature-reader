const forge = require('node-forge');
const VerifyPDFError = require('./VerifyPDFError');
const {
  extractSignature,
  getMessageFromSignature,
  getClientCertificate,
  checkForSubFilter,
  preparePDF,
  authenticateSignature,
  sortCertificateChain,
  isCertsExpired,
} = require('./helpers');
const { extractCertificatesDetails } = require('./certificateDetails');

const verify = (signature, signedData, signatureMeta) => {
  const message = getMessageFromSignature(signature);
  const {
    certificates,
    rawCapture: {
      signature: sig,
      authenticatedAttributes: attrs,
      digestAlgorithm,
    },
  } = message;
  const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
  const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toLowerCase();
  const clientCertificate = getClientCertificate(certificates);
  const dataDigest = forge.md[hashAlgorithm]
    .create()
    .update(signedData.toString('latin1'))
    .digest()
    .getBytes();
  const sortedCerts = sortCertificateChain(certificates);
  const parsedCerts = extractCertificatesDetails(sortedCerts);
  const authenticity = authenticateSignature(sortedCerts);
  const expired = isCertsExpired(sortedCerts);
  if (!attrs) {
    // No signed attributes (RFC 5652 §5.4): the signature is computed directly
    // over the content digest, so verifying it also verifies the integrity
    let integrity;
    try {
      integrity = clientCertificate.publicKey.verify(dataDigest, sig);
    } catch (e) {
      integrity = false;
    }
    return ({
      verified: integrity && authenticity && !expired,
      authenticity,
      integrity,
      expired,
      meta: { certs: parsedCerts, signatureMeta },
    });
  }
  const set = forge.asn1.create(
    forge.asn1.Class.UNIVERSAL,
    forge.asn1.Type.SET,
    true,
    attrs,
  );
  const digest = forge.md[hashAlgorithm]
    .create()
    .update(forge.asn1.toDer(set).data)
    .digest()
    .getBytes();
  const validAuthenticatedAttributes = clientCertificate.publicKey.verify(digest, sig);
  if (!validAuthenticatedAttributes) {
    throw new VerifyPDFError(
      'Wrong authenticated attributes',
      VerifyPDFError.VERIFY_SIGNATURE,
    );
  }
  const messageDigestAttr = forge.pki.oids.messageDigest;
  const fullAttrDigest = attrs
    .find((attr) => forge.asn1.derToOid(attr.value[0].value) === messageDigestAttr);
  const attrDigest = fullAttrDigest.value[1].value[0].value;
  const integrity = dataDigest === attrDigest;
  return ({
    verified: integrity && authenticity && !expired,
    authenticity,
    integrity,
    expired,
    meta: { certs: parsedCerts, signatureMeta },
  });
};

module.exports = (pdf) => {
  const pdfBuffer = preparePDF(pdf);
  checkForSubFilter(pdfBuffer);
  try {
    const { signatureStr, signedData, signatureMeta } = extractSignature(pdfBuffer);

    const signatures = signedData.map((signed, index) => {
      return (verify(signatureStr[index], signed, signatureMeta[index]));
    })

    return {
      verified: signatures.every(o => o.verified === true),
      authenticity: signatures.every(o => o.authenticity === true),
      integrity: signatures.every(o => o.integrity === true),
      expired: signatures.some(o => o.expired === true),
      signatures
    };
  } catch (error) {
    return ({ verified: false, message: error.message, error });
  }
};
