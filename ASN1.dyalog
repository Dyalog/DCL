:Namespace ASN1

    :section Variables
⍝ === VARIABLES ===

    BITSTRING←0 0 3
    BMPSTR←0 0 30
    BOOLEAN←0 0 1
    CLASS_APPLICATION←1
    CLASS_CONTEXT←2
    CLASS_PRIVATE←3
    CLASS_UNIVERSAL←0
    EMBEDDED_PDV←0 0 11
    ENUMERATED←0 0 10
    EOC←,⊂3⍴0
    EXTERNAL←0 1 8
    FALSE←0
    FORM_CONSTRUCTED←1
    FORM_PRIMITIVE←0
    GENERALIZEDTIME←0 0 24
    GENERALSTR←0 0 27
    GRAPHICSTR←0 0 25
    IA5STR←0 0 22
    INTEGER←0 0 2
    NULLTAG←,⊂0 0 5
    NUMERICSTR←0 0 18
    OBJDESCRIPTOR←0 0 7
    OCTETSTRING←0 0 4
    OID←0 0 6
    OidTab←665 4⍴(0 2 262 1 10 7 20) 'id-isismtt-at-nameDistinguisher' 'Name distinguisher' 'Unterscheidungsnummer' (0 2 262 1 10 12 0) 'id-isismtt-at-liabilityLimitationFlag' 'Liability limitation flag' 'Haftungsbeschränkungs-Kennzeichen' (0 4 0 127 0 7) 'bsi-de' '' '' (0 4 0 127 0 7 3) 'bsi-de-applications' '' '' (0 4 0 127 0 7 3 1) 'bsi-de-MRTD' '' '' (0 4 0 127 0 7 3 1 5) 'bsi-de-id-DefectList' '' '' (0 4 0 127 0 7 3 1 5 1) 'bsi-de-id-certificateDefect' '' '' (0 4 0 127 0 7 3 1 5 1) 'bsi-de-id-certificateDefect' '' '' (0 4 0 127 0 7 3 1 5 1 1) 'bsi-de-id-certRevoked' '' '' (0 4 0 127 0 7 3 1 5 1 2) 'bsi-de-id-certReplaced' '' '' (0 4 0 127 0 7 3 1 5 2) 'bsi-de-id-personalizationDefect' '' '' (0 4 0 127 0 7 3 1 5 2 1) 'bsi-de-id-DGMalformed' '' '' (0 4 0 127 0 7 3 1 5 2 2) 'bsi-de-id-SODInvalid' '' '' (0 4 0 127 0 7 3 2) 'bsi-de-eID' '' '' (0 4 0 127 0 7 3 2 2) 'bsi-de-id-BlackList' '' '' (0 9 2342 19200300 100 1 1) 'userID' 'User ID' 'User-ID' (0 9 2342 19200300 100 1 25) 'id-domainComponent' 'DC' 'DC' (1 2 752 34 2 1) 'id-seis-pe-cn' '' '' (1 2 840 10040 2 1) 'holdinstruction-none' '' '' (1 2 840 10040 2 2) 'holdinstruction-callissuer' '' '' (1 2 840 10040 2 3) 'holdinstruction-reject' '' '' (1 2 840 10040 4 1) 'dsa' 'DSA' 'DSA' (1 2 840 10040 4 3) 'dsaWithSha1' 'sha1DSA' 'sha1DSA' (1 2 840 10045 1) 'fieldType' '' '' (1 2 840 10045 1 1) 'prime-field' '' '' (1 2 840 10045 1 2) 'characteristic-two-field' '' '' (1 2 840 10045 1 2 1) 'characteristic-two-field-gnBasis' '' '' (1 2 840 10045 1 2 2) 'characteristic-two-field-tpBasis' '' '' (1 2 840 10045 1 2 3) 'characteristic-two-field-ppBasis' '' '' (1 2 840 10045 1 2 3 1) 'characteristic-two-field-ppBasis-gnBasis' '' '' (1 2 840 10045 1 2 3 2) 'characteristic-two-field-ppBasis-tpBasis' '' '' (1 2 840 10045 1 2 3 3) 'characteristic-two-field-ppBasis-ppBasis' '' '' (1 2 840 10045 2) 'id-public-key-type' '' '' (1 2 840 10045 2 1) 'ecPublicKey' '' '' (1 2 840 10045 3) 'curves' '' '' (1 2 840 10045 3 0) 'curves-characteristicTwo' '' '' (1 2 840 10045 3 1) 'prime' '' '' (1 2 840 10045 4) 'signatures' '' '' (1 2 840 10045 4 1) 'ecdsa-with-SHA1' '' '' (1 2 840 10045 4 2) 'ecdsa-with-Recommended' '' '' (1 2 840 10045 4 3) 'ecdsa-with-SHA2' '' '' (1 2 840 10045 4 3 1) 'ecdsa-with-SHA224' '' '' (1 2 840 10045 4 3 2) 'ecdsa-with-SHA256' '' '' (1 2 840 10045 4 3 3) 'ecdsa-with-SHA384' '' '' (1 2 840 10045 4 3 4) 'ecdsa-with-SHA512' '' '' (1 2 840 10046 2 1) 'dhPublicNumber' 'DH' 'DH' (1 2 840 113533 7) 'nsn' '' '' (1 2 840 113533 7 65) 'nsn-ce' '' '' (1 2 840 113533 7 65 0) 'entrustVersInfo' '' '' (1 2 840 113533 7 66) 'nsn-alg' '' '' (1 2 840 113533 7 66 3) 'cast3CBC' '' '' (1 2 840 113533 7 66 10) 'cast5CBC' '' '' (1 2 840 113533 7 66 11) 'cast5MAC' '' '' (1 2 840 113533 7 66 12) 'pbeWithMD5AndCAST5-CBC' '' '' (1 2 840 113533 7 67) 'nsn-oc' '' '' (1 2 840 113533 7 67 12) 'entrustUser' '' '' (1 2 840 113533 7 68) 'nsn-at' '' '' (1 2 840 113533 7 68 0) 'entrustCAInfo' '' '' (1 2 840 113533 7 68 10) 'nsn-attributeCertificate' '' '' (1 2 840 113549 1 1) 'pkcs-1' '' '' (1 2 840 113549 1 1 1) 'pkcs-1-rsaEncryption' 'RSA Encryption' 'RSA Verschlüsselung' (1 2 840 113549 1 1 2) 'pkcs-1-md2WithRSAEncryption' 'MD2 with RSA Encryption' 'MD2 mit RSA Verschlüsselung' (1 2 840 113549 1 1 3) 'pkcs-1-md4WithRSAEncryption' 'MD4 with RSA Encryption' 'MD4 mit RSA Verschlüsselung' (1 2 840 113549 1 1 4) 'pkcs-1-md5WithRSAEncryption' 'MD5 with RSA Encryption' 'MD5 mit RSA Verschlüsselung' (1 2 840 113549 1 1 5) 'pkcs-1-sha1WithRSAEncryption' 'SHA1 with RSA Encryption' 'SHA1 mit RSA Verschlüsselung' (1 2 840 113549 1 1 6) 'pkcs-1-rsaOAEPEncryptionSET' 'OAEP Encryption Set' 'OAEP Verschlüsselungssatz' (1 2 840 113549 1 1 7) 'pkcs-1-id-RSAES-OAEP' 'RSAES Optimal Asymetric Encryption Padding' '' (1 2 840 113549 1 1 8) 'pkcs-1-id-mgf1' 'Mask Generation Function' '' (1 2 840 113549 1 1 9) 'pkcs-1-id-id-pSpecified' 'Encoding Parameters Explicitly Specified' '' (1 2 840 113549 1 3) 'pkcs-3' '' '' (1 2 840 113549 1 3 1) 'pkcs-3-dhKeyAgreement' 'DH' 'DH' (1 2 840 113549 1 5) 'pkcs-5' '' '' (1 2 840 113549 1 5 1) 'pkcs-5-pbeWithMD2AndDES-CBC' '' '' (1 2 840 113549 1 5 3) 'pkcs-5-pbeWithMD5AndDES-CBC' '' '' (1 2 840 113549 1 5 4) 'pkcs-5-pbeWithMD2AndRC2-CBC' '' '' (1 2 840 113549 1 5 6) 'pkcs-5-pbeWithMD5AndRC2-CBC' '' '' (1 2 840 113549 1 5 9) 'pkcs-5-pbeWithMD5AndXOR' '' '' (1 2 840 113549 1 5 10) 'pkcs-5-pbeWithSHA1AndDES-CBC' '' '' (1 2 840 113549 1 5 11) 'pkcs-5-pbeWithSHA1AndRC2-CBC' '' '' (1 2 840 113549 1 5 12) 'pkcs-5-id-PBKDF2' '' '' (1 2 840 113549 1 5 13) 'pkcs-5-id-PBES2' '' '' (1 2 840 113549 1 5 14) 'pkcs-5-id-PBMAC1' '' '' (1 2 840 113549 1 7) 'pkcs-7' '' '' (1 2 840 113549 1 7 1) 'pkcs-7-data' '' '' (1 2 840 113549 1 7 2) 'pkcs-7-signedData' '' '' (1 2 840 113549 1 7 3) 'pkcs-7-envelopedData' '' '' (1 2 840 113549 1 7 4) 'pkcs-7-signedAndEnvelopedData' '' '' (1 2 840 113549 1 7 5) 'pkcs-7-digestData' '' '' (1 2 840 113549 1 7 6) 'pkcs-7-encryptedData' '' '' (1 2 840 113549 1 9) 'pkcs-9' '' '' (1 2 840 113549 1 9 1) 'pkcs-9-at-emailAddress' 'Email address' 'Email-Adresse' (1 2 840 113549 1 9 2) 'pkcs-9-at-unstructuredName' 'Unstructured name' 'Unstrukturierter Name' (1 2 840 113549 1 9 3) 'pkcs-9-at-contentType' 'Content type' 'Inhaltstyp' (1 2 840 113549 1 9 4) 'pkcs-9-at-messageDigest' 'Message digest' 'Meldung-Digest' (1 2 840 113549 1 9 5) 'pkcs-9-at-signingTime' 'Signing time' 'Zeitpunkt der Signatur' (1 2 840 113549 1 9 6) 'pkcs-9-at-counterSignature' 'Counter signature' 'Gegensignatur' (1 2 840 113549 1 9 7) 'pkcs-9-at-challengePassword' 'Challenge password' 'Kennwort in Frage stellen' (1 2 840 113549 1 9 8) 'pkcs-9-at-unstructuredAddress' 'Unstructured address' 'Unstrukturierte Adresse' (1 2 840 113549 1 9 9) 'pkcs-9-at-extendedCertificateAttributes' 'Extended certificate attributes' 'Erweiterte Zertifikatsattribute' (1 2 840 113549 1 9 10) 'pkcs-9-at-issuerAndSerialNumber' '' '' (1 2 840 113549 1 9 11) 'pkcs-9-at-passwordCheck' '' '' (1 2 840 113549 1 9 12) 'pkcs-9-at-publicKey' '' '' (1 2 840 113549 1 9 13) 'pkcs-9-at-signingDescription' '' '' (1 2 840 113549 1 9 14) 'pkcs-9-at-extensionRequest' '' '' (1 2 840 113549 1 9 15) 'pkcs-9-at-smimeCapabilities' 'SMIME capabilities' 'SMIME-Funktionen' (1 2 840 113549 1 9 15 1) 'pkcs-9-preferSignedData' 'prefer signed data' 'Signierte Daten bevorzugen' (1 2 840 113549 1 9 15 2) 'pkcs-9-canNotDecryptAny' '' '' (1 2 840 113549 1 9 15 3) 'pkcs-9-receiptRequest' '' '' (1 2 840 113549 1 9 15 4) 'pkcs-9-receipt' '' '' (1 2 840 113549 1 9 15 5) 'pkcs-9-contentHints' '' '' (1 2 840 113549 1 9 15 6) 'pkcs-9-mlExpansionHistory' '' '' (1 2 840 113549 1 9 16) 'smime' 'S/MIME (RFC 2633)' 'S/MIME (RFC 2633)' (1 2 840 113549 1 9 16 2 14) 'id-signatureTimeStampToken' 'Signature Timestamp attribute' 'Signatur Zeitstempel Attribut' (1 2 840 113549 1 9 20) 'pkcs-9-at-friendlyName' '' '' (1 2 840 113549 1 9 21) 'pkcs-9-at-localKeyId' '' '' (1 2 840 113549 1 9 22) 'pkcs-9-certTypes' 'Certificate types defined in PKCS#12' 'Zertifikats-Typen definiert in PKCS#12' (1 2 840 113549 1 9 22 1) 'pkcs-9-certType-x509Certificate' '' '' (1 2 840 113549 1 9 22 2) 'pkcs-9-certType-sdsiCertificate' '' '' (1 2 840 113549 1 9 23) 'pkcs-9-crlTypes' 'CRL types defined in PKCS#12' 'CRL-Typen definiert in PKCS#12' (1 2 840 113549 1 9 23 1) 'pkcs-9-crlType-x509CRL' '' '' (1 2 840 113549 1 9 24 1) 'pkcs-9-oc-pkcsEntity' '' '' (1 2 840 113549 1 9 24 2) 'pkcs-9-oc-naturalPerson' '' '' (1 2 840 113549 1 9 25 1) 'pkcs-9-at-pkcs15Token' '' '' (1 2 840 113549 1 9 25 2) 'pkcs-9-at-encryptedPrivateKeyInfo' '' '' (1 2 840 113549 1 9 25 3) 'pkcs-9-at-randomNonce' '' '' (1 2 840 113549 1 9 25 4) 'pkcs-9-at-sequenceNumber' '' '' (1 2 840 113549 1 9 25 5) 'pkcs-9-at-pkcs7PDU' '' '' (1 2 840 113549 1 9 25 6) 'pkcs-9-at-allegedContentType' '' '' (1 2 840 113549 1 9 26 1) 'pkcs-9-sx-pkcs9String' '' '' (1 2 840 113549 1 9 26 2) 'pkcs-9-sx-signingTime' '' '' (1 2 840 113549 1 9 27 1) 'pkcs-9-mr-caseIgnoreMatch' '' '' (1 2 840 113549 1 9 27 2) 'pkcs-9-mr-signingTimeMatch' '' '' (1 2 840 113549 1 12) 'pkcs-12' '' '' (1 2 840 113549 1 12 1) 'pkcs-12PbeIds' '' '' (1 2 840 113549 1 12 1 1) 'pkcs-12-pbeWithSHAAnd128BitRC4' '' '' (1 2 840 113549 1 12 1 2) 'pkcs-12-pbeWithSHAAnd40BitRC4' '' '' (1 2 840 113549 1 12 1 3) 'pkcs-12-pbeWithSHAAnd3-KeyTripleDES-CBC' '' '' (1 2 840 113549 1 12 1 4) 'pkcs-12-pbeWithSHAAnd2-KeyTripleDES-CBC' '' '' (1 2 840 113549 1 12 1 5) 'pkcs-12-pbeWithSHAAnd128BitRC2-CBC' '' '' (1 2 840 113549 1 12 1 6) 'pkcs-12-pbewithSHAAnd40BitRC2-CBC' '' '' (1 2 840 113549 1 12 10 1) 'pkcs-12-bagtypes' '' '' (1 2 840 113549 1 12 10 1 1) 'pkcs-12-keyBag' '' '' (1 2 840 113549 1 12 10 1 2) 'pkcs-12-pkcs8ShroudedKeyBag' '' '' (1 2 840 113549 1 12 10 1 3) 'pkcs-12-certBag' '' '' (1 2 840 113549 1 12 10 1 4) 'pkcs-12-crlBag' '' '' (1 2 840 113549 1 12 10 1 5) 'pkcs-12-secretBag' '' '' (1 2 840 113549 1 12 10 1 6) 'pkcs-12-safeContentsBag' '' '' (1 2 840 113549 1 15 3 1) 'pkcs15-ct-PKCS15Token' '' '' (1 2 840 113549 2) 'digestAlgorithm' '' '' (1 2 840 113549 2 2) 'digestAlgorithm-md2' 'MD2' 'MD2' (1 2 840 113549 2 4) 'digestAlgorithm-md4' 'MD4' 'MD4' (1 2 840 113549 2 5) 'digestAlgorithm-md5' 'MD5' 'MD5' (1 2 840 113549 2 7) 'digestAlgorithm-id-hmacWithSHA1' 'hmacSHA1' 'hmacSHA1' (1 2 840 113549 2 8) 'digestAlgorithm-id-hmacWithSHA224' 'hmacSHA224' 'hmacSHA224' (1 2 840 113549 2 9) 'digestAlgorithm-id-hmacWithSHA256' 'hmacSHA256' 'hmacSHA256' (1 2 840 113549 2 10) 'digestAlgorithm-id-hmacWithSHA384' 'hmacSHA384' 'hmacSHA384' (1 2 840 113549 2 11) 'digestAlgorithm-id-hmacWithSHA512' 'hmacSHA512' 'hmacSHA512' (1 2 840 113549 3) 'encryptionAlgorithm' '' '' (1 2 840 113549 3 2) 'encryptionAlgorithm-rc2CBC' 'RC2' 'RC2' (1 2 840 113549 3 3) 'encryptionAlgorithm-rc2ECB' '' '' (1 2 840 113549 3 4) 'encryptionAlgorithm-rc4' 'RC4' 'RC4' (1 2 840 113549 3 5) 'encryptionAlgorithm-rc4WithMAC' '' '' (1 2 840 113549 3 6) 'encryptionAlgorithm-DESX-CBC' '' '' (1 2 840 113549 3 7) 'encryptionAlgorithm-DES-EDE3-CBC' '3DES' '3DES' (1 2 840 113549 3 8) 'encryptionAlgorithm-RC5-CBC' '' '' (1 2 840 113549 3 9) 'encryptionAlgorithm-rc5-CBC-PAD' '' '' (1 2 840 113549 3 10) 'encryptionAlgorithm-desCDMF' '' '' (1 2 840 113556 4 3) 'microsoftExcel' '' '' (1 2 840 113556 4 4) 'titledWithOID' '' '' (1 2 840 113556 4 5) 'microsoftPowerPoint' '' '' (1 3 6 1 2 1 2 2 1 3) 'ifType' '' '' (1 3 6 1 2 1 10) 'transmission' '' '' (1 3 6 1 2 1 10 23) 'transmission.ppp' '' '' (1 3 6 1 2 1 27) 'application' '' '' (1 3 6 1 2 1 28) 'mta' '' '' (1 3 6 1 4 1 311) 'ms' '' '' (1 3 6 1 4 1 311 2 1 4) 'ms-spcIndirectDataContext' '' '' (1 3 6 1 4 1 311 2 1 10) 'ms-spcSpecifiedAgencyInfo' '' '' (1 3 6 1 4 1 311 2 1 11) 'ms-spcStatementType' '' '' (1 3 6 1 4 1 311 2 1 12) 'ms-spcSpecifiedOpusInfo' '' '' (1 3 6 1 4 1 311 2 1 14) 'ms-spcCertExtensions' '' '' (1 3 6 1 4 1 311 2 1 15) 'ms-spcPeImageData' '' '' (1 3 6 1 4 1 311 2 1 18) 'ms-spcRawFileData' '' '' (1 3 6 1 4 1 311 2 1 19) 'ms-spcStructuredStorageData' '' '' (1 3 6 1 4 1 311 2 1 20) 'ms-spcJavaClassData' '' '' (1 3 6 1 4 1 311 2 1 21) 'ms-spcIndividualSpecialKeyPurpose' '' '' (1 3 6 1 4 1 311 2 1 22) 'ms-spcCommercialSpecialKeyPurpose' '' '' (1 3 6 1 4 1 311 2 1 25) 'ms-spcCabData' '' '' (1 3 6 1 4 1 311 2 1 26) 'ms-spcMinimalCriteria' '' '' (1 3 6 1 4 1 311 2 1 27) 'ms-spcFinancialCriteria' '' '' (1 3 6 1 4 1 311 2 1 28) 'ms-spcLink' '' '' (1 3 6 1 4 1 311 2 1 29) 'ms-spcHashInfo' '' '' (1 3 6 1 4 1 311 2 1 30) 'ms-spcSipiInfo' '' '' (1 3 6 1 4 1 311 2 2 1) 'ms-spcTrustedCodesigningCaList' '' '' (1 3 6 1 4 1 311 2 2 2) 'ms-spcTrustedClientAuthCaList' '' '' (1 3 6 1 4 1 311 2 2 3) 'ms-spcTrustedServerAuthCaList' '' '' (1 3 6 1 4 1 311 3 2 1) 'ms-spcTimeStampRequest' '' '' (1 3 6 1 4 1 311 10 1) 'ms-ct-certificateTrustList' '' '' (1 3 6 1 4 1 311 10 1 1) 'ms-ct-sortedCertificateTrustList' '' '' (1 3 6 1 4 1 311 10 2) 'ms-ct-nextUpdateLocation' '' '' (1 3 6 1 4 1 311 10 3 1) 'ms-kp-ctlTrustListSigning' '' '' (1 3 6 1 4 1 311 10 3 2) 'ms-kp-timeStampSigning' '' '' (1 3 6 1 4 1 311 10 3 6) 'ms-kp-nt5Crypto' '' '' (1 3 6 1 4 1 311 12 1 1) 'ms-catalogList' '' '' (1 3 6 1 4 1 311 12 1 2) 'ms-catalogListMember' '' '' (1 3 6 1 4 1 311 12 2 1) 'ms-catalogNameValue' '' '' (1 3 6 1 4 1 311 12 2 2) 'ms-catalogMemberInfo' '' '' (1 3 6 1 4 1 311 16 4) 'ms-ol-encryptionKeyPreference' '' '' (1 3 6 1 4 1 311 17 1) 'ms-csp-cryptoServiceProvider' '' '' (1 3 6 1 4 1 311 17 2) 'ms-csp-localMachineKeyset' '' '' (1 3 6 1 4 1 311 20 1) 'ms-cer-autoEnrollCtlUsage' '' '' (1 3 6 1 4 1 311 20 2) 'ms-ce-enrollCerttype' '' '' (1 3 6 1 4 1 311 20 2 1) 'ms-ce-enrollmentAgent' '' '' (1 3 6 1 4 1 311 20 2 2) 'ms-ce-kpSmartcardLogon' '' '' (1 3 6 1 4 1 311 20 2 3) 'ms-ce-ntPrincipalName' '' '' (1 3 6 1 4 1 311 21) 'ms-ce-certSrvInfrastructure' '' '' (1 3 6 1 4 1 311 21 1) 'ms-ce-certSrvCaVersion' '' '' (1 3 6 1 4 1 311 21 2) 'ms-ce-certSrvPrevCertHash' '' '' (1 3 6 1 4 1 3029 32 1) 'cryptlibEnvelope' '' '' (1 3 6 1 4 1 3029 32 2) 'cryptlibPrivateKey' '' '' (1 3 6 1 4 1 3744) 'datev' '' '' (1 3 6 1 4 1 3761) 'he' '' '' (1 3 6 1 5 5 7) 'pkix' '' '' (1 3 6 1 5 5 7 1) 'id-pe' 'Private extension' 'Private Erweiterungen' (1 3 6 1 5 5 7 1 1) 'id-pe-authorityInfoAccess' 'Authority info access' 'Zugriff auf Zertifizierungsstelleninformationen' (1 3 6 1 5 5 7 2) '' 'Policy qualifier Ids' 'Richtlinien-Kriterien Ids' (1 3 6 1 5 5 7 2 1) 'id-qt-cps' 'CPS' 'CPS' (1 3 6 1 5 5 7 2 2) 'id-qt-unotice' 'User notice' 'Benutzerbenachrichtigung' (1 3 6 1 5 5 7 3) 'id-kp' 'Key purpose' 'Schlüsselverwendung' (1 3 6 1 5 5 7 3 1) 'id-kp-serverAuth' 'Server authentication' 'Serverauthentifizierung' (1 3 6 1 5 5 7 3 2) 'id-kp-clientAuth' 'Client authentication' 'Clientauthentifizierung' (1 3 6 1 5 5 7 3 3) 'id-kp-codeSigning' 'Code signing' 'Codesignatur' (1 3 6 1 5 5 7 3 4) 'id-kp-emailProtection' 'Email protection' 'Sichere E-Mail' (1 3 6 1 5 5 7 3 5) 'id-kp-ipsecEndSystem' 'ipsec end system' 'IP-Sicherheitsendsystem' (1 3 6 1 5 5 7 3 6) 'id-kp-ipsecTunnel' 'ipsec tunnel' 'IP-Sicherheitstunnelabschluss' (1 3 6 1 5 5 7 3 7) 'id-kp-ipsecUser' 'ipsec user' 'IP-Sicherheitsbenutzer' (1 3 6 1 5 5 7 3 8) 'id-kp-timeStamping' 'Time stamping' 'Zeitstempel' (1 3 6 1 5 5 7 3 9) 'id-kp-OCSPSigning' 'Delegated OCSP signing' '' (1 3 6 1 5 5 7 4) 'id-it' 'Information type and Value' 'Art und Wert der Information' (1 3 6 1 5 5 7 4 1) 'id-it-caProtEncCert' 'CA protection encryption certificates' '' (1 3 6 1 5 5 7 4 2) 'id-it-signKeyPairTypes' 'Sign key pair types' '' (1 3 6 1 5 5 7 4 3) 'id-it-encKeyPairTypes' 'Encryption key pair types' '' (1 3 6 1 5 5 7 4 4) 'id-it-preferredSymmAlg' 'Preferred symmetric algorithm' '' (1 3 6 1 5 5 7 4 5) 'id-it-caKeyUpdateInfo' 'CA key update info' '' (1 3 6 1 5 5 7 4 6) 'id-it-currentCRL' 'Current CRL' '' (1 3 6 1 5 5 7 9) 'id-pda' '' '' (1 3 6 1 5 5 7 9 1) 'id-pda-dateOfBirth' 'Date of birth' 'Geburtsdatum' (1 3 6 1 5 5 7 9 2) 'id-pda-placeOfBirth' 'Place of birth' 'Geburtsort' (1 3 6 1 5 5 7 9 3) 'id-pda-gender' 'Gender' 'Geschlecht' (1 3 6 1 5 5 7 9 4) 'id-pda-countryOfCitizenship' 'Country of citizenship' 'Staatsangehörigkeit' (1 3 6 1 5 5 7 9 5) 'id-pda-countryOfResidence' 'Country of residence' 'Wohnsitz' (1 3 6 1 5 5 7 48) 'authorityInfoAccessDescriptors' '' '' (1 3 6 1 5 5 7 48 1) 'id-pkix-ocsp' 'OCSP' 'Onlinestatusprotokoll des Zertifikats' (1 3 6 1 5 5 7 48 1 1) 'id-pkix-ocsp-basic' 'Basic Response Type' '' (1 3 6 1 5 5 7 48 1 2) 'id-pkix-ocsp-nonce' 'Response to Request binding' '' (1 3 6 1 5 5 7 48 1 3) 'id-pkix-ocsp-crl' 'CRL reference' '' (1 3 6 1 5 5 7 48 1 4) 'id-pkix-ocsp-response' 'Acceptable response types OCSP client understands' '' (1 3 6 1 5 5 7 48 1 5) 'id-pkix-ocsp-nocheck' 'Trust for responder lifetime' '' (1 3 6 1 5 5 7 48 1 6) 'id-pkix-ocsp-cutoff' 'Retain revocation beyond expiration' '' (1 3 6 1 5 5 7 48 1 7) 'id-pkix-ocsp-service-locator' 'Route request to OCSP authoritative' '' (1 3 6 1 5 5 7 48 2) 'id-ad-caIssuers' 'CA issuers' 'Zertifizierungsstellenaussteller' (1 3 6 1 5 5 7 48 3) 'id-ad-timeStamping' '' '' (1 3 14 3 2 2) 'md4WitRSA' 'md4RSA' 'md4RSA' (1 3 14 3 2 3) 'md5WithRSA' 'md5RSA' 'md5RSA' (1 3 14 3 2 4) 'md4WithRSAEncryption' 'md4RSA' 'md4RSA' (1 3 14 3 2 6) 'desECB' '' '' (1 3 14 3 2 7) 'desCBC' 'DES' 'DES' (1 3 14 3 2 8) 'desOFB' '' '' (1 3 14 3 2 9) 'desCFB' '' '' (1 3 14 3 2 10) 'desMAC' '' '' (1 3 14 3 2 11) 'rsaSignature' '' '' (1 3 14 3 2 12) 'oiwDsa' 'DSA' 'DSA' (1 3 14 3 2 13) 'dsaWithSHA' ' sha1DSA' 'sha1DSA' (1 3 14 3 2 14) 'mdc2WithRSASignature' '' '' (1 3 14 3 2 15) 'shaWithRSASignature' 'shaRSA' 'shaRSA' (1 3 14 3 2 16) 'dhWithCommonModulus' '' '' (1 3 14 3 2 17) 'desEDE' '' '' (1 3 14 3 2 18) 'oiwSha' 'sha' 'sha' (1 3 14 3 2 19) 'mdc-2' '' '' (1 3 14 3 2 20) 'dsaCommon' '' '' (1 3 14 3 2 21) 'dsaCommonWithSHA' '' '' (1 3 14 3 2 22) 'rsaKeyTransport' 'RSA_KEYX' 'RSA_KEYX' (1 3 14 3 2 23) 'keyed-hash-seal' '' '' (1 3 14 3 2 24) 'md2WithRSASignature' '' '' (1 3 14 3 2 25) 'md5WithRSASignature' '' '' (1 3 14 3 2 26) 'id-sha1' 'SHA1' 'SHA1' (1 3 14 3 2 27) 'dsaWithSHA1' 'dsaSHA1' 'dsaSHA1' (1 3 14 3 2 28) 'dsaWithSHA1withCommonParameters' '' '' (1 3 14 3 2 29) 'sha-1WithRSAEncryption' 'sha1RSA' 'sha1RSA' (1 3 14 3 3 1) 'simple-strong-auth-mechanism' '' '' (1 3 14 7 2 1 1) 'ElGamal' '' '' (1 3 14 7 2 3 1) 'md2WithRSA' 'md2RSA' 'md2RSA' (1 3 14 7 2 3 2) 'md2WithElGamal' '' '' (1 3 36 3 2) 'hashAlgorithm' '' '' (1 3 36 3 2 1) 'hashAlgorithm-ripemd160' 'RIPEMD160' '' (1 3 36 3 2 2) 'hashAlgorithm-ripemd128' 'RIPEMD128' '' (1 3 36 3 2 3) 'hashAlgorithm-ripemd256' 'RIPEMD256' '' (1 3 36 3 3) 'signatureAlgorithm' '' '' (1 3 36 3 3 1) 'signatureAlgorithm-rsaSignature' '' '' (1 3 36 3 3 1 2) 'signatureAlgorithm-rsaSignatureWithripemd160' 'RIPEMD160 with RSA Encryption' 'RIPEMD160 mit RSA Verschlüsselung' (1 3 36 3 3 1 3) 'signatureAlgorithm-rsaSignatureWithripemd128' 'RIPEMD128 with RSA Encryption' 'RIPEMD128 mit RSA Verschlüsselung' (1 3 36 3 3 1 4) 'signatureAlgorithm-rsaSignatureWithripemd256' 'RIPEMD256 with RSA Encryption' 'RIPEMD256 mit RSA Verschlüsselung' (1 3 36 8 1) 'id-isismtt-cp' '' '' (1 3 36 8 1 1) 'id-isismtt-cp-sigGconform' 'SigG conform certificate' 'SigG konformes Zertifikat' (1 3 36 8 3) 'id-isismtt-at' '' '' (1 3 36 8 3 1) 'id-isismtt-at-dateOfCertGen' 'Date of certificate generation' 'Datum der Zertifikats-Generierung' (1 3 36 8 3 2) 'id-isismtt-at-procuration' 'Procuration' 'Prokura' (1 3 36 8 3 3) 'id-isismtt-at-admission' 'Admission' 'Zugangsberechtigung' (1 3 36 8 3 4) 'id-isismtt-at-monetaryLimit' 'Monetary Limit' 'Monitärer Limit' (1 3 36 8 3 5) 'id-isismtt-at-declarationOfMajority' 'Declaration of Majority' 'Volljährigkeitserklärung' (1 3 36 8 3 6) 'id-isismtt-at-iCSSN' 'ICCSN' 'ICCSN' (1 3 36 8 3 7) 'id-isismtt-at-pKReference' 'PKReference' 'PKReferenz' (1 3 36 8 3 9) 'id-isismtt-at-retrieveIfAllowed' '' '' (1 3 36 8 3 10) 'id-isismtt-at-requestedCertificate' '' '' (1 3 36 8 3 11) 'id-isismtt-at-namingAuthorities' '' '' (1 3 36 8 3 12) 'id-isismtt-at-certInDirSince' '' '' (1 3 36 8 3 13) 'id-isismtt-at-certHash' '' '' (1 3 36 8 3 14) 'id-isismtt-at-nameAtBirth' 'Maiden Name' 'Mädchenname' (2 1 0 0 0) 'CharacterModule' '' '' (2 1 0 1 0) 'NumericString' '' '' (2 1 0 1 1) 'PrintableString' '' '' (2 1 1) 'BasicEncodingRules' '' '' (2 1 2 0) 'CanonicalEncodingRules' '' '' (2 1 2 1) 'DistinguishedEncodingRules' '' '' (2 5 4 0) 'id-at-objectClass' '' '' (2 5 4 1) 'id-at-aliasedEntryName' '' '' (2 5 4 1 2) 'id-at-encryptedAliasedEntryName' '' '' (2 5 4 2) 'id-at-knowledgeInformation' 'Knowledge Information' 'Informative Daten' (2 5 4 3) 'id-at-commonName' 'Common Name' 'Name' (2,5-¯1×⎕io-⍳4) 'id-at-encryptedCommonName' 'Encrypted Common Name' 'Name verschlüsselt' (2 5 4 4) 'id-at-surname' 'Surname' 'Familienname' (2 5 4 4 2) 'id-at-encryptedSurname' 'Encrypted Surname' 'Familienname verschlüsselt' (2 5 4 5) 'id-at-serialNumber' 'Serial Number' 'Serien-Nummer' (2 5 4 5 2) 'id-at-encryptedSerialNumber' 'Encrypted Serial Number' 'Serien-Nummer verschlüsselt' (2 5 4 6) 'id-at-countryName' 'Country' 'Nation' (2 5 4 6 2) 'id-at-encryptedCountryName' 'Encrypted Country' 'Nation verschlüsselt' (2 5 4 7) 'id-at-localityName' 'Locality Name' 'Stadt' (2 5 4 7 2) 'id-at-encryptedLocalityName' 'Encrypted Locality' 'Stadt verschlüsselt' (2 5 4 7 1) 'id-at-collectiveLocalityName' 'Collective Locality' 'Sammelbegriff Stadt' (2 5 4 7 1 2) 'id-at-encryptedCollectiveLocalityName' 'Encrypted Collective Locality' 'Stadt verschlüsselt' (2 5 4 8) 'id-at-stateOrProvinceName' 'State' 'Land' (2 5 4 8 2) 'id-at-encryptedStateOrProvinceName' 'Encrypted State' 'Land verschlüsselt' (2 5 4 8 1) 'id-at-collectiveStateOrProvinceName' 'Collective State' 'Sammelbegriff Land' (2 5 4 8 1 2) 'id-at-encryptedCollectiveStateOrProvinceName' 'Encrypted Collective State' 'Sammelbegriff Land verschlüsselt' (2 5 4 9) 'id-at-streetAddress' 'Street' 'Straße' (2 5 4 9 2) 'id-at-encryptedStreetAddress' 'Encrypted Street' 'Straße verschlüsselt' (2 5 4 9 1) 'id-at-collectiveStreetAddress' 'Collective Street' 'Sammelbegriff Straße' (2 5 4 9 1 2) 'id-at-encryptedCollectiveStreetAddress' 'Encrypted Collective Street' 'Sammelbegriff Straße verschlüsselt' (2 5 4 10) 'id-at-organizationName' 'Organization' 'Betrieb' (2 5 4 10 2) 'id-at-encryptedOrganizationName' 'Encrypted Organization' 'Betrieb verschlüsselt' (2 5 4 10 1) 'id-at-collectiveOrganizationName' 'Collective Organization' 'Sammelbegriff Betrieb' (2 5 4 10 1 2) 'id-at-encryptedCollectiveOrganizationName' 'Encrypted Collective Organization' 'Sammelbegriff Betrieb verschlüsselt' (2 5 4 11) 'id-at-organizationalUnitName' 'Organizational Unit' 'Abteilung' (2 5 4 11 2) 'id-at-encryptedOrganizationalUnitName' 'Encrypted Organizational Unit' 'Abteilung verschlüsselt' (2 5 4 11 1) 'id-at-collectiveOrganizationalUnitName' 'Collective Organizational Unit' 'Sammelbegriff Abteilung' (2 5 4 11 1 2) 'id-at-encryptedCollectiveOrganizationalUnitName' 'Encrypted Collective Organizational Unit' 'Sammelbegriff Abteilung verschlüsselt' (2 5 4 12) 'id-at-title' 'Title' 'Titel' (2 5 4 12 2) 'id-at-encryptedTitle' 'Encrypted Title' 'Titel verschlüsselt' (2 5 4 13) 'id-at-description' 'Description' 'Beschreibung' (2 5 4 13 2) 'id-at-encryptedDescription' 'Encrypted Description' 'Beschreibung verschlüsselt' (2 5 4 14) 'id-at-searchGuide' 'Search Guide' 'Suchhilfe' (2 5 4 14 2) 'id-at-encryptedSearchGuide' 'Encrypted Search Guide' 'Suchhilfe verschlüsselt' (2 5 4 15) 'id-at-businessCategory' 'Business Category' 'Berufsbezeichnung' (2 5 4 15 2) 'id-at-encryptedBusinessCategory' 'Encrypted Business Category' 'Berufsbezeichnung verschlüsselt' (2 5 4 16) 'id-at-postalAddress' 'Postal Address' 'Postanschrift' (2 5 4 16 2) 'id-at-encryptedPostalAddress' 'Encrypted Postal Address' 'Postanschrift verschlüsselt' (2 5 4 16 1) 'id-at-collectivePostalAddress' 'Collective Postal Address' 'Sammelbegriff Postanschrift' (2 5 4 16 1 2) 'id-at-encryptedCollectivePostalAddress' 'Encrypted Collective Postal Address' 'Sammelbegriff Postanschrift verschlüsselt' (2 5 4 17) 'id-at-postalCode' 'Postal Code' 'Postleitzahl' (2 5 4 17 2) 'id-at-encryptedPostalCode' 'Encrypted Postal Code' 'Postleitzahl verschlüsselt' (2 5 4 17 1) 'id-at-collectivePostalCode' 'Collective Postal Code' 'Sammelbegriff Postleitzahl' (2 5 4 17 1 2) 'id-at-encryptedCollectivePostalCode' 'Encrypted Collective Postal Code' 'Sammelbegriff Postleitzahl verschlüsselt' (2 5 4 18) 'id-at-postOfficeBox' 'Post Office Box' 'Postfach' (2 5 4 18 2) 'id-at-encryptedPostOfficeBox' 'Encrypted Post Office Box' 'Postfach verschlüsselt' (2 5 4 18 1) 'id-at-collectivePostOfficeBox' 'Collective Post Office Box' 'Sammelbegriff Postfach' (2 5 4 18 1 2) 'id-at-encryptedCollectivePostOfficeBox' 'Encrypted Collective Post Office Box' 'Sammelbegriff Postfach verschlüsselt' (2 5 4 19) 'id-at-physicalDeliveryOfficeName' 'Physical Delivery Office' 'Postzustellamt' (2 5 4 19 2) 'id-at-encryptedPhysicalDeliveryOfficeName' 'Encrypted Physical Delivery Office' 'Postzustellamt verschlüsselt' (2 5 4 19 1) 'id-at-collectivePhysicalDeliveryOfficeName' 'Collective Physical Delivery Office' 'Sammelbegriff Postzustellamt' (2 5 4 19 1 2) 'id-at-encryptedCollectivePhysicalDeliveryOfficeName' 'Encrypted Collective Physical Delivery Office' 'Sammelbegriff Postzustellamt verschlüsselt' (2 5 4 20) 'id-at-telephoneNumber' 'Telephone Number' 'Telefonnummer' (2 5 4 20 2) 'id-at-encryptedTelephoneNumber' 'Encrypted Telephone Number' 'Telefonnummer verschlüsselt' (2 5 4 20 1) 'id-at-collectiveTelephoneNumber' 'Collective Telephone Number' 'Sammelbegriff Telefonnummer' (2 5 4 20 1 2) 'id-at-encryptedCollectiveTelephoneNumber' 'Encrypted Collective Telephone Number' 'Sammelbegriff Telefonnummer verschlüsselt' (2 5 4 21) 'id-at-telexNumber' 'Telex Number' 'Telexnummer' (2 5 4 21 2) 'id-at-encryptedTelexNumber' 'Encrypted Telex Number' 'Telexnummer verschlüsselt' (2 5 4 21 1) 'id-at-collectiveTelexNumber' 'Collective Telex Number' 'Sammelbegriff Telexnummer' (2 5 4 21 1 2) 'id-at-encryptedCollectiveTelexNumber' 'Encrypted Collective Telex Number' 'Sammelbegriff Telexnummer verschlüsselt' (2 5 4 22) 'id-at-teletexTerminalIdentifier' 'Teletex Terminal Identifier' 'Teletex Terminal Identifikation' (2 5 4 22 2) 'id-at-encryptedTeletexTerminalIdentifier' 'Encrypted Teletex Terminal Identifier' 'Teletex Terminal Identifikation verschlüsselt' (2 5 4 22 1) 'id-at-collectiveTeletexTerminalIdentifier' 'Collective Teletex Terminal Identifier' 'Sammelbegriff Teletex Terminal Identifikation' (2 5 4 22 1 2) 'id-at-encryptedCollectiveTeletexTerminalIdentifier' 'Encrypted Collective Teletex Terminal Identifier' 'Sammelbegriff Teletex Terminal Identifikation verschlüsselt' (2 5 4 23) 'id-at-facsimileTelephoneNumber' 'Facsimile Telephone Number' 'Fax-Nummer' (2 5 4 23 2) 'id-at-encryptedFacsimileTelephoneNumber' 'Encrypted Facsimile Telephone Number' 'Fax-Nummer verschlüsselt' (2 5 4 23 1) 'id-at-collectiveFacsimileTelephoneNumber' 'Collective Facsimile Telephone Number' 'Sammelbegriff Fax-Nummer' (2 5 4 23 1 2) 'id-at-encryptedCollectiveFacsimileTelephoneNumber' 'Encrypted Collective Facsimile Telephone Number' 'Sammelbegriff Fax-Nummer verschlüsselt' (2 5 4 24) 'id-at-x121Address' 'X.121 Address' 'X.121 Adresse' (2 5 4 24 2) 'id-at-encryptedX121Address' 'Encrypted X.121 Address' 'X.121 Adresse verschlüsselt' (2 5 4 25) 'id-at-internationalISDNNumber' 'International ISDN Number' 'Internationale ISDN-Nummer' (2 5 4 25 2) 'id-at-encryptedInternationalISDNNumber' 'Encrypted International ISDN Number' 'Internationale ISDN-Nummer verschlüsselt' (2 5 4 25 1) 'id-at-collectiveInternationalISDNNumber' 'Collective International ISDN Number' 'Sammelbegriff internationale ISDN-Nummer' (2 5 4 25 1 2) 'id-at-encryptedCollectiveInternationalISDNNumber' 'Encrypted Collective International ISDN Number' 'Sammelbegriff internationale ISDN-Nummer verschlüsselt' (2 5 4 26) 'id-at-registeredAddress' '' '' (2 5 4 26 2) 'id-at-encryptedRegisteredAddress' '' '' (2 5 4 27) 'id-at-destinationIndicator' '' '' (2 5 4 27 2) 'id-at-encryptedDestinationIndicator' '' '' (2 5 4 28) 'id-at-preferredDeliveryMethod' '' '' (2 5 4 28 2) 'id-at-encryptedPreferredDeliveryMethod' '' '' (2 5 4 29) 'id-at-presentationAddress' '' '' (2 5 4 29 2) 'id-at-encryptedPresentationAddress' '' '' (2 5 4 30) 'id-at-supportedApplicationContext' '' '' (2 5 4 30 2) 'id-at-encryptedSupportedApplicationContext' '' '' (2 5 4 31) 'id-at-member' 'Member' 'Mitglied' (2 5 4 31 2) 'id-at-encryptedMember' 'Encrypted Member' 'Mitglied verschlüsselt' (2 5 4 32) 'id-at-owner' 'Owner' 'Inhaber' (2 5 4 32 2) 'id-at-encryptedOwner' 'Encrypted Owner' 'Inhaber verschlüsselt' (2 5 4 33) 'id-at-roleOccupant' 'Role Occupant' 'Rechtsinhaber' (2 5 4 33 2) 'id-at-encryptedRoleOccupant' 'Encrypted Role Occupant' 'Rechtsinhaber verschlüsselt' (2 5 4 34) 'id-at-seeAlso' 'See Also' 'Siehe auch' (2 5 4 34 2) 'id-at-encryptedSeeAlso' 'Encrypted See Also' 'Siehe auch verschlüsselt' (2 5 4 35) 'id-at-userPassword' 'User Password' 'Anwender Passwort' (2 5 4 35 2) 'id-at-encryptedUserPassword' 'Encrypted User Password' 'Anwender Passwort verschlüsselt' (2 5 4 36) 'id-at-userCertificate' 'User Certificate' 'Anwender Zertifikat' (2 5 4 36 2) 'id-at-encryptedUserCertificate' 'Encrypted User Certificate' 'Anwender Zertifikat verschlüsselt' (2 5 4 37) 'id-at-cACertificate' 'CA Certificate' 'CA Zertifikat' (2 5 4 37 2) 'id-at-encryptedCACertificate' 'Encrypted CA Certificate' 'CA Zertifikat verschlüsselt' (2 5 4 38) 'id-at-authorityRevocationList' '' '' (2 5 4 38 2) 'id-at-encryptedAuthorityRevocationList' '' '' (2 5 4 39) 'id-at-certificateRevocationList' '' '' (2 5 4 39 2) 'id-at-encryptedCertificateRevocationList' '' '' (2 5 4 40) 'id-at-crossCertificatePair' '' '' (2 5 4 40 2) 'id-at-encryptedCrossCertificatePair' '' '' (2 5 4 41) 'id-at-name' 'Name' 'Name' (2 5 4 42) 'id-at-givenName' 'Given Name' 'Vorname' (2 5 4 42 2) 'id-at-encryptedGivenName' 'Encrypted Given Name' 'Vorname verschlüsselt' (2 5 4 43) 'id-at-initials' 'Initials' 'Initialen' (2 5 4 43 2) 'id-at-encryptedInitials' 'Encrypted Initials' 'Initialen verschlüsselt' (2 5 4 44) 'id-at-generationQualifier' 'Generation Qualifier' 'Generations-Zusatz' (2 5 4 44 2) 'id-at-encryptedGenerationQualifier' 'Encrypted Generation Qualifier' 'Generations-Zusatz verschlüsselt' (2 5 4 45) 'id-at-uniqueIdentifier' 'Unique Identifier' 'Eindeutige Identifikation' (2 5 4 45 2) 'id-at-encryptedUniqueIdentifier' 'Encrypted Unique Identifier' 'Eindeutige Identifikation verschlüsselt' (2 5 4 46) 'id-at-dnQualifier' 'dnQualifier' 'dnQualifier' (2 5 4 46 2) 'id-at-encryptedDnQualifier' '' '' (2 5 4 47) 'id-at-enhancedSearchGuide' '' '' (2 5 4 47 2) 'id-at-encryptedEnhancedSearchGuide' '' '' (2 5 4 48) 'id-at-protocolInformation' 'Protocol Information' 'Protokoll-Information' (2 5 4 48 2) 'id-at-encryptedProtocolInformation' 'Encrypted Protocol Information' 'Protokoll-Information verschlüsselt' (2 5 4 49) 'id-at-distinguishedName' 'Distinguished Name' 'Unterscheidungs-Name' (2 5 4 49 2) 'id-at-encryptedDistinguishedName' 'Encrypted Distinguished Name' 'Unterscheidungs-Name verschlüsselt' (2 5 4 50) 'id-at-uniqueMember' '' '' (2 5 4 50 2) 'id-at-encryptedUniqueMember' '' '' (2 5 4 51) 'id-at-houseIdentifier' 'House Identifier' 'Hausnummer' (2 5 4 51 2) 'id-at-encryptedHouseIdentifier' 'Encrypted House Identifier' 'Hausnummer verschlüsselt' (2 5 4 52) 'id-at-supportedAlgorithms' '' '' (2 5 4 52 2) 'id-at-encryptedSupportedAlgorithms' '' '' (2 5 4 53) 'id-at-deltaRevocationList' '' '' (2 5 4 53 2) 'id-at-encryptedDeltaRevocationList' '' '' (2 5 4 54) 'id-at-dmdName' '' '' (2 5 4 54 2) 'id-at-encryptedDmdName' '' '' (2 5 4 55) 'id-at-clearance' '' '' (2 5 4 55 2) 'id-at-encryptedClearance' '' '' (2 5 4 56) 'id-at-defaultDirQop' '' '' (2 5 4 56 2) 'id-at-encryptedDefaultDirQop' '' '' (2 5 4 57) 'id-at-attributeIntegrityInfo' '' '' (2 5 4 57 2) 'id-at-encryptedAttributeIntegrityInfo' '' '' (2 5 4 58) 'id-at-attributeCertificate' 'Attribute Certificate' 'Zertifikats-Attribut' (2 5 4 58 2) 'id-at-encryptedAttributeCertificate' 'Encrypted Attribute Certificate' 'Zertifikats-Attribut verschlüsselt' (2 5 4 59) 'id-at-attributeCertificateRevocationList' '' '' (2 5 4 59 2) 'id-at-encryptedAttributeCertificateRevocationList' '' '' (2 5 4 60) 'id-at-confKeyInfo' '' '' (2 5 4 60 2) 'id-at-encryptedConfKeyInfo' '' '' (2 5 4 65) 'id-at-pseudonym' 'pseudonym' 'Pseudonym' (2 5 8) 'X.500-Algorithms' '' '' (2 5 8 1) 'X.500-Alg-Encryption' '' '' (2 5 8 1 1) 'rsa' '' '' (2 5 29 1) 'id-ce-draft-authorityKeyIdentifier' 'Authority key identifier' 'Stellenschlüssel-ID' (2 5 29 2) 'id-ce-keyAttributes' 'Key attributes' 'Schlüsselattribute' (2 5 29 3) 'id-ce-draft-certificatePolicies' '' '' (2 5 29 4) 'id-ce-keyUsageRestriction' 'Key usage restriction' 'Einschränkung der Schlüsselverwendung' (2 5 29 5) 'id-ce-draft-policyMappings' '' '' (2 5 29 6) 'id-ce-subtreesConstraint' '' '' (2 5 29 7) 'id-ce-draft-subjectAltName' 'Subject alt name' 'Alternativer Antragstellername' (2 5 29 8) 'id-ce-draft-issuerAltName' 'Issuer alt name' 'Alternativer Ausstellername' (2 5 29 9) 'id-ce-subjectDirectoryAttributes' '' '' (2 5 29 10) 'id-ce-draft-basicConstraints' 'Basic constraints' 'Basiseinschränkungen' (2 5 29 11) 'id-ce-draft-nameConstraints' '' '' (2 5 29 12) 'id-ce-draft-policyConstraints' '' '' (2 5 29 13) 'id-ce-draft2-basicConstraints' '' '' (2 5 29 14) 'id-ce-subjectKeyIdentifier' 'Subject key identifier' 'Schlüssel-ID des Antragstellers' (2 5 29 15) 'id-ce-keyUsage' 'Key usage' 'Schlüsselverwendung' (2 5 29 16) 'id-ce-privateKeyUsagePeriod' '' '' (2 5 29 17) 'id-ce-subjectAltName' 'Subject alt name' 'Alternativer Antragstellername' (2 5 29 18) 'id-ce-issuerAltName' 'Issuer alt name' 'Alternativer Ausstellername' (2 5 29 19) 'id-ce-basicConstraints' 'Basic constraints' 'Basiseinschränkungen' (2 5 29 20) 'id-ce-cRLNumber' '' '' (2 5 29 21) 'id-ce-reasonCode' 'CRL reason code' 'CRL-Grundcode' (2 5 29 22) 'id-ce-expirationDate' '' '' (2 5 29 23) 'id-ce-holdInstructionCode' '' '' (2 5 29 24) 'id-ce-invalidityDate' '' '' (2 5 29 25) 'id-ce-cRLDistributionPoints' '' '' (2 5 29 26) 'id-ce-draft-issuingDistributionPoint' '' '' (2 5 29 27) 'id-ce-deltaCRLIndicator' '' '' (2 5 29 28) 'id-ce-issuingDistributionPoint' '' '' (2 5 29 29) 'id-ce-certificateIssuer' '' '' (2 5 29 30) 'id-ce-nameConstraints' '' '' (2 5 29 31) 'id-ce-cRLDistPoints' 'CRL distribution points' 'CRL-Verteilungspunkte' (2 5 29 32) 'id-ce-certificatePolicies' 'Certificate policies' 'Zertifikatsrichtlinien' (2 5 29 33) 'id-ce-policyMappings' '' '' (2 5 29 34) 'id-ce-draft2-policyConstraints' '' '' (2 5 29 35) 'id-ce-authorityKeyIdentifier' 'Authority key identifier' 'Stellenschlüssel-ID' (2 5 29 36) 'id-ce-policyConstraints' '' '' (2 5 29 37) 'id-ce-extKeyUsage' 'Extended key usage' 'Erweiterte Schlüsselverwendung' (2 5 29 38) 'id-ce-authorityAttributeIdentifier' '' '' (2 5 29 39) 'id-ce-ownerAttributeIdentifier' '' '' (2 5 29 40) 'id-ce-delegatorAttributeIdentifier' '' '' (2 5 29 41) 'id-ce-basicAttConstraints' '' '' (2 5 29 42) 'id-ce-attributeNameConstraints' '' '' (2 5 29 43) 'id-ce-timeSpecification' '' '' (2 5 29 44) 'id-ce-crlScope' '' '' (2 5 29 45) 'id-ce-statusReferrals' '' '' (2 5 29 46) 'id-ce-freshestCRL' '' '' (2 5 29 47) 'id-ce-orderedList' '' '' (2 5 29 48) 'id-ce-attributeDescriptor' '' '' (2 5 29 49) 'id-ce-crossPrivilege' '' '' (2 16 840 1 101 3) 'csor' '' '' (2 16 840 1 101 3 4) 'nistAlgorithm' '' '' (2 16 840 1 101 3 4 2) 'hashAlgs' '' '' (2 16 840 1 101 3 4 2 1) 'sha256' '' '' (2 16 840 1 101 3 4 2 2) 'sha384' '' '' (2 16 840 1 101 3 4 2 3) 'sha512' '' '' (2 16 840 1 101 3 4 2 4) 'sha224' '' '' (2 16 840 1 101 2 1 1 1) 'sdnsSignatureAlgorithm' '' '' (2 16 840 1 101 2 1 1 2) 'mosaicSignatureAlgorithm' '' '' (2 16 840 1 101 2 1 1 3) 'sdnsConfidentialityAlgorithm' '' '' (2 16 840 1 101 2 1 1 4) 'mosaicConfidentialityAlgorithm' '' '' (2 16 840 1 101 2 1 1 5) 'sdnsIntegrityAlgorithm' '' '' (2 16 840 1 101 2 1 1 6) 'mosaicIntegrityAlgorithm' '' '' (2 16 840 1 101 2 1 1 7) 'sdnsTokenProtectionAlgorithm' '' '' (2 16 840 1 101 2 1 1 8) 'mosaicTokenProtectionAlgorithm' '' '' (2 16 840 1 101 2 1 1 9) 'sdnsKeyManagementAlgorithm' '' '' (2 16 840 1 101 2 1 1 10) 'mosaicKeyManagementAlgorithm' '' '' (2 16 840 1 101 2 1 1 11) 'sdnsKMandSigAlgorithm' '' '' (2 16 840 1 101 2 1 1 12) 'mosaicKMandSigAlgorithm' '' '' (2 16 840 1 101 2 1 1 13) 'SuiteASignatureAlgorithm' '' '' (2 16 840 1 101 2 1 1 14) 'SuiteAConfidentialityAlgorithm' '' '' (2 16 840 1 101 2 1 1 15) 'SuiteAIntegrityAlgorithm' '' '' (2 16 840 1 101 2 1 1 16) 'SuiteATokenProtectionAlgorithm' '' '' (2 16 840 1 101 2 1 1 17) 'SuiteAKeyManagementAlgorithm' '' '' (2 16 840 1 101 2 1 1 18) 'SuiteAKMandSigAlgorithm' '' '' (2 16 840 1 101 2 1 1 19) 'mosaicUpdatedSigAlgorithm' 'mosaicUpdatedSig' 'mosaicUpdatedSig' (2 16 840 1 101 2 1 1 20) 'mosaicKMandUpdSigAlgorithms' 'mosaicKMandUpdSig' 'mosaicKMandUpdSig' (2 16 840 1 101 2 1 1 21) 'mosaicUpdatedIntegAlgorithm' '' '' (2 16 840 1 101 2 1 1 22) 'mosaicKeyEncryptionAlgorithm' '' '' (2 16 840 1 113730 1 1) 'cert-type' 'Netscape Certificate Type' 'Netscape Zertifikats-Typ' (2 16 840 1 113730 1 2) 'base-url' 'NetscapeBaseURL' 'NetscapeBaseURL' (2 16 840 1 113730 1 3) 'revocation-url' 'NetscapeRevocationURL' 'NetscapeRevocationURL' (2 16 840 1 113730 1 4) 'ca-revocation-url' 'NetscapeCARevocationURL' 'NetscapeCARevocationURL' (2 16 840 1 113730 1 5) 'cert-sequence' '' '' (2 16 840 1 113730 1 6) 'cert-url' '' '' (2 16 840 1 113730 1 7) 'renewal-url' 'NetscapeCertRenewalURL' 'NetscapeCertRenewalURL' (2 16 840 1 113730 1 8) 'ca-policy-url' 'NetscapeCAPolicyURL' 'NetscapeCAPolicyURL' (2 16 840 1 113730 1 9) 'HomePage-url' '' '' (2 16 840 1 113730 1 10) 'EntityLogo' '' '' (2 16 840 1 113730 1 11) 'UserPicture' '' '' (2 16 840 1 113730 1 12) 'ssl-server-name' 'NetscapeSSLServerName' 'NetscapeSSLServerName' (2 16 840 1 113730 1 13) 'comment' 'NetscapeComment' 'NetscapeComment' (2 16 840 1 113730 2) 'data-type' '' '' (2 16 840 1 113730 2 1) 'GIF' '' '' (2 16 840 1 113730 2 2) 'JPEG' '' '' (2 16 840 1 113730 2 3) 'URL' '' '' (2 16 840 1 113730 2 4) 'HTML' '' '' (2 16 840 1 113730 2 5) 'CertSeq' '' '' (2 16 840 1 113730 3) 'directory' '' '' (2 16 840 1 113730 3 1 216) 'pkcs-9-at-userPKCS12' '' '' (2 16 840 1 101 3 4 1 2) 'aes128-CBC-PAD' '' '' (2 16 840 1 101 3 4 1 22) 'aes192-CBC-PAD' '' '' (2 16 840 1 101 3 4 1 42) 'aes256-CBC-PAD' '' '' (2 23 42 0 0) 'PANData' '' '' (2 23 42 0 1) 'PANToken' '' '' (2 23 42 0 2) 'PANOnly' '' '' (2 23 42 1) 'msgExt' '' '' (2 23 42 2) 'field' '' '' (2 23 42 2 0) 'fullName' '' '' (2 23 42 2 1) 'givenName2' '' '' (2 23 42 2 2) 'familyName' '' '' (2 23 42 2 3) 'birthFamilyName' '' '' (2 23 42 2 4) 'placeName' '' '' (2 23 42 2 5) 'identificationNumber' '' '' (2 23 42 2 6) 'month' '' '' (2 23 42 2 7) 'date' '' '' (2 23 42 2 8) 'address' '' '' (2 23 42 2 9) 'telephone' '' '' (2 23 42 2 10) 'amount' '' '' (2 23 42 2 11) 'accountNumber' '' '' (2 23 42 2 12) 'passPhrase' '' '' (2 23 42 3) 'attribute' '' '' (2 23 42 3 0) 'cert' '' '' (2 23 42 3 0 0) 'rootKeyThumb' '' '' (2 23 42 3 0 1) 'additionalPolicy' '' '' (2 23 42 4) 'algorithm' '' '' (2 23 42 5) 'policy' '' '' (2 23 42 5 0) 'root' '' '' (2 23 42 6) 'module' '' '' (2 23 42 7) 'certExt' '' '' (2 23 42 7 0) 'hashedRootKey' '' '' (2 23 42 7 1) 'certificateType' '' '' (2 23 42 7 2) 'merchantData' '' '' (2 23 42 7 3) 'cardCertRequired' '' '' (2 23 42 7 4) 'tunneling' '' '' (2 23 42 7 5) 'setExtensions' '' '' (2 23 42 7 6) 'setQualifier' '' '' (2 23 42 8) 'brand' '' '' (2 23 42 8 1) 'IATA-ATA' '' '' (2 23 42 8 4) 'VISA' '' '' (2 23 42 8 5) 'MasterCard' '' '' (2 23 42 8 30) 'Diners' '' '' (2 23 42 8 34) 'AmericanExpress' '' '' (2 23 42 8 6011) 'Novus' '' '' (2 23 42 9) 'vendor' '' '' (2 23 42 9 0) 'GlobeSet' '' '' (2 23 42 9 1) 'IBM' '' '' (2 23 42 9 2) 'CyberCash' '' '' (2 23 42 9 3) 'Terisa' '' '' (2 23 42 9 4) 'RSADSI' '' '' (2 23 42 9 5) 'VeriFone' '' '' (2 23 42 9 6) 'TrinTech' '' '' (2 23 42 9 7) 'BankGate' '' '' (2 23 42 9 8) 'GTE' '' '' (2 23 42 9 9) 'CompuSource' '' '' (2 23 42 9 10) 'Griffin' '' '' (2 23 42 9 11) 'Certicom' '' '' (2 23 42 9 12) 'OSS' '' '' (2 23 42 9 13) 'TenthMountain' '' '' (2 23 42 9 14) 'Antares' '' '' (2 23 42 9 15) 'ECC' '' '' (2 23 42 9 16) 'Maithean' '' '' (2 23 42 9 17) 'Netscape' '' '' (2 23 42 9 18) 'Verisign' '' '' (2 23 42 9 19) 'BlueMoney' '' '' (2 23 42 9 20) 'Lacerte' '' '' (2 23 42 9 21) 'Fujitsu' '' '' (2 23 42 9 22) 'eLab' '' '' (2 23 42 9 23) 'Entrust' '' '' (2 23 42 9 24) 'VIAnet' '' '' (2 23 42 9 25) 'III' '' '' (2 23 42 9 26) 'OpenMarket' '' '' (2 23 42 9 27) 'Lexem' '' '' (2 23 42 9 28) 'Intertrader' '' '' (2 23 42 9 29) 'Persimmon' '' '' (2 23 42 9 30) 'NABLE' '' '' (2 23 42 9 31) 'espace-net' '' '' (2 23 42 9 32) 'Hitachi' '' '' (2 23 42 9 33) 'Microsoft' '' '' (2 23 42 9 34) 'NEC' '' '' (2 23 42 9 35) 'Mitsubishi' '' '' (2 23 42 9 36) 'NCR' '' '' (2 23 42 9 37) 'e-COMM' '' '' (2 23 42 9 38) 'Gemplus' '' '' (2 23 42 10) 'national' '' '' (2 23 42 10 192) 'Japan' '' '' (2 23 136) 'id-icao' '' '' (2 23 136 1) 'id-icao-mrtd' '' '' (2 23 136 1 1) 'id-icao-mrtd-security' '' '' (2 23 136 1 1 2) 'id-icao-cscaMasterList' '' '' (2 23 136 1 1 3) 'id-icao-cscaMasterListSigningKey' '' ''
    PRINTABLESTR←0 0 19
    REAL←0 0 9
    SEQUENCE←0 1 16
    SET←0 1 17
    T61STR←0 0 20
    TAG_BITSTRING←3
    TAG_BMPSTR←30
    TAG_BOOLEAN←1
    TAG_EMBEDDED_PDV←11
    TAG_ENUMERATED←10
    TAG_EOC←0
    TAG_EXTERNAL←8
    TAG_GENERALIZEDTIME←24
    TAG_GENERALSTR←27
    TAG_GRAPHICSTR←25
    TAG_IA5STR←22
    TAG_INTEGER←2
    TAG_NULLTAG←5
    TAG_NUMERICSTR←18
    TAG_OBJDESCRIPTOR←7
    TAG_OCTETSTRING←4
    TAG_OID←6
    TAG_PRINTABLESTR←19
    TAG_REAL←9
    TAG_SEQUENCE←16
    TAG_SET←17
    TAG_T61STR←20
    TAG_UNIVERSALSTR←28
    TAG_UTCTIME←23
    TAG_UTF8STR←12
    TAG_VIDEOTEXSTR←21
    TAG_VISIBLESTR←26
    TRUE←1
    UNIVERSALSTR←0 0 28
    UTCTIME←0 0 23
    UTF8STR←0 0 12
    UTO_ANSI←1
    UTO_AUTO←4
    UTO_FMT←4
    UTO_HEX←8
    UTO_I32←1
    UTO_I48←2
    UTO_I53←3
    UTO_LOCAL←2
    UTO_NUM←1
    UTO_SPCALL←3
    UTO_SPCSEQ←2
    UTO_STR←0
    UTO_WIDE←2
    UTO_ZULU←1
    UnivTagOptions←1 2 2 3 ⍬ 1 ⍬ ⍬ ⍬ 2 ⍬ 1 ⍬ ⍬ ⍬ ⍬ ⍬ 1 1 1 0 1 6 2 0 0 0 1 ⍬ 1
    VIDEOTEXSTR←0 0 21
    VISIBLESTR←0 0 26

⍝ === End of variables definition ===
    :endsection


    (⎕IO ⎕ML ⎕WX ⎕CT)←1 3 1 9.999999999999998E¯15

    ∇ C←Adjust C
     ⍝ Adjust Length of an ASN.1 string by removing trailing bytes
     ⍝ Upon error the result is ''
     ⍝ Check #.RCode and #.RText for further information.
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
      :Trap 0
          C←_AdjustASN1⊂C
      :Case 6
          :Trap 0
              Init''
              C←_AdjustASN1⊂C
          :Else
              ⎕SIGNAL ⎕EN
          :EndTrap
      :Else
          ⎕SIGNAL ⎕EN
      :EndTrap
    ∇

    CONTEXT←{CLASS_CONTEXT FORM_CONSTRUCTED ⍵}

    ∇ C←{P}Code C
     ⍝ Decode/Encode ASN.1 sequences and APL nested structures, regardless of the coding state of the input
     ⍝
     ⍝ C(Content)      = ASN.1 sequence or APL nested structure
     ⍝
     ⍝ P(Parms)        = 0-2 element vector, consists of (Depth UnivTagOptions) defined as:
     ⍝
     ⍝ Depth           = 0: Decode all possible levels (Default, same as monadic usage)
     ⍝                   1: Encode to ASN.1 sequence
     ⍝                   N: Decode/Encode recursively to an N levels deep nested structure
     ⍝                  -N: Same as N, except attempt to decode PRIMITIVE forms of substrings within
     ⍝                      OCTETSTRINGs and byte aligned BITSTRINGs is inhibited (No speculative decode)
     ⍝
     ⍝ UnivTagOptions  = Up to 30 elements numeric vector of UTO_XXX constants or ⍬s, defining tag specific coding behaviour of UNIVERSAL tags:
     ⍝                   0: Decode ALL tag's data fields as character vectors, except not byte aligned BITSTRINGs, which will decode as bit vector
     ⍝                   ⍬: Apply default behaviour for specified tag, same as:
     ⍝                      UnivTagOptions←30⍴⊂⍬
     ⍝                      UnivTagOptions[TAG_BOOLEAN TAG_OID]←UTO_NUM
     ⍝                      UnivTagOptions[TAG_INTEGER TAG_ENUMERATED]←UTO_I48
     ⍝                      UnivTagOptions[TAG_BITSTRING]←UTO_SPCSEQ
     ⍝                      UnivTagOptions[TAG_OCTETSTRING]←UTO_SPCALL
     ⍝                      UnivTagOptions[TAG_UTCTIME]←UTO_LOCAL+UTO_AUTO
     ⍝                      UnivTagOptions[TAG_GENERALIZEDTIME]←UTO_LOCAL
     ⍝                      UnivTagOptions[TAG_UTF8STR TAG_NUMERICSTR TAG_PRINTABLESTR TAG_T61STR TAG_IA5STR TAG_UNIVERSALSTR TAG_BMPSTR]←UTO_ANSI
     ⍝                      UnivTagOptions[TAG_VIDEOTEXSTR TAG_GRAPHICSTR TAG_VISIBLESTR TAG_GENERALSTR]←UTO_STR
      :If ×⎕NC'P'
          :Trap 0
              C←_CodeASN1 P C
          :Case 6
              :Trap 0
                  Init''
                  C←_CodeASN1 P C
              :Else
                  ⎕SIGNAL ⎕EN
              :EndTrap
          :Else
              ⎕SIGNAL ⎕EN
          :EndTrap
      :Else
          :Trap 0
              C←_CodeASN1 ⍬ C
          :Case 6
              :Trap 0
                  Init''
                  C←_CodeASN1 ⍬ C
              :Else
                  ⎕SIGNAL ⎕EN
              :EndTrap
          :Else
              ⎕SIGNAL ⎕EN
          :EndTrap
      :EndIf
    ∇

    DEFAULT←{⍺{(≡⍺)>≡⍵:((⊂⍴⍺)⊃⍺)∇ ⍵ ⋄ ⍺≡⍵}⍵:'' ⋄ ⍺}

    ∇ {RCode}←Exit
      :Hold '#.ASN1.Init'
          ⎕EX⊃'_CodeASN1' '_AdjustASN1'
      :EndHold
      RCode←0
    ∇

    IMPLICIT←{CLASS_CONTEXT FORM_PRIMITIVE ⍵}

    ∇ r←Platform;apl
    ⍝ return best guess for the platform we're running on
      :If 'lin'≡r←{('abcdefghijklmnopqrstuvwxyz',⍵)[(⎕A,⍵)⍳⍵]}3↑apl←1⊃'.'⎕WG'APLVersion'
          :If 'armv'≡4↑↑⎕SH'uname -m'  ⍝!!! warning, could be Android someday
              r←'arm'
          :EndIf
      :EndIf
      r←r((1+∨/'-64'⍷apl)⊃'32' '64')
    ∇

    ∇ {RCode}←Init path;platform;width;dlldir;scriptpath;dll;wspath;curpath;exepath;found;Library
      :Trap 0
          (platform width)←Platform
     
          dlldir←'/',⍨'aix' 'linux' 'pi' 'windows' 'mac'⊃⍨'aix' 'lin' 'arm' 'win' 'mac'⍳⊂platform
     
          :If 0=≢scriptpath←{0::'' ⋄ AddSep ExtractPath ⍵⍎'SALT_Data.SourceFile'}⎕THIS
              scriptpath←1⊃⎕NPARTS 4⊃5179⌶⍕⎕THIS
          :EndIf
     
          dll←'dyacrypt20_',width,'.',(1+'win'≡platform)⊃'so' 'dll'
          wspath←1⊃1 ⎕NPARTS ⎕WSID
          curpath←1⊃1 ⎕NPARTS''
          exepath←1⊃1 ⎕NPARTS 1⊃2 ⎕NQ'.' 'GetCommandLineArgs'
     
          :Hold '#.Crypt.Init'
              :If 0=⎕NC'_Hash' ⍝ if _Hash already exists, assume we're initialized
                  :If 0∊⍴path
                      :For path :In scriptpath wspath curpath exepath
                          :If ~found←⎕NEXISTS Library←path,dll
                              found←⎕NEXISTS Library←path,dlldir,dll
                          :EndIf
                          :If found ⋄ :Leave ⋄ :EndIf
                      :EndFor
                  :Else
                      :If ~found←⎕NEXISTS Library←path,dll
                          found←⎕NEXISTS Library←path,dlldir,dll
                      :EndIf
                  :EndIf
     
                  ('DCL shared library (',dll,') not found') ⎕SIGNAL found↓999
     
     ⍝ AdjustASN1: Adjust Length of an ASN.1 string
                  '_AdjustASN1'⎕NA Library,'|AdjustASN1* =A'
     ⍝ CodeASN1:   ASN.1 encode / decode function
                  '_CodeASN1'⎕NA Library,'|CodeASN1* <A =A'
     ⍝ Tag classes
                  CLASS_UNIVERSAL←0      ⍝  0 = Universal (defined by ITU X.680)
                  CLASS_APPLICATION←1    ⍝  1 = Application
                  CLASS_CONTEXT←2        ⍝  2 = Context-specific
                  CLASS_PRIVATE←3        ⍝  3 = Private
     ⍝ Encoding forms
                  FORM_PRIMITIVE←0       ⍝  0 = primitive
                  FORM_CONSTRUCTED←1     ⍝  1 = constructed
     ⍝ Class universal tags
                  TAG_EOC←0              ⍝  0 = End-of-contents octets
                  TAG_BOOLEAN←1          ⍝  1 = TRUE or FALSE
                  TAG_INTEGER←2          ⍝  2 = Arbitrary precision integer
                  TAG_BITSTRING←3        ⍝  3 = Sequence of bits
                  TAG_OCTETSTRING←4      ⍝  4 = Sequence of bytes
                  TAG_NULLTAG←5          ⍝  5 = NULL
                  TAG_OID←6              ⍝  6 = Object Identifier (numeric sequence)
                  TAG_OBJDESCRIPTOR←7    ⍝  7 = Object Descriptor (human readable)
                  TAG_EXTERNAL←8         ⍝  8 = External / Instance Of
                  TAG_REAL←9             ⍝  9 = Real (Mantissa * Base∧Exponent)
                  TAG_ENUMERATED←10      ⍝ 10 = Enumerated
                  TAG_EMBEDDED_PDV←11    ⍝ 11 = Embedded Presentation Data Value
                  TAG_UTF8STR←12         ⍝ 12 = UTF-8 String (RFC2044)
     ⍝            TAG_RES_13←13          ⍝ 13 = reserved
     ⍝            TAG_RES_14←14          ⍝ 14 = reserved
     ⍝            TAG_RES_15←15          ⍝ 15 = reserved
                  TAG_SEQUENCE←16        ⍝ 16 = Constructed Sequence / Sequence Of
                  TAG_SET←17             ⍝ 17 = Constructed Set / Set Of
                  TAG_NUMERICSTR←18      ⍝ 18 = Numeric String (digits only)
                  TAG_PRINTABLESTR←19    ⍝ 19 = Printable String
                  TAG_T61STR←20          ⍝ 20 = T61 String (Teletex)
                  TAG_VIDEOTEXSTR←21     ⍝ 21 = Videotex String
                  TAG_IA5STR←22          ⍝ 22 = IA5 String
                  TAG_UTCTIME←23         ⍝ 23 = UTC Time
                  TAG_GENERALIZEDTIME←24 ⍝ 24 = Generalized Time
                  TAG_GRAPHICSTR←25      ⍝ 25 = Graphic String
                  TAG_VISIBLESTR←26      ⍝ 26 = Visible String (ISO 646)
                  TAG_GENERALSTR←27      ⍝ 27 = General String
                  TAG_UNIVERSALSTR←28    ⍝ 28 = Universal String
     ⍝            TAG_RES_29←29          ⍝ 29 = reserved
                  TAG_BMPSTR←30          ⍝ 30 = Basic Multilingual Plane String
     ⍝            TAG_SUBSEQ←31          ⍝ 31 = Subsequent (ASN1_ID2_Octets will follow)
     ⍝ Class universal tag values
                  EOC←,⊂CLASS_UNIVERSAL FORM_PRIMITIVE TAG_EOC                       ⍝ 0 0 0  = End-of-contents octets
                  BOOLEAN←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_BOOLEAN                 ⍝ 0 0 1  = TRUE or FALSE
                  INTEGER←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_INTEGER                 ⍝ 0 0 2  = Arbitrary precision integer
                  BITSTRING←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_BITSTRING             ⍝ 0 0 3  = Sequence of bits
                  OCTETSTRING←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_OCTETSTRING         ⍝ 0 0 4  = Sequence of bytes
                  NULLTAG←,⊂CLASS_UNIVERSAL FORM_PRIMITIVE TAG_NULLTAG               ⍝ 0 0 5  = NULL (No Data will follow)
                  OID←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_OID                         ⍝ 0 0 6  = Object Identifier (numeric sequence)
                  OBJDESCRIPTOR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_OBJDESCRIPTOR     ⍝ 0 0 7 =  Object Descriptor (human readable)
                  EXTERNAL←CLASS_UNIVERSAL FORM_CONSTRUCTED TAG_EXTERNAL             ⍝ 0 1 8 =  External / Instance Of
                  REAL←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_REAL                       ⍝ 0 0 9 =  Real (Mantissa * Base∧Exponent)
                  ENUMERATED←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_ENUMERATED           ⍝ 0 0 10 = Enumerated
                  EMBEDDED_PDV←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_EMBEDDED_PDV       ⍝ 0 0 11 = Embedded Presentation Data Value
                  UTF8STR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_UTF8STR                 ⍝ 0 0 12 = UTF-8 String (RFC2044)
                  SEQUENCE←CLASS_UNIVERSAL FORM_CONSTRUCTED TAG_SEQUENCE             ⍝ 0 1 16 = Constructed Sequence / Sequence Of
                  SET←CLASS_UNIVERSAL FORM_CONSTRUCTED TAG_SET                       ⍝ 0 1 17 = Constructed Set / Set Of
                  NUMERICSTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_NUMERICSTR           ⍝ 0 0 18 = Numeric String (digits only)
                  PRINTABLESTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_PRINTABLESTR       ⍝ 0 0 19 = Printable String
                  T61STR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_T61STR                   ⍝ 0 0 20 = T61 String (Teletex)
                  VIDEOTEXSTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_VIDEOTEXSTR         ⍝ 0 0 21 = Videotex String
                  IA5STR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_IA5STR                   ⍝ 0 0 22 = IA5 String
                  UTCTIME←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_UTCTIME                 ⍝ 0 0 23 = UTC Time
                  GENERALIZEDTIME←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_GENERALIZEDTIME ⍝ 0 0 24 = Generalized Time
                  GRAPHICSTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_GRAPHICSTR           ⍝ 0 0 25 = Graphic String
                  VISIBLESTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_VISIBLESTR           ⍝ 0 0 26 = Visible String (ISO 646)
                  GENERALSTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_GENERALSTR           ⍝ 0 0 27 = General String
                  UNIVERSALSTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_UNIVERSALSTR       ⍝ 0 0 28 = Universal String
                  BMPSTR←CLASS_UNIVERSAL FORM_PRIMITIVE TAG_BMPSTR                   ⍝ 0 0 30 = Basic Multilingual Plane String
     ⍝ Class context tag primitive
                  IMPLICIT←{CLASS_CONTEXT FORM_PRIMITIVE ⍵}                          ⍝ 2 0 ⍵  = Context-specific
     ⍝ Class context tag contructed / EXPLICIT
                  CONTEXT←{CLASS_CONTEXT FORM_CONSTRUCTED ⍵}                         ⍝ 2 1 ⍵  = Context-specific
     ⍝ Some additional ASN.1 keywords
                  OPTIONAL←{⍵:⍺ ⋄ ''}
                  DEFAULT←{⍺{(≡⍺)>≡⍵:((⊂⍴⍺)⊃⍺)∇ ⍵ ⋄ ⍺≡⍵}⍵:'' ⋄ ⍺}
     ⍝ BOOLEAN values
                  FALSE←0
                  TRUE←1
     ⍝ Class universal tag options
                  UTO_STR←0    ⍝ Code tag as string
                  UTO_NUM←1    ⍝ Code TAG_BOOLEAN TAG_BITSTRING TAG_OID numerical (TAG_BOOLEAN TAG_OID default)
                  UTO_SPCSEQ←2 ⍝ Code TAG_BITSTRING TAG_OCTETSTRING speculative if it contains sequence (TAG_BITSTRING default)
                  UTO_SPCALL←3 ⍝ Code TAG_BITSTRING TAG_OCTETSTRING speculative if it contains any universal tag (TAG_OCTETSTRING string default)
                  UTO_I32←1    ⍝ Code TAG_INTEGER TAG_ENUMERATED within 32 bit numeric
                  UTO_I48←2    ⍝ Code TAG_INTEGER TAG_ENUMERATED within 48 bit numeric (TAG_INTEGER TAG_ENUMERATED default)
                  UTO_I53←3    ⍝ Code TAG_INTEGER TAG_ENUMERATED within 53 bit numeric
                  UTO_FMT←4    ⍝ Code TAG_INTEGER TAG_ENUMERATED as formatted squence  (may combine with UTO_Ixx)
                  UTO_HEX←8    ⍝ Code TAG_INTEGER TAG_ENUMERATED as hexadecimal string (may combine with UTO_Ixx)
                  UTO_ANSI←1   ⍝ Code TAG_UTF8STR TAG_NUMERICSTR TAG_PRINTABLESTR TAG_T61STR TAG_IA5STR TAG_UNIVERSALSTR TAG_BMPSTR as ANSI string (default)
                  UTO_WIDE←2   ⍝ Code TAG_UTF8STR TAG_NUMERICSTR TAG_PRINTABLESTR TAG_T61STR TAG_VIDEOTEXSTR TAG_IA5STR TAG_GRAPHICSTR TAG_VISIBLESTR TAG_GENERALSTR TAG_UNIVERSALSTR TAG_BMPSTR as Unicode string
                  UTO_ZULU←1   ⍝ Code TAG_UTCTIME TAG_GENERALIZEDTIME as Zulu time
                  UTO_LOCAL←2  ⍝ Code TAG_UTCTIME TAG_GENERALIZEDTIME as local time (TAG_GENERALIZEDTIME default)
                  UTO_AUTO←4   ⍝ Code TAG_UTCTIME as Generalized Time if necessary (TAG_UTCTIME default)
     ⍝ Defaults for class universal tag options
     ⍝                                                      ┌OctetStr OID┐ External┐ ┌Real     ┌Embedd  Sequence┐ ┌Set                         ┌VideotextStr                               VisibleStr┐       ┌GeneralStr
     ⍝                           ┌Bool   ┌Integer┌BitString │   NullTag┐ │ObjDesc┐ │ │ ┌Enumera│ ┌UTF8Str       │ │ ┌NumbrStr┌PrntStr ┌T61Str  │       ┌IA5Str  ┌UTCTime GeneraTime┐ GraphStr┐       │       │       ┌UniversStr┌BMPStr
     ⍝                           ├─────┐ ├─────┐ ├────────┐ ├────────┐ │ ├─────┐ │ │ │ ├─────┐ │ ├──────┐       │ │ ├──────┐ ├──────┐ ├──────┐ ├─────┐ ├──────┐ ├────────────────┐ ├───────┐ ├─────┐ ├─────┐ ├─────┐ ├──────┐   ├──────┐
                  UnivTagOptions←UTO_NUM UTO_I48 UTO_SPCSEQ UTO_SPCALL ⍬ UTO_NUM ⍬ ⍬ ⍬ UTO_I48 ⍬ UTO_ANSI ⍬ ⍬ ⍬ ⍬ ⍬ UTO_ANSI UTO_ANSI UTO_ANSI UTO_STR UTO_ANSI(UTO_LOCAL+UTO_AUTO)UTO_LOCAL UTO_STR UTO_STR UTO_STR UTO_ANSI ⍬ UTO_ANSI
     
              :AndIf 0=⎕NC'OidTab'
                  InitOidTab
              :EndIf
          :EndHold
          RCode←0
      :Else
          RCode←⎕EN
      :EndTrap
    ∇

    ∇ InitOidTab;CCITT;ISO;JOINT_ISO_CCITT;member_body;DE;SE;seis;US;nsn;rsadsi;pkcs;pkcs_1;pkcs_3;pkcs_5;pkcs_7;pkcs_9;pkcs_12;pkcs_15;digestAlgorithm;encryptionAlgorithm;ms;usgov;lotus;novell;netscape;cert_extension;data_type;org;identified_organization;secsig;algorithms;dod;internet;directory;mgmt;experimental;private;enterprises;microsoft;cryptlib;datev;he;security;mechanisms;pkix;pe;qt;kp;it;pda;ad;SNMPv2;mail;oiw;isismtt;id_alg;id_alg_hash;id_alg_sign;id_sig;id_sig_cp;id_sig_at;id;module;serviceElement;ac;at;attributeSyntax;oc;algorithm;as;dsaOperationalAttribute;mr;kmr;nf;group;sc;oa;ob;soc;soa;ar;aca;rosObject;contract;package;acScheme;ce;mgt;country;organization;gov;csor;nistAlgorithm;aes;etsi;reserved;etsi_identified_organization;bsi_de;ansi_x962
     ⍝ TAG_OID 1st element values:
      CCITT←0                        ⍝ 1st OID component: ccitt
      ISO←1                          ⍝ 1st OID component: iso
      JOINT_ISO_CCITT←2              ⍝ 1st OID component: joint_iso_ccitt
     ⍝ CCITT = ITU-T:
      identified_organization←4      ⍝ ITU-T identified_organization
      etsi←0                         ⍝ ITU-T identified_organization etsi
      reserved←127                   ⍝ ITU-T identified_organization etsi reserved
      etsi_identified_organization←0 ⍝ ITU-T identified_organization etsi reserved etsi_identified_organization
      bsi_de←7                       ⍝ ITU-T identified_organization etsi reserved etsi_identified_organization bsi_de
     ⍝ Imports from: UsefulDefinitions, InformationFramework, SelectedAttributeTypes, AuthenticationFramework
      member_body←2                  ⍝ ISO member_body
      DE←276                         ⍝ ISO member_body GERMANY
      SE←752                         ⍝ ISO member_body SWEDEN
      seis←34                        ⍝ ISO member_body SE seis
      US←840                         ⍝ ISO member_body US
      ansi_x962←10045                ⍝ ISO member_body US ansi_x962
      nsn←113533                     ⍝ ISO member_body US nsn (NortelSecureNetworks)
      rsadsi←113549                  ⍝ ISO member_body US rsadsi
      pkcs←1                         ⍝ ISO member_body US rsadsi pkcs
      pkcs_1←1                       ⍝ ISO member_body US rsadsi pkcs pkcs_1
      pkcs_3←3                       ⍝ ISO member_body US rsadsi pkcs pkcs_3
      pkcs_5←5                       ⍝ ISO member_body US rsadsi pkcs pkcs_5
      pkcs_7←7                       ⍝ ISO member_body US rsadsi pkcs pkcs_7
      pkcs_9←9                       ⍝ ISO member_body US rsadsi pkcs pkcs_9
      pkcs_12←12                     ⍝ ISO member_body US rsadsi pkcs pkcs_12
      pkcs_15←15                     ⍝ ISO member_body US rsadsi pkcs pkcs_12
      digestAlgorithm←2              ⍝ ISO member_body US rsadsi digestAlgorithm
      encryptionAlgorithm←3          ⍝ ISO member_body US rsadsi encryptionAlgorithm
      ms←113556                      ⍝ ISO member_body US ms (Microsoft)
      usgov←101                      ⍝ ISO member_body US usgov (US Government)
      lotus←113678                   ⍝ ISO member_body US lotus
      novell←113719                  ⍝ ISO member_body US novell
      netscape←113730                ⍝ ISO member_body US netscape (Netscape Communications Corp.)
      cert_extension←1               ⍝ ISO member_body US netscape cert_extension
      data_type←2                    ⍝ ISO member_body US netscape data_type
      org←3                          ⍝ ISO org
      dod←6                          ⍝ ISO org dod (U.S. Department of Defense)
      internet←1                     ⍝ ISO org dod internet (RFC 1155)
      directory←1                    ⍝ ISO org dod internet directory
      mgmt←2                         ⍝ ISO org dod internet mgmt
      experimental←3                 ⍝ ISO org dod internet experimental
      private←4                      ⍝ ISO org dod internet private
      enterprises←1                  ⍝ ISO org dod internet private enterprises
      microsoft←311                  ⍝ ISO org dod internet private enterprises microsoft
      cryptlib←3029                  ⍝ ISO org dod internet private enterprises cryptlib (Digital Data Security)
      datev←3744                     ⍝ ISO org dod internet private enterprises datev (DATEV eG)
      he←3761                        ⍝ ISO org dod internet private enterprises he (HAGER-ELECTRONICS GmbH)
      security←5                     ⍝ ISO org dod internet security
      mechanisms←5                   ⍝ ISO org dod internet security mechanisms
      pkix←7                         ⍝ ISO org dod internet security mechanisms id-pkix
      pe←1                           ⍝ ISO org dod internet security mechanisms id-pkix pe
      qt←2                           ⍝ ISO org dod internet security mechanisms id-pkix qt
      kp←3                           ⍝ ISO org dod internet security mechanisms id-pkix kp
      it←4                           ⍝ ISO org dod internet security mechanisms id-pkix it
      pda←9                          ⍝ ISO org dod internet security mechanisms id-pkix pda
      ad←48                          ⍝ ISO org dod internet security mechanisms id-pkix ad
      SNMPv2←6                       ⍝ ISO org dod internet SNMPv2
      mail←7                         ⍝ ISO org dod internet mail
      oiw←14                         ⍝ ISO org oiw (Open Systems Implementors Workshop)
      secsig←3                       ⍝ ISO org oiw secsig
      algorithms←2                   ⍝ ISO org oiw secsig algorithms
      isismtt←36                     ⍝ ISO org isismtt (teletrust)
      id_alg←3                       ⍝ ISO org isismtt
      id_alg_hash←2                  ⍝ ISO org isismtt id_alg_hash
      id_alg_sign←3                  ⍝ ISO org isismtt id_alg_sign
      id_sig←8                       ⍝ ISO org isismtt id_sig
      id_sig_cp←1                    ⍝ ISO org isismtt id_sig id_sig_cp
      id_sig_at←3                    ⍝ ISO org isismtt id_sig id_sig_at
      id←5                           ⍝ JOINT_ISO_CCITT id
      module←1                       ⍝ JOINT_ISO_CCITT id module
      serviceElement←2               ⍝ JOINT_ISO_CCITT id serviceElement
      ac←3                           ⍝ JOINT_ISO_CCITT id ac (applicationContext)
      at←4                           ⍝ JOINT_ISO_CCITT id at (attributeType)
      attributeSyntax←5              ⍝ JOINT_ISO_CCITT id attributeSyntax
      oc←6                           ⍝ JOINT_ISO_CCITT id oc (objectClass)
      algorithm←8                    ⍝ JOINT_ISO_CCITT id algorithm
      as←9                           ⍝ JOINT_ISO_CCITT id as (abstractSyntax)
      dsaOperationalAttribute←12     ⍝ JOINT_ISO_CCITT id dsaOperationalAttribute
      mr←13                          ⍝ JOINT_ISO_CCITT id mr (matchingRule)
      kmr←14                         ⍝ JOINT_ISO_CCITT id kmr (knowledgeMatchingRule)
      nf←15                          ⍝ JOINT_ISO_CCITT id nf (nameForm)
      group←16                       ⍝ JOINT_ISO_CCITT id group
      sc←17                          ⍝ JOINT_ISO_CCITT id sc (subentry)
      oa←18                          ⍝ JOINT_ISO_CCITT id oa (operationalAttributeType)
      ob←19                          ⍝ JOINT_ISO_CCITT id ob (operationalBinding)
      soc←20                         ⍝ JOINT_ISO_CCITT id soc (schemaObjectClass)
      soa←21                         ⍝ JOINT_ISO_CCITT id soa (schemaOperationalAttribute)
      ar←23                          ⍝ JOINT_ISO_CCITT id ar (administrativeRoles)
      aca←24                         ⍝ JOINT_ISO_CCITT id aca (accessControlAttribute)
      rosObject←25                   ⍝ JOINT_ISO_CCITT id rosObject
      contract←26                    ⍝ JOINT_ISO_CCITT id contract
      package←27                     ⍝ JOINT_ISO_CCITT id package
      acScheme←28                    ⍝ JOINT_ISO_CCITT id acScheme (accessControlSchemes)
      ce←29                          ⍝ JOINT_ISO_CCITT id ce (certificateExtension)
      mgt←30                         ⍝ JOINT_ISO_CCITT id mgt (managementObject)
      country←16                     ⍝ JOINT_ISO_CCITT country
      organization←1                 ⍝ JOINT_ISO_CCITT country US organization
      gov←101                        ⍝ JOINT_ISO_CCITT country US organization gov
      csor←3                         ⍝ JOINT_ISO_CCITT country US organization gov csor
      nistAlgorithm←4                ⍝ JOINT_ISO_CCITT country US organization gov csor nistAlgorithm
      aes←1                          ⍝ JOINT_ISO_CCITT country US organization gov csor nistAlgorithm aes
     
     ⍝ Table of ASN.1 Object Identifiers
      OidTab←0 4⍴⍬'ObjectIdentifier' 'Description' 'Beschreibung' ⍝ Comment
     ⍝ Deutsche Telekom
      OidTab←OidTab⍪(CCITT 2 262 1 10 7 20)'id-isismtt-at-nameDistinguisher' 'Name distinguisher' 'Unterscheidungsnummer' ⍝ id-preliminaryMember (Peter Treptow 22.09.2000)
      OidTab←OidTab⍪(CCITT 2 262 1 10 12 0)'id-isismtt-at-liabilityLimitationFlag' 'Liability limitation flag' 'Haftungsbeschränkungs-Kennzeichen'
     ⍝ BSI
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de)'bsi-de' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3)'bsi-de-applications' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1)'bsi-de-MRTD' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5)'bsi-de-id-DefectList' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5 1)'bsi-de-id-certificateDefect' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5 1)'bsi-de-id-certificateDefect' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5 1 1)'bsi-de-id-certRevoked' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5 1 2)'bsi-de-id-certReplaced' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5 2)'bsi-de-id-personalizationDefect' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5 2 1)'bsi-de-id-DGMalformed' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 1 5 2 2)'bsi-de-id-SODInvalid' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 2)'bsi-de-eID' '' ''
      OidTab←OidTab⍪(CCITT identified_organization etsi reserved etsi_identified_organization bsi_de 3 2 2)'bsi-de-id-BlackList' '' ''
     ⍝ RFC2247
      OidTab←OidTab⍪(CCITT 9 2342 19200300 100 1 1)'userID' 'User ID' 'User-ID'
      OidTab←OidTab⍪(CCITT 9 2342 19200300 100 1 25)'id-domainComponent' 'DC' 'DC'
     ⍝ SEIS(SE)
      OidTab←OidTab⍪(ISO member_body SE seis 2 1)'id-seis-pe-cn' '' ''
     ⍝ X9.57
      OidTab←OidTab⍪(ISO member_body US 10040 2 1)'holdinstruction-none' '' ''
      OidTab←OidTab⍪(ISO member_body US 10040 2 2)'holdinstruction-callissuer' '' ''
      OidTab←OidTab⍪(ISO member_body US 10040 2 3)'holdinstruction-reject' '' ''
      OidTab←OidTab⍪(ISO member_body US 10040 4 1)'dsa' 'DSA' 'DSA'
      OidTab←OidTab⍪(ISO member_body US 10040 4 3)'dsaWithSha1' 'sha1DSA' 'sha1DSA'
     ⍝ X9.62
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1)'fieldType' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 1)'prime-field' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 2)'characteristic-two-field' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 2 1)'characteristic-two-field-gnBasis' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 2 2)'characteristic-two-field-tpBasis' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 2 3)'characteristic-two-field-ppBasis' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 2 3 1)'characteristic-two-field-ppBasis-gnBasis' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 2 3 2)'characteristic-two-field-ppBasis-tpBasis' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 1 2 3 3)'characteristic-two-field-ppBasis-ppBasis' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 2)'id-public-key-type' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 2 1)'ecPublicKey' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 3)'curves' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 3 0)'curves-characteristicTwo' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 3 1)'prime' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4)'signatures' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4 1)'ecdsa-with-SHA1' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4 2)'ecdsa-with-Recommended' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4 3)'ecdsa-with-SHA2' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4 3 1)'ecdsa-with-SHA224' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4 3 2)'ecdsa-with-SHA256' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4 3 3)'ecdsa-with-SHA384' '' ''
      OidTab←OidTab⍪(ISO member_body US ansi_x962 4 3 4)'ecdsa-with-SHA512' '' ''
     ⍝ X9.42
      OidTab←OidTab⍪(ISO member_body US 10046 2 1)'dhPublicNumber' 'DH' 'DH'
     ⍝ Nortel Secure Networks
      OidTab←OidTab⍪(ISO member_body US nsn 7)'nsn' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 65)'nsn-ce' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 65 0)'entrustVersInfo' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 66)'nsn-alg' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 66 3)'cast3CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 66 10)'cast5CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 66 11)'cast5MAC' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 66 12)'pbeWithMD5AndCAST5-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 67)'nsn-oc' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 67 12)'entrustUser' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 68)'nsn-at' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 68 0)'entrustCAInfo' '' ''
      OidTab←OidTab⍪(ISO member_body US nsn 7 68 10)'nsn-attributeCertificate' '' ''
     ⍝ PKCS #1
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1)'pkcs-1' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 1)'pkcs-1-rsaEncryption' 'RSA Encryption' 'RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 2)'pkcs-1-md2WithRSAEncryption' 'MD2 with RSA Encryption' 'MD2 mit RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 3)'pkcs-1-md4WithRSAEncryption' 'MD4 with RSA Encryption' 'MD4 mit RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 4)'pkcs-1-md5WithRSAEncryption' 'MD5 with RSA Encryption' 'MD5 mit RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 5)'pkcs-1-sha1WithRSAEncryption' 'SHA1 with RSA Encryption' 'SHA1 mit RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 6)'pkcs-1-rsaOAEPEncryptionSET' 'OAEP Encryption Set' 'OAEP Verschlüsselungssatz'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 7)'pkcs-1-id-RSAES-OAEP' 'RSAES Optimal Asymetric Encryption Padding' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 8)'pkcs-1-id-mgf1' 'Mask Generation Function' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_1 9)'pkcs-1-id-id-pSpecified' 'Encoding Parameters Explicitly Specified' ''
     ⍝ PKCS #3
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_3)'pkcs-3' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_3 1)'pkcs-3-dhKeyAgreement' 'DH' 'DH'
     ⍝ PKCS #5
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5)'pkcs-5' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 1)'pkcs-5-pbeWithMD2AndDES-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 3)'pkcs-5-pbeWithMD5AndDES-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 4)'pkcs-5-pbeWithMD2AndRC2-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 6)'pkcs-5-pbeWithMD5AndRC2-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 9)'pkcs-5-pbeWithMD5AndXOR' '' ''        ⍝ Used in BSAFE only
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 10)'pkcs-5-pbeWithSHA1AndDES-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 11)'pkcs-5-pbeWithSHA1AndRC2-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 12)'pkcs-5-id-PBKDF2' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 13)'pkcs-5-id-PBES2' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_5 14)'pkcs-5-id-PBMAC1' '' ''
     ⍝ PKCS #7
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_7)'pkcs-7' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_7 1)'pkcs-7-data' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_7 2)'pkcs-7-signedData' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_7 3)'pkcs-7-envelopedData' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_7 4)'pkcs-7-signedAndEnvelopedData' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_7 5)'pkcs-7-digestData' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_7 6)'pkcs-7-encryptedData' '' ''
     ⍝ PKCS #9
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9)'pkcs-9' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 1)'pkcs-9-at-emailAddress' 'Email address' 'Email-Adresse'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 2)'pkcs-9-at-unstructuredName' 'Unstructured name' 'Unstrukturierter Name'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 3)'pkcs-9-at-contentType' 'Content type' 'Inhaltstyp'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 4)'pkcs-9-at-messageDigest' 'Message digest' 'Meldung-Digest'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 5)'pkcs-9-at-signingTime' 'Signing time' 'Zeitpunkt der Signatur'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 6)'pkcs-9-at-counterSignature' 'Counter signature' 'Gegensignatur'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 7)'pkcs-9-at-challengePassword' 'Challenge password' 'Kennwort in Frage stellen'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 8)'pkcs-9-at-unstructuredAddress' 'Unstructured address' 'Unstrukturierte Adresse'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 9)'pkcs-9-at-extendedCertificateAttributes' 'Extended certificate attributes' 'Erweiterte Zertifikatsattribute'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 10)'pkcs-9-at-issuerAndSerialNumber' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 11)'pkcs-9-at-passwordCheck' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 12)'pkcs-9-at-publicKey' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 13)'pkcs-9-at-signingDescription' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 14)'pkcs-9-at-extensionRequest' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 15)'pkcs-9-at-smimeCapabilities' 'SMIME capabilities' 'SMIME-Funktionen'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 15 1)'pkcs-9-preferSignedData' 'prefer signed data' 'Signierte Daten bevorzugen'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 15 2)'pkcs-9-canNotDecryptAny' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 15 3)'pkcs-9-receiptRequest' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 15 4)'pkcs-9-receipt' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 15 5)'pkcs-9-contentHints' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 15 6)'pkcs-9-mlExpansionHistory' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 16)'smime' 'S/MIME (RFC 2633)' 'S/MIME (RFC 2633)'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 16 2 14)'id-signatureTimeStampToken' 'Signature Timestamp attribute' 'Signatur Zeitstempel Attribut'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 20)'pkcs-9-at-friendlyName' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 21)'pkcs-9-at-localKeyId' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 22)'pkcs-9-certTypes' 'Certificate types defined in PKCS#12' 'Zertifikats-Typen definiert in PKCS#12'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 22 1)'pkcs-9-certType-x509Certificate' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 22 2)'pkcs-9-certType-sdsiCertificate' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 23)'pkcs-9-crlTypes' 'CRL types defined in PKCS#12' 'CRL-Typen definiert in PKCS#12'
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 23 1)'pkcs-9-crlType-x509CRL' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 24 1)'pkcs-9-oc-pkcsEntity' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 24 2)'pkcs-9-oc-naturalPerson' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 25 1)'pkcs-9-at-pkcs15Token' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 25 2)'pkcs-9-at-encryptedPrivateKeyInfo' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 25 3)'pkcs-9-at-randomNonce' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 25 4)'pkcs-9-at-sequenceNumber' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 25 5)'pkcs-9-at-pkcs7PDU' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 25 6)'pkcs-9-at-allegedContentType' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 26 1)'pkcs-9-sx-pkcs9String' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 26 2)'pkcs-9-sx-signingTime' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 27 1)'pkcs-9-mr-caseIgnoreMatch' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_9 27 2)'pkcs-9-mr-signingTimeMatch' '' ''
     ⍝ PKCS #12
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12)'pkcs-12' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 1)'pkcs-12PbeIds' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 1 1)'pkcs-12-pbeWithSHAAnd128BitRC4' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 1 2)'pkcs-12-pbeWithSHAAnd40BitRC4' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 1 3)'pkcs-12-pbeWithSHAAnd3-KeyTripleDES-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 1 4)'pkcs-12-pbeWithSHAAnd2-KeyTripleDES-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 1 5)'pkcs-12-pbeWithSHAAnd128BitRC2-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 1 6)'pkcs-12-pbewithSHAAnd40BitRC2-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 10 1)'pkcs-12-bagtypes' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 10 1 1)'pkcs-12-keyBag' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 10 1 2)'pkcs-12-pkcs8ShroudedKeyBag' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 10 1 3)'pkcs-12-certBag' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 10 1 4)'pkcs-12-crlBag' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 10 1 5)'pkcs-12-secretBag' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_12 10 1 6)'pkcs-12-safeContentsBag' '' ''
     ⍝ PKCS #15
      OidTab←OidTab⍪(ISO member_body US rsadsi pkcs pkcs_15 3 1)'pkcs15-ct-PKCS15Token' '' ''
     ⍝ RSADSI digest algorithms
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm)'digestAlgorithm' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 2)'digestAlgorithm-md2' 'MD2' 'MD2'
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 4)'digestAlgorithm-md4' 'MD4' 'MD4'
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 5)'digestAlgorithm-md5' 'MD5' 'MD5'
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 7)'digestAlgorithm-id-hmacWithSHA1' 'hmacSHA1' 'hmacSHA1'
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 8)'digestAlgorithm-id-hmacWithSHA224' 'hmacSHA224' 'hmacSHA224'
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 9)'digestAlgorithm-id-hmacWithSHA256' 'hmacSHA256' 'hmacSHA256'
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 10)'digestAlgorithm-id-hmacWithSHA384' 'hmacSHA384' 'hmacSHA384'
      OidTab←OidTab⍪(ISO member_body US rsadsi digestAlgorithm 11)'digestAlgorithm-id-hmacWithSHA512' 'hmacSHA512' 'hmacSHA512'
     ⍝ RSADSI encryption algorithms
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm)'encryptionAlgorithm' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 2)'encryptionAlgorithm-rc2CBC' 'RC2' 'RC2'
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 3)'encryptionAlgorithm-rc2ECB' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 4)'encryptionAlgorithm-rc4' 'RC4' 'RC4'
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 5)'encryptionAlgorithm-rc4WithMAC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 6)'encryptionAlgorithm-DESX-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 7)'encryptionAlgorithm-DES-EDE3-CBC' '3DES' '3DES'
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 8)'encryptionAlgorithm-RC5-CBC' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 9)'encryptionAlgorithm-rc5-CBC-PAD' '' ''
      OidTab←OidTab⍪(ISO member_body US rsadsi encryptionAlgorithm 10)'encryptionAlgorithm-desCDMF' '' ''
     ⍝ Microsoft
      OidTab←OidTab⍪(ISO member_body US ms 4 3)'microsoftExcel' '' ''
      OidTab←OidTab⍪(ISO member_body US ms 4 4)'titledWithOID' '' ''
      OidTab←OidTab⍪(ISO member_body US ms 4 5)'microsoftPowerPoint' '' ''
     ⍝ SMI Network Management MGMT
      OidTab←OidTab⍪(ISO org dod internet mgmt 1 2 2 1 3)'ifType' '' ''
      OidTab←OidTab⍪(ISO org dod internet mgmt 1 10)'transmission' '' ''
      OidTab←OidTab⍪(ISO org dod internet mgmt 1 10 23)'transmission.ppp' '' ''
      OidTab←OidTab⍪(ISO org dod internet mgmt 1 27)'application' '' ''
      OidTab←OidTab⍪(ISO org dod internet mgmt 1 28)'mta' '' ''
     ⍝ Microsoft (1.3.6.1.4.1.311)
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft)'ms' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 4)'ms-spcIndirectDataContext' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 10)'ms-spcSpecifiedAgencyInfo' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 11)'ms-spcStatementType' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 12)'ms-spcSpecifiedOpusInfo' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 14)'ms-spcCertExtensions' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 15)'ms-spcPeImageData' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 18)'ms-spcRawFileData' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 19)'ms-spcStructuredStorageData' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 20)'ms-spcJavaClassData' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 21)'ms-spcIndividualSpecialKeyPurpose' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 22)'ms-spcCommercialSpecialKeyPurpose' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 25)'ms-spcCabData' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 26)'ms-spcMinimalCriteria' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 27)'ms-spcFinancialCriteria' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 28)'ms-spcLink' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 29)'ms-spcHashInfo' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 1 30)'ms-spcSipiInfo' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 2 1)'ms-spcTrustedCodesigningCaList' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 2 2)'ms-spcTrustedClientAuthCaList' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 2 2 3)'ms-spcTrustedServerAuthCaList' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 3 2 1)'ms-spcTimeStampRequest' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 10 1)'ms-ct-certificateTrustList' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 10 1 1)'ms-ct-sortedCertificateTrustList' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 10 2)'ms-ct-nextUpdateLocation' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 10 3 1)'ms-kp-ctlTrustListSigning' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 10 3 2)'ms-kp-timeStampSigning' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 10 3 6)'ms-kp-nt5Crypto' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 12 1 1)'ms-catalogList' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 12 1 2)'ms-catalogListMember' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 12 2 1)'ms-catalogNameValue' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 12 2 2)'ms-catalogMemberInfo' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 16 4)'ms-ol-encryptionKeyPreference' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 17 1)'ms-csp-cryptoServiceProvider' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 17 2)'ms-csp-localMachineKeyset' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 20 1)'ms-cer-autoEnrollCtlUsage' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 20 2)'ms-ce-enrollCerttype' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 20 2 1)'ms-ce-enrollmentAgent' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 20 2 2)'ms-ce-kpSmartcardLogon' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 20 2 3)'ms-ce-ntPrincipalName' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 21)'ms-ce-certSrvInfrastructure' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 21 1)'ms-ce-certSrvCaVersion' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises microsoft 21 2)'ms-ce-certSrvPrevCertHash' '' ''
     ⍝ Digital Data Security (Cryptlib)
      OidTab←OidTab⍪(ISO org dod internet private enterprises cryptlib 32 1)'cryptlibEnvelope' '' ''
      OidTab←OidTab⍪(ISO org dod internet private enterprises cryptlib 32 2)'cryptlibPrivateKey' '' ''
     ⍝ Datev eG (1.3.6.1.4.1.3744)
      OidTab←OidTab⍪(ISO org dod internet private enterprises datev)'datev' '' ''
     ⍝ HAGER-ELECTRONICS GmbH (1.3.6.1.4.1.3761)
      OidTab←OidTab⍪(ISO org dod internet private enterprises he)'he' '' ''
     ⍝ PKIX
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix)'pkix' '' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pe)'id-pe' 'Private extension' 'Private Erweiterungen'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pe 1)'id-pe-authorityInfoAccess' 'Authority info access' 'Zugriff auf Zertifizierungsstelleninformationen'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix qt)'' 'Policy qualifier Ids' 'Richtlinien-Kriterien Ids'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix qt 1)'id-qt-cps' 'CPS' 'CPS'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix qt 2)'id-qt-unotice' 'User notice' 'Benutzerbenachrichtigung'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp)'id-kp' 'Key purpose' 'Schlüsselverwendung'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 1)'id-kp-serverAuth' 'Server authentication' 'Serverauthentifizierung'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 2)'id-kp-clientAuth' 'Client authentication' 'Clientauthentifizierung'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 3)'id-kp-codeSigning' 'Code signing' 'Codesignatur'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 4)'id-kp-emailProtection' 'Email protection' 'Sichere E-Mail'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 5)'id-kp-ipsecEndSystem' 'ipsec end system' 'IP-Sicherheitsendsystem'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 6)'id-kp-ipsecTunnel' 'ipsec tunnel' 'IP-Sicherheitstunnelabschluss'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 7)'id-kp-ipsecUser' 'ipsec user' 'IP-Sicherheitsbenutzer'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 8)'id-kp-timeStamping' 'Time stamping' 'Zeitstempel'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix kp 9)'id-kp-OCSPSigning' 'Delegated OCSP signing' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix it)'id-it' 'Information type and Value' 'Art und Wert der Information'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix it 1)'id-it-caProtEncCert' 'CA protection encryption certificates' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix it 2)'id-it-signKeyPairTypes' 'Sign key pair types' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix it 3)'id-it-encKeyPairTypes' 'Encryption key pair types' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix it 4)'id-it-preferredSymmAlg' 'Preferred symmetric algorithm' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix it 5)'id-it-caKeyUpdateInfo' 'CA key update info' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix it 6)'id-it-currentCRL' 'Current CRL' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pda)'id-pda' '' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pda 1)'id-pda-dateOfBirth' 'Date of birth' 'Geburtsdatum'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pda 2)'id-pda-placeOfBirth' 'Place of birth' 'Geburtsort'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pda 3)'id-pda-gender' 'Gender' 'Geschlecht'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pda 4)'id-pda-countryOfCitizenship' 'Country of citizenship' 'Staatsangehörigkeit'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix pda 5)'id-pda-countryOfResidence' 'Country of residence' 'Wohnsitz'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad)'authorityInfoAccessDescriptors' '' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1)'id-pkix-ocsp' 'OCSP' 'Onlinestatusprotokoll des Zertifikats'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1 1)'id-pkix-ocsp-basic' 'Basic Response Type' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1 2)'id-pkix-ocsp-nonce' 'Response to Request binding' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1 3)'id-pkix-ocsp-crl' 'CRL reference' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1 4)'id-pkix-ocsp-response' 'Acceptable response types OCSP client understands' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1 5)'id-pkix-ocsp-nocheck' 'Trust for responder lifetime' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1 6)'id-pkix-ocsp-cutoff' 'Retain revocation beyond expiration' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 1 7)'id-pkix-ocsp-service-locator' 'Route request to OCSP authoritative' ''
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 2)'id-ad-caIssuers' 'CA issuers' 'Zertifizierungsstellenaussteller'
      OidTab←OidTab⍪(ISO org dod internet security mechanisms pkix ad 3)'id-ad-timeStamping' '' ''
     ⍝ NIST Open Systems Environment (OSE) Implementor's Workshop (OIW), specialising in oddball and partially-defunct OIDs
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 2)'md4WitRSA' 'md4RSA' 'md4RSA'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 3)'md5WithRSA' 'md5RSA' 'md5RSA'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 4)'md4WithRSAEncryption' 'md4RSA' 'md4RSA'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 6)'desECB' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 7)'desCBC' 'DES' 'DES'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 8)'desOFB' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 9)'desCFB' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 10)'desMAC' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 11)'rsaSignature' '' ''        ⍝ Also X9.31 Part 1
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 12)'oiwDsa' 'DSA' 'DSA'        ⍝ Supposedly from an incomplete version of SDN.702 (does not match final SDN.702)
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 13)'dsaWithSHA' ' sha1DSA' 'sha1DSA'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 14)'mdc2WithRSASignature' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 15)'shaWithRSASignature' 'shaRSA' 'shaRSA'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 16)'dhWithCommonModulus' '' '' ⍝ Deprecated, use a plain DH OID instead
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 17)'desEDE' '' ''              ⍝ Mode is ECB
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 18)'oiwSha' 'sha' 'sha'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 19)'mdc-2' '' ''               ⍝ DES-based hash, planned for X9.31 Part 2
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 20)'dsaCommon' '' ''           ⍝ Deprecated, use a plain DSA OID instead
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 21)'dsaCommonWithSHA' '' ''    ⍝ Deprecated, use a plain dsaWithSHA OID instead
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 22)'rsaKeyTransport' 'RSA_KEYX' 'RSA_KEYX'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 23)'keyed-hash-seal' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 24)'md2WithRSASignature' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 25)'md5WithRSASignature' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 26)'id-sha1' 'SHA1' 'SHA1'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 27)'dsaWithSHA1' 'dsaSHA1' 'dsaSHA1'
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 28)'dsaWithSHA1withCommonParameters' '' ''
      OidTab←OidTab⍪(ISO org oiw secsig algorithms 29)'sha-1WithRSAEncryption' 'sha1RSA' 'sha1RSA'
      OidTab←OidTab⍪(ISO org oiw secsig 3 1)'simple-strong-auth-mechanism' '' ''
      OidTab←OidTab⍪(ISO org oiw 7 2 1 1)'ElGamal' '' ''
      OidTab←OidTab⍪(ISO org oiw 7 2 3 1)'md2WithRSA' 'md2RSA' 'md2RSA'
      OidTab←OidTab⍪(ISO org oiw 7 2 3 2)'md2WithElGamal' '' ''
      ⍝ ISIS MailTrusT (TeleTrust)
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_hash)'hashAlgorithm' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_hash 1)'hashAlgorithm-ripemd160' 'RIPEMD160' ''
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_hash 2)'hashAlgorithm-ripemd128' 'RIPEMD128' ''
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_hash 3)'hashAlgorithm-ripemd256' 'RIPEMD256' ''
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_sign)'signatureAlgorithm' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_sign 1)'signatureAlgorithm-rsaSignature' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_sign 1 2)'signatureAlgorithm-rsaSignatureWithripemd160' 'RIPEMD160 with RSA Encryption' 'RIPEMD160 mit RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_sign 1 3)'signatureAlgorithm-rsaSignatureWithripemd128' 'RIPEMD128 with RSA Encryption' 'RIPEMD128 mit RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO org isismtt id_alg id_alg_sign 1 4)'signatureAlgorithm-rsaSignatureWithripemd256' 'RIPEMD256 with RSA Encryption' 'RIPEMD256 mit RSA Verschlüsselung'
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_cp)'id-isismtt-cp' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_cp 1)'id-isismtt-cp-sigGconform' 'SigG conform certificate' 'SigG konformes Zertifikat'
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at)'id-isismtt-at' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 1)'id-isismtt-at-dateOfCertGen' 'Date of certificate generation' 'Datum der Zertifikats-Generierung'
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 2)'id-isismtt-at-procuration' 'Procuration' 'Prokura'
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 3)'id-isismtt-at-admission' 'Admission' 'Zugangsberechtigung'
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 4)'id-isismtt-at-monetaryLimit' 'Monetary Limit' 'Monitärer Limit'
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 5)'id-isismtt-at-declarationOfMajority' 'Declaration of Majority' 'Volljährigkeitserklärung'
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 6)'id-isismtt-at-iCSSN' 'ICCSN' 'ICCSN'                  ⍝ Serial number of smart card containing corresponding private key
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 7)'id-isismtt-at-pKReference' 'PKReference' 'PKReferenz' ⍝ Reference for file of smartcard storing the public key of this certificate and that is used as "security anchor"
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 9)'id-isismtt-at-retrieveIfAllowed' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 10)'id-isismtt-at-requestedCertificate' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 11)'id-isismtt-at-namingAuthorities' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 12)'id-isismtt-at-certInDirSince' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 13)'id-isismtt-at-certHash' '' ''
      OidTab←OidTab⍪(ISO org isismtt id_sig id_sig_at 14)'id-isismtt-at-nameAtBirth' 'Maiden Name' 'Mädchenname'
     ⍝ X.680 Annex E
      OidTab←OidTab⍪(JOINT_ISO_CCITT 1 0 0 0)'CharacterModule' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 1 0 1 0)'NumericString' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 1 0 1 1)'PrintableString' '' ''
     ⍝ X.208 Clause 25.2
      OidTab←OidTab⍪(JOINT_ISO_CCITT 1 1)'BasicEncodingRules' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 1 2 0)'CanonicalEncodingRules' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 1 2 1)'DistinguishedEncodingRules' '' ''
     ⍝ X.520
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 0)'id-at-objectClass' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 1)'id-at-aliasedEntryName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 1 2)'id-at-encryptedAliasedEntryName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 2)'id-at-knowledgeInformation' 'Knowledge Information' 'Informative Daten'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 3)'id-at-commonName' 'Common Name' 'Name'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 3 2)'id-at-encryptedCommonName' 'Encrypted Common Name' 'Name verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 4)'id-at-surname' 'Surname' 'Familienname'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 4 2)'id-at-encryptedSurname' 'Encrypted Surname' 'Familienname verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 5)'id-at-serialNumber' 'Serial Number' 'Serien-Nummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 5 2)'id-at-encryptedSerialNumber' 'Encrypted Serial Number' 'Serien-Nummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 6)'id-at-countryName' 'Country' 'Nation'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 6 2)'id-at-encryptedCountryName' 'Encrypted Country' 'Nation verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 7)'id-at-localityName' 'Locality Name' 'Stadt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 7 2)'id-at-encryptedLocalityName' 'Encrypted Locality' 'Stadt verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 7 1)'id-at-collectiveLocalityName' 'Collective Locality' 'Sammelbegriff Stadt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 7 1 2)'id-at-encryptedCollectiveLocalityName' 'Encrypted Collective Locality' 'Stadt verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 8)'id-at-stateOrProvinceName' 'State' 'Land'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 8 2)'id-at-encryptedStateOrProvinceName' 'Encrypted State' 'Land verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 8 1)'id-at-collectiveStateOrProvinceName' 'Collective State' 'Sammelbegriff Land'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 8 1 2)'id-at-encryptedCollectiveStateOrProvinceName' 'Encrypted Collective State' 'Sammelbegriff Land verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 9)'id-at-streetAddress' 'Street' 'Straße'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 9 2)'id-at-encryptedStreetAddress' 'Encrypted Street' 'Straße verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 9 1)'id-at-collectiveStreetAddress' 'Collective Street' 'Sammelbegriff Straße'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 9 1 2)'id-at-encryptedCollectiveStreetAddress' 'Encrypted Collective Street' 'Sammelbegriff Straße verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 10)'id-at-organizationName' 'Organization' 'Betrieb'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 10 2)'id-at-encryptedOrganizationName' 'Encrypted Organization' 'Betrieb verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 10 1)'id-at-collectiveOrganizationName' 'Collective Organization' 'Sammelbegriff Betrieb'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 10 1 2)'id-at-encryptedCollectiveOrganizationName' 'Encrypted Collective Organization' 'Sammelbegriff Betrieb verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 11)'id-at-organizationalUnitName' 'Organizational Unit' 'Abteilung'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 11 2)'id-at-encryptedOrganizationalUnitName' 'Encrypted Organizational Unit' 'Abteilung verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 11 1)'id-at-collectiveOrganizationalUnitName' 'Collective Organizational Unit' 'Sammelbegriff Abteilung'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 11 1 2)'id-at-encryptedCollectiveOrganizationalUnitName' 'Encrypted Collective Organizational Unit' 'Sammelbegriff Abteilung verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 12)'id-at-title' 'Title' 'Titel'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 12 2)'id-at-encryptedTitle' 'Encrypted Title' 'Titel verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 13)'id-at-description' 'Description' 'Beschreibung'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 13 2)'id-at-encryptedDescription' 'Encrypted Description' 'Beschreibung verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 14)'id-at-searchGuide' 'Search Guide' 'Suchhilfe'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 14 2)'id-at-encryptedSearchGuide' 'Encrypted Search Guide' 'Suchhilfe verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 15)'id-at-businessCategory' 'Business Category' 'Berufsbezeichnung'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 15 2)'id-at-encryptedBusinessCategory' 'Encrypted Business Category' 'Berufsbezeichnung verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 16)'id-at-postalAddress' 'Postal Address' 'Postanschrift'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 16 2)'id-at-encryptedPostalAddress' 'Encrypted Postal Address' 'Postanschrift verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 16 1)'id-at-collectivePostalAddress' 'Collective Postal Address' 'Sammelbegriff Postanschrift'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 16 1 2)'id-at-encryptedCollectivePostalAddress' 'Encrypted Collective Postal Address' 'Sammelbegriff Postanschrift verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 17)'id-at-postalCode' 'Postal Code' 'Postleitzahl'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 17 2)'id-at-encryptedPostalCode' 'Encrypted Postal Code' 'Postleitzahl verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 17 1)'id-at-collectivePostalCode' 'Collective Postal Code' 'Sammelbegriff Postleitzahl'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 17 1 2)'id-at-encryptedCollectivePostalCode' 'Encrypted Collective Postal Code' 'Sammelbegriff Postleitzahl verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 18)'id-at-postOfficeBox' 'Post Office Box' 'Postfach'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 18 2)'id-at-encryptedPostOfficeBox' 'Encrypted Post Office Box' 'Postfach verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 18 1)'id-at-collectivePostOfficeBox' 'Collective Post Office Box' 'Sammelbegriff Postfach'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 18 1 2)'id-at-encryptedCollectivePostOfficeBox' 'Encrypted Collective Post Office Box' 'Sammelbegriff Postfach verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 19)'id-at-physicalDeliveryOfficeName' 'Physical Delivery Office' 'Postzustellamt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 19 2)'id-at-encryptedPhysicalDeliveryOfficeName' 'Encrypted Physical Delivery Office' 'Postzustellamt verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 19 1)'id-at-collectivePhysicalDeliveryOfficeName' 'Collective Physical Delivery Office' 'Sammelbegriff Postzustellamt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 19 1 2)'id-at-encryptedCollectivePhysicalDeliveryOfficeName' 'Encrypted Collective Physical Delivery Office' 'Sammelbegriff Postzustellamt verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 20)'id-at-telephoneNumber' 'Telephone Number' 'Telefonnummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 20 2)'id-at-encryptedTelephoneNumber' 'Encrypted Telephone Number' 'Telefonnummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 20 1)'id-at-collectiveTelephoneNumber' 'Collective Telephone Number' 'Sammelbegriff Telefonnummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 20 1 2)'id-at-encryptedCollectiveTelephoneNumber' 'Encrypted Collective Telephone Number' 'Sammelbegriff Telefonnummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 21)'id-at-telexNumber' 'Telex Number' 'Telexnummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 21 2)'id-at-encryptedTelexNumber' 'Encrypted Telex Number' 'Telexnummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 21 1)'id-at-collectiveTelexNumber' 'Collective Telex Number' 'Sammelbegriff Telexnummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 21 1 2)'id-at-encryptedCollectiveTelexNumber' 'Encrypted Collective Telex Number' 'Sammelbegriff Telexnummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 22)'id-at-teletexTerminalIdentifier' 'Teletex Terminal Identifier' 'Teletex Terminal Identifikation'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 22 2)'id-at-encryptedTeletexTerminalIdentifier' 'Encrypted Teletex Terminal Identifier' 'Teletex Terminal Identifikation verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 22 1)'id-at-collectiveTeletexTerminalIdentifier' 'Collective Teletex Terminal Identifier' 'Sammelbegriff Teletex Terminal Identifikation'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 22 1 2)'id-at-encryptedCollectiveTeletexTerminalIdentifier' 'Encrypted Collective Teletex Terminal Identifier' 'Sammelbegriff Teletex Terminal Identifikation verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 23)'id-at-facsimileTelephoneNumber' 'Facsimile Telephone Number' 'Fax-Nummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 23 2)'id-at-encryptedFacsimileTelephoneNumber' 'Encrypted Facsimile Telephone Number' 'Fax-Nummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 23 1)'id-at-collectiveFacsimileTelephoneNumber' 'Collective Facsimile Telephone Number' 'Sammelbegriff Fax-Nummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 23 1 2)'id-at-encryptedCollectiveFacsimileTelephoneNumber' 'Encrypted Collective Facsimile Telephone Number' 'Sammelbegriff Fax-Nummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 24)'id-at-x121Address' 'X.121 Address' 'X.121 Adresse'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 24 2)'id-at-encryptedX121Address' 'Encrypted X.121 Address' 'X.121 Adresse verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 25)'id-at-internationalISDNNumber' 'International ISDN Number' 'Internationale ISDN-Nummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 25 2)'id-at-encryptedInternationalISDNNumber' 'Encrypted International ISDN Number' 'Internationale ISDN-Nummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 25 1)'id-at-collectiveInternationalISDNNumber' 'Collective International ISDN Number' 'Sammelbegriff internationale ISDN-Nummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 25 1 2)'id-at-encryptedCollectiveInternationalISDNNumber' 'Encrypted Collective International ISDN Number' 'Sammelbegriff internationale ISDN-Nummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 26)'id-at-registeredAddress' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 26 2)'id-at-encryptedRegisteredAddress' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 27)'id-at-destinationIndicator' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 27 2)'id-at-encryptedDestinationIndicator' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 28)'id-at-preferredDeliveryMethod' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 28 2)'id-at-encryptedPreferredDeliveryMethod' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 29)'id-at-presentationAddress' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 29 2)'id-at-encryptedPresentationAddress' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 30)'id-at-supportedApplicationContext' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 30 2)'id-at-encryptedSupportedApplicationContext' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 31)'id-at-member' 'Member' 'Mitglied'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 31 2)'id-at-encryptedMember' 'Encrypted Member' 'Mitglied verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 32)'id-at-owner' 'Owner' 'Inhaber'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 32 2)'id-at-encryptedOwner' 'Encrypted Owner' 'Inhaber verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 33)'id-at-roleOccupant' 'Role Occupant' 'Rechtsinhaber'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 33 2)'id-at-encryptedRoleOccupant' 'Encrypted Role Occupant' 'Rechtsinhaber verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 34)'id-at-seeAlso' 'See Also' 'Siehe auch'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 34 2)'id-at-encryptedSeeAlso' 'Encrypted See Also' 'Siehe auch verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 35)'id-at-userPassword' 'User Password' 'Anwender Passwort'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 35 2)'id-at-encryptedUserPassword' 'Encrypted User Password' 'Anwender Passwort verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 36)'id-at-userCertificate' 'User Certificate' 'Anwender Zertifikat'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 36 2)'id-at-encryptedUserCertificate' 'Encrypted User Certificate' 'Anwender Zertifikat verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 37)'id-at-cACertificate' 'CA Certificate' 'CA Zertifikat'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 37 2)'id-at-encryptedCACertificate' 'Encrypted CA Certificate' 'CA Zertifikat verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 38)'id-at-authorityRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 38 2)'id-at-encryptedAuthorityRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 39)'id-at-certificateRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 39 2)'id-at-encryptedCertificateRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 40)'id-at-crossCertificatePair' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 40 2)'id-at-encryptedCrossCertificatePair' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 41)'id-at-name' 'Name' 'Name'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 42)'id-at-givenName' 'Given Name' 'Vorname'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 42 2)'id-at-encryptedGivenName' 'Encrypted Given Name' 'Vorname verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 43)'id-at-initials' 'Initials' 'Initialen'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 43 2)'id-at-encryptedInitials' 'Encrypted Initials' 'Initialen verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 44)'id-at-generationQualifier' 'Generation Qualifier' 'Generations-Zusatz'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 44 2)'id-at-encryptedGenerationQualifier' 'Encrypted Generation Qualifier' 'Generations-Zusatz verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 45)'id-at-uniqueIdentifier' 'Unique Identifier' 'Eindeutige Identifikation'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 45 2)'id-at-encryptedUniqueIdentifier' 'Encrypted Unique Identifier' 'Eindeutige Identifikation verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 46)'id-at-dnQualifier' 'dnQualifier' 'dnQualifier'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 46 2)'id-at-encryptedDnQualifier' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 47)'id-at-enhancedSearchGuide' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 47 2)'id-at-encryptedEnhancedSearchGuide' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 48)'id-at-protocolInformation' 'Protocol Information' 'Protokoll-Information'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 48 2)'id-at-encryptedProtocolInformation' 'Encrypted Protocol Information' 'Protokoll-Information verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 49)'id-at-distinguishedName' 'Distinguished Name' 'Unterscheidungs-Name'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 49 2)'id-at-encryptedDistinguishedName' 'Encrypted Distinguished Name' 'Unterscheidungs-Name verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 50)'id-at-uniqueMember' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 50 2)'id-at-encryptedUniqueMember' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 51)'id-at-houseIdentifier' 'House Identifier' 'Hausnummer'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 51 2)'id-at-encryptedHouseIdentifier' 'Encrypted House Identifier' 'Hausnummer verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 52)'id-at-supportedAlgorithms' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 52 2)'id-at-encryptedSupportedAlgorithms' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 53)'id-at-deltaRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 53 2)'id-at-encryptedDeltaRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 54)'id-at-dmdName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 54 2)'id-at-encryptedDmdName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 55)'id-at-clearance' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 55 2)'id-at-encryptedClearance' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 56)'id-at-defaultDirQop' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 56 2)'id-at-encryptedDefaultDirQop' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 57)'id-at-attributeIntegrityInfo' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 57 2)'id-at-encryptedAttributeIntegrityInfo' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 58)'id-at-attributeCertificate' 'Attribute Certificate' 'Zertifikats-Attribut'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 58 2)'id-at-encryptedAttributeCertificate' 'Encrypted Attribute Certificate' 'Zertifikats-Attribut verschlüsselt'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 59)'id-at-attributeCertificateRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 59 2)'id-at-encryptedAttributeCertificateRevocationList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 60)'id-at-confKeyInfo' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 60 2)'id-at-encryptedConfKeyInfo' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id at 65)'id-at-pseudonym' 'pseudonym' 'Pseudonym'
     ⍝ X.500 algorithms
      OidTab←OidTab⍪(JOINT_ISO_CCITT id algorithm)'X.500-Algorithms' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id algorithm 1)'X.500-Alg-Encryption' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id algorithm 1 1)'rsa' '' '' ⍝ Ambiguous, since no padding rules specified
     ⍝ X.509.  Some of the smaller values are from early X.509 drafts with cross-pollination from X9.55 and are now deprecated.  Alternative OIDs are marked if these are known.  In some cases there are multiple generations of superseded OIDs
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 1)'id-ce-draft-authorityKeyIdentifier' 'Authority key identifier' 'Stellenschlüssel-ID' ⍝ Deprecated, use (2 5 29 35) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 2)'id-ce-keyAttributes' 'Key attributes' 'Schlüsselattribute' ⍝ Deprecated, alternative OID uncertain
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 3)'id-ce-draft-certificatePolicies' '' ''        ⍝ Deprecated, use (2 5 29 32) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 4)'id-ce-keyUsageRestriction' 'Key usage restriction' 'Einschränkung der Schlüsselverwendung' ⍝ Deprecated, alternative OID uncertain
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 5)'id-ce-draft-policyMappings' '' ''             ⍝ Deprecated, use (2 5 29 33) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 6)'id-ce-subtreesConstraint' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 7)'id-ce-draft-subjectAltName' 'Subject alt name' 'Alternativer Antragstellername' ⍝ Deprecated, use (2 5 29 17) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 8)'id-ce-draft-issuerAltName' 'Issuer alt name' 'Alternativer Ausstellername' ⍝ Deprecated, use (2 5 29 18) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 9)'id-ce-subjectDirectoryAttributes' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 10)'id-ce-draft-basicConstraints' 'Basic constraints' 'Basiseinschränkungen' ⍝ Deprecated, use (2 5 29 19) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 11)'id-ce-draft-nameConstraints' '' ''           ⍝ Deprecated, use (2 5 29 30) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 12)'id-ce-draft-policyConstraints' '' ''         ⍝ Deprecated, use (2 5 29 36) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 13)'id-ce-draft2-basicConstraints' '' ''         ⍝ Deprecated, use (2 5 29 19) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 14)'id-ce-subjectKeyIdentifier' 'Subject key identifier' 'Schlüssel-ID des Antragstellers'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 15)'id-ce-keyUsage' 'Key usage' 'Schlüsselverwendung'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 16)'id-ce-privateKeyUsagePeriod' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 17)'id-ce-subjectAltName' 'Subject alt name' 'Alternativer Antragstellername'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 18)'id-ce-issuerAltName' 'Issuer alt name' 'Alternativer Ausstellername'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 19)'id-ce-basicConstraints' 'Basic constraints' 'Basiseinschränkungen'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 20)'id-ce-cRLNumber' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 21)'id-ce-reasonCode' 'CRL reason code' 'CRL-Grundcode'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 22)'id-ce-expirationDate' '' ''                  ⍝ Deprecated, alternative OID uncertain
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 23)'id-ce-holdInstructionCode' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 24)'id-ce-invalidityDate' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 25)'id-ce-cRLDistributionPoints' '' ''           ⍝ Deprecated
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 26)'id-ce-draft-issuingDistributionPoint' '' ''  ⍝ Deprecated, use (2 5 29 28) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 27)'id-ce-deltaCRLIndicator' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 28)'id-ce-issuingDistributionPoint' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 29)'id-ce-certificateIssuer' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 30)'id-ce-nameConstraints' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 31)'id-ce-cRLDistPoints' 'CRL distribution points' 'CRL-Verteilungspunkte'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 32)'id-ce-certificatePolicies' 'Certificate policies' 'Zertifikatsrichtlinien'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 33)'id-ce-policyMappings' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 34)'id-ce-draft2-policyConstraints' '' ''        ⍝ Deprecated, use (2 5 29 36) instead
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 35)'id-ce-authorityKeyIdentifier' 'Authority key identifier' 'Stellenschlüssel-ID'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 36)'id-ce-policyConstraints' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 37)'id-ce-extKeyUsage' 'Extended key usage' 'Erweiterte Schlüsselverwendung'
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 38)'id-ce-authorityAttributeIdentifier' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 39)'id-ce-ownerAttributeIdentifier' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 40)'id-ce-delegatorAttributeIdentifier' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 41)'id-ce-basicAttConstraints' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 42)'id-ce-attributeNameConstraints' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 43)'id-ce-timeSpecification' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 44)'id-ce-crlScope' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 45)'id-ce-statusReferrals' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 46)'id-ce-freshestCRL' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 47)'id-ce-orderedList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 48)'id-ce-attributeDescriptor' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT id ce 49)'id-ce-crossPrivilege' '' ''
     ⍝
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US 1 101 3)'csor' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US 1 101 3 4)'nistAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US 1 101 3 4 2)'hashAlgs' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US 1 101 3 4 2 1)'sha256' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US 1 101 3 4 2 2)'sha384' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US 1 101 3 4 2 3)'sha512' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US 1 101 3 4 2 4)'sha224' '' ''
     ⍝ DMS-SDN-702
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 1)'sdnsSignatureAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 2)'mosaicSignatureAlgorithm' '' '' ⍝ This OID is better known as dsaWithSHA-1
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 3)'sdnsConfidentialityAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 4)'mosaicConfidentialityAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 5)'sdnsIntegrityAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 6)'mosaicIntegrityAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 7)'sdnsTokenProtectionAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 8)'mosaicTokenProtectionAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 9)'sdnsKeyManagementAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 10)'mosaicKeyManagementAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 11)'sdnsKMandSigAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 12)'mosaicKMandSigAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 13)'SuiteASignatureAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 14)'SuiteAConfidentialityAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 15)'SuiteAIntegrityAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 16)'SuiteATokenProtectionAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 17)'SuiteAKeyManagementAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 18)'SuiteAKMandSigAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 19)'mosaicUpdatedSigAlgorithm' 'mosaicUpdatedSig' 'mosaicUpdatedSig'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 20)'mosaicKMandUpdSigAlgorithms' 'mosaicKMandUpdSig' 'mosaicKMandUpdSig'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 21)'mosaicUpdatedIntegAlgorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises 101 2 1 1 22)'mosaicKeyEncryptionAlgorithm' '' ''
     ⍝ Netscape
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 1)'cert-type' 'Netscape Certificate Type' 'Netscape Zertifikats-Typ'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 2)'base-url' 'NetscapeBaseURL' 'NetscapeBaseURL'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 3)'revocation-url' 'NetscapeRevocationURL' 'NetscapeRevocationURL'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 4)'ca-revocation-url' 'NetscapeCARevocationURL' 'NetscapeCARevocationURL'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 5)'cert-sequence' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 6)'cert-url' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 7)'renewal-url' 'NetscapeCertRenewalURL' 'NetscapeCertRenewalURL'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 8)'ca-policy-url' 'NetscapeCAPolicyURL' 'NetscapeCAPolicyURL'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 9)'HomePage-url' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 10)'EntityLogo' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 11)'UserPicture' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 12)'ssl-server-name' 'NetscapeSSLServerName' 'NetscapeSSLServerName'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape cert_extension 13)'comment' 'NetscapeComment' 'NetscapeComment'
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape 2)'data-type' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape data_type 1)'GIF' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape data_type 2)'JPEG' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape data_type 3)'URL' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape data_type 4)'HTML' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape data_type 5)'CertSeq' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape 3)'directory' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US enterprises netscape 3 1 216)'pkcs-9-at-userPKCS12' '' ''
     ⍝ NIST
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US organization gov csor nistAlgorithm aes 2)'aes128-CBC-PAD' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US organization gov csor nistAlgorithm aes 22)'aes192-CBC-PAD' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT country US organization gov csor nistAlgorithm aes 42)'aes256-CBC-PAD' '' ''
     ⍝ SET
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 0 0)'PANData' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 0 1)'PANToken' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 0 2)'PANOnly' '' ''
     ⍝ And on and on and on for another 80-odd OIDs which I'm not going to type in
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 1)'msgExt' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2)'field' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 0)'fullName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 1)'givenName2' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 2)'familyName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 3)'birthFamilyName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 4)'placeName' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 5)'identificationNumber' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 6)'month' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 7)'date' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 8)'address' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 9)'telephone' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 10)'amount' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 11)'accountNumber' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 2 12)'passPhrase' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 3)'attribute' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 3 0)'cert' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 3 0 0)'rootKeyThumb' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 3 0 1)'additionalPolicy' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 4)'algorithm' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 5)'policy' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 5 0)'root' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 6)'module' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7)'certExt' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7 0)'hashedRootKey' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7 1)'certificateType' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7 2)'merchantData' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7 3)'cardCertRequired' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7 4)'tunneling' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7 5)'setExtensions' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 7 6)'setQualifier' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 8)'brand' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 8 1)'IATA-ATA' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 8 4)'VISA' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 8 5)'MasterCard' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 8 30)'Diners' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 8 34)'AmericanExpress' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 8 6011)'Novus' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9)'vendor' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 0)'GlobeSet' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 1)'IBM' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 2)'CyberCash' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 3)'Terisa' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 4)'RSADSI' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 5)'VeriFone' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 6)'TrinTech' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 7)'BankGate' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 8)'GTE' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 9)'CompuSource' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 10)'Griffin' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 11)'Certicom' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 12)'OSS' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 13)'TenthMountain' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 14)'Antares' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 15)'ECC' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 16)'Maithean' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 17)'Netscape' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 18)'Verisign' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 19)'BlueMoney' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 20)'Lacerte' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 21)'Fujitsu' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 22)'eLab' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 23)'Entrust' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 24)'VIAnet' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 25)'III' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 26)'OpenMarket' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 27)'Lexem' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 28)'Intertrader' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 29)'Persimmon' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 30)'NABLE' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 31)'espace-net' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 32)'Hitachi' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 33)'Microsoft' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 34)'NEC' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 35)'Mitsubishi' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 36)'NCR' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 37)'e-COMM' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 9 38)'Gemplus' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 10)'national' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 42 10 192)'Japan' '' ''
     ⍝
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 136)'id-icao' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 136 1)'id-icao-mrtd' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 136 1 1)'id-icao-mrtd-security' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 136 1 1 2)'id-icao-cscaMasterList' '' ''
      OidTab←OidTab⍪(JOINT_ISO_CCITT 23 136 1 1 3)'id-icao-cscaMasterListSigningKey' '' ''
    ∇

    OPTIONAL←{⍵:⍺ ⋄ ''}

    :Namespace Base64
        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        BaseDecode←{{#.Win.TxtInt(-64+.=⍵)↓,⍉⌊256 256 256⊤{64⊥⍉⍵{⍵⍴(×/⍵)↑⍺}(⌈(↑⍴⍵)÷4)4}(64>⍵)/⍵}¯1+'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='⍳⍵}

        BaseEncode←{'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'[1+,⍉⌊64 64 64 64⊤{256⊥256|⍉⍵{⍵⍴(×/⍵)↑⍺}(⌈(↑⍴⍵)÷3)3}#.Win.IntTxt ⍵]{((-⍵)↓⍺),⍵⍴'='}3|-↑⍴⍵}

        ∇ Data←Decode Text;Delimiter;Count
          :If ≠/Count←+/Delimiter←⍉⊃∨/1 1 2 2⊂⍉∨/¨'--BEGIN ' '--END ' '- BEGIN ' '- END '∘.⍷#.Uppercase Text←{(~⍵∊⎕TC)⊂⍵}Text
              Data←0 3⍴⊂''
          :ElseIf 0 0≡Count
              Data←1 3⍴('')(0 2⍴⊂'')(BaseDecode↑,/Text)
          :Else
              Data←{('-'≠⍵)/¨⍵}{(7+(∨⌿'- BEGIN ' '--BEGIN '∘.⍷#.Uppercase ⍵)⍳¨1)↓¨⍵}Delimiter[1;]/Text
              Text←({(~∨⌿⍵)×+⌿+\⍵}Delimiter)⊂Text
              Data,[1.5]←⊃¨{{(' '≠⍵)/⍵}¨2⍴(~⍵∊':')⊂⍵}¨¨{(':'∊¨⍵)/⍵}¨Text
              Data,←BaseDecode¨{×↑⍴⍵:↑,/⍵ ⋄ ''}∘{(~':'∊¨⍵)/⍵}¨Text
          :EndIf
        ∇

        ∇ Text←Encode Data
          :If 0≠↑⍴↑Data
              Text←,∘⊂¨'-----BEGIN '∘,¨Data[;1],¨⊂'-----'
              Text,¨←{⍺,': ',⍵}/¨Data[;2]
              Text,¨←(0≠↑∘⍴¨Data[;2])⍴¨⊂,⊂''
              Text,¨←{(+\(⍴⍵)⍴64↑1)⊂⍵}¨BaseEncode¨Data[;3]
              Text,¨←,∘⊂¨'-----END '∘,¨Data[;1],¨⊂'-----'
              Text←↑,/Text
          :ElseIf 0≠↑⍴Data
              Text←↑,/{(+\(⍴⍵)⍴64↑1)⊂⍵}¨BaseEncode¨Data[;3]
          :Else
              Text←''
          :EndIf
          Text←∊Text,¨⎕TC[3]
        ∇

    :EndNamespace
    :Namespace LDAP
        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        ∇ StringRepresentation←ConvertNameToString DistinguishedName;ReplaceEscapes;ReplaceFirst;ReplaceLast;ConcatenateWithPlus;ConcatenateWithComma;RelativeDistinguishedName;AttributeTypeAndValue;Tag;AttributeType;AttributeValue;Type;Name;Value;NameValue;id_isismtt_at_nameDistinguisher;id_isismtt_at_liabilityLimitationFlag;id_domainComponent;pkcs_9_emailAddress;pkcs_9_unstructuredName;pkcs_9_unstructuredAddress;id_ldap_namingContexts;id_ldap_altServer;id_ldap_supportedExtension;id_ldap_supportedControl;id_ldap_supportedSASLMechanisms;id_ldap_supportedLDAPVersion;id_ldap_ldapSyntaxes;id_pda_dateOfBirth;id_pda_placeOfBirth;id_pda_gender;id_pda_countryOfCitizenship;id_pda_countryOfResidence;id_isismtt_at_nameAtBirth;id_at_objectClass;id_at_aliasedEntryName;id_at_knowledgeInformation;id_at_commonName;id_at_surname;id_at_serialNumber;id_at_countryName;id_at_localityName;id_at_stateOrProvinceName;id_at_streetAddress;id_at_organizationName;id_at_organizationalUnitName;id_at_title;id_at_description;id_at_searchGuide;id_at_businessCategory;id_at_postalAddress;id_at_postalCode;id_at_postOfficeBox;id_at_physicalDeliveryOfficeName;id_at_telephoneNumber;id_at_telexNumber;id_at_teletexTerminalIdentifier;id_at_facsimileTelephoneNumber;id_at_x121Address;id_at_internationalISDNNumber;id_at_registeredAddress;id_at_destinationIndicator;id_at_preferredDeliveryMethod;id_at_presentationAddress;id_at_supportedApplicationContext;id_at_member;id_at_owner;id_at_roleOccupant;id_at_seeAlso;id_at_userPassword;id_at_userCertificate;id_at_cACertificate;id_at_authorityRevocationList;id_at_certificateRevocationList;id_at_crossCertificatePair;id_at_name;id_at_givenName;id_at_initials;id_at_generationQualifier;id_at_uniqueIdentifier;id_at_dnQualifier;id_at_enhancedSearchGuide;id_at_protocolInformation;id_at_distinguishedName;id_at_uniqueMember;id_at_houseIdentifier;id_at_supportedAlgorithms;id_at_deltaRevocationList;id_at_dmdName;id_at_pseudonym;id_oa_createTimestamp;id_oa__modifyTimestamp;id_oa__creatorsName;id_oa__modifiersName;id_oa__subschemaSubentry;id_sa_dITStructureRules;id_sa_dITContentRules;id_sa_matchingRules;id_sa_attributeTypes;id_sa_objectClasses;id_sa_nameForms;id_sa_matchingRuleUse
     ⍝ Konvertierung eines AttributeValue von ASN.1 in einen String gemäß RFC2253 (LDAPv3: UTF-8 String Representation of Distinguished Names)
     ⍝ Attribute aus RFC2252,Kap.5, RFC2256,Kap.5, etc
     ⍝
     ⍝ DistinguishedName     = Vektor von AttributeTypeAndValue (Resultat von #.ASN1.X509.GetCertificateSubject oder #.ASN1.X509.GetCertificateIssuer)
     ⍝ StringRepresentation  = Vektor von Directory System Names
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
          ReplaceEscapes←(⊂[1]'' '\'∘.,',+"\<>;')∘#.Replace
          ReplaceFirst←{(↑⍵)∊' #':'\',⍵ ⋄ ⍵}
          ReplaceLast←{' '=↑⌽⍵:{'\ '≢⍵:(¯1↓⍵),'\ ' ⋄ ⍵}⍵ ⋄ ⍵}
          ConcatenateWithPlus←{0∊⍴⍺:⍵ ⋄ 0∊⍴⍵:⍺ ⋄ ⍺,'+',⍵}
          ConcatenateWithComma←{0∊⍴⍺:⍵ ⋄ 0∊⍴⍵:⍺ ⋄ ⍺,',',⍵}
     ⍝
          id_isismtt_at_nameDistinguisher←0 2 262 1 10 7 20
          id_isismtt_at_liabilityLimitationFlag←0 2 262 1 10 12 0
          id_domainComponent←0 9 2342 19200300 100 1 25
          pkcs_9_emailAddress←1 2 840 113549 1 9 1
          pkcs_9_unstructuredName←1 2 840 113549 1 9 2
          pkcs_9_unstructuredAddress←1 2 840 113549 1 9 8
          id_ldap_namingContexts←1 3 6 1 4 1 1466 101 120 5
          id_ldap_altServer←1 3 6 1 4 1 1466 101 120 6
          id_ldap_supportedExtension←1 3 6 1 4 1 1466 101 120 7
          id_ldap_supportedControl←1 3 6 1 4 1 1466 101 120 13
          id_ldap_supportedSASLMechanisms←1 3 6 1 4 1 1466 101 120 14
          id_ldap_supportedLDAPVersion←1 3 6 1 4 1 1466 101 120 15
          id_ldap_ldapSyntaxes←1 3 6 1 4 1 1466 101 120 16
          id_pda_dateOfBirth←1 3 6 1 5 5 7 9 1
          id_pda_placeOfBirth←1 3 6 1 5 5 7 9 2
          id_pda_gender←1 3 6 1 5 5 7 9 3
          id_pda_countryOfCitizenship←1 3 6 1 5 5 7 9 4
          id_pda_countryOfResidence←1 3 6 1 5 5 7 9 5
          id_isismtt_at_nameAtBirth←1 3 36 8 3 14
          id_at_objectClass←2 5 4 0
          id_at_aliasedEntryName←2 5 4 1
          id_at_knowledgeInformation←2 5 4 2
          id_at_commonName←2 5 4 3
          id_at_surname←2 5 4 4
          id_at_serialNumber←2 5 4 5
          id_at_countryName←2 5 4 6
          id_at_localityName←2 5 4 7
          id_at_stateOrProvinceName←2 5 4 8
          id_at_streetAddress←2 5 4 9
          id_at_organizationName←2 5 4 10
          id_at_organizationalUnitName←2 5 4 11
          id_at_title←2 5 4 12
          id_at_description←2 5 4 13
          id_at_searchGuide←2 5 4 14
          id_at_businessCategory←2 5 4 15
          id_at_postalAddress←2 5 4 16
          id_at_postalCode←2 5 4 17
          id_at_postOfficeBox←2 5 4 18
          id_at_physicalDeliveryOfficeName←2 5 4 19
          id_at_telephoneNumber←2 5 4 20
          id_at_telexNumber←2 5 4 21
          id_at_teletexTerminalIdentifier←2 5 4 22
          id_at_facsimileTelephoneNumber←2 5 4 23
          id_at_x121Address←2 5 4 24
          id_at_internationalISDNNumber←2 5 4 25
          id_at_registeredAddress←2 5 4 26
          id_at_destinationIndicator←2 5 4 27
          id_at_preferredDeliveryMethod←2 5 4 28
          id_at_presentationAddress←2 5 4 29
          id_at_supportedApplicationContext←2 5 4 30
          id_at_member←2 5 4 31
          id_at_owner←2 5 4 32
          id_at_roleOccupant←2 5 4 33
          id_at_seeAlso←2 5 4 34
          id_at_userPassword←2 5 4 35
          id_at_userCertificate←2 5 4 36
          id_at_cACertificate←2 5 4 37
          id_at_authorityRevocationList←2 5 4 38
          id_at_certificateRevocationList←2 5 4 39
          id_at_crossCertificatePair←2 5 4 40
          id_at_name←2 5 4 41
          id_at_givenName←2 5 4 42
          id_at_initials←2 5 4 43
          id_at_generationQualifier←2 5 4 44
          id_at_uniqueIdentifier←2 5 4 45
          id_at_dnQualifier←2 5 4 46
          id_at_enhancedSearchGuide←2 5 4 47
          id_at_protocolInformation←2 5 4 48
          id_at_distinguishedName←2 5 4 49
          id_at_uniqueMember←2 5 4 50
          id_at_houseIdentifier←2 5 4 51
          id_at_supportedAlgorithms←2 5 4 52
          id_at_deltaRevocationList←2 5 4 53
          id_at_dmdName←2 5 4 54
          id_at_pseudonym←2 5 4 65
          id_oa_createTimestamp←2 5 18 1
          id_oa__modifyTimestamp←2 5 18 2
          id_oa__creatorsName←2 5 18 3
          id_oa__modifiersName←2 5 18 4
          id_oa__subschemaSubentry←2 5 18 10
          id_sa_dITStructureRules←2 5 21 1
          id_sa_dITContentRules←2 5 21 2
          id_sa_matchingRules←2 5 21 4
          id_sa_attributeTypes←2 5 21 5
          id_sa_objectClasses←2 5 21 6
          id_sa_nameForms←2 5 21 7
          id_sa_matchingRuleUse←2 5 21 8
     ⍝
          :If 0∊⍴DistinguishedName←¯5 ##.Code DistinguishedName
              StringRepresentation←''
              :Return
          :ElseIf ##.SEQUENCE≢↑DistinguishedName
              StringRepresentation←''
              #.RCode←#.Win.CRYPT_E_ASN1_BADTAG
              :Return
          :Else
              StringRepresentation←''
              :For RelativeDistinguishedName :In ⌽1↓DistinguishedName
                  :If ##.SET≢↑RelativeDistinguishedName
                      StringRepresentation←''
                      #.RCode←#.Win.CRYPT_E_ASN1_BADTAG
                      :Return
                  :Else
                      NameValue←''
                      :For AttributeTypeAndValue :In ⌽1↓RelativeDistinguishedName
                          :If 3≠↑⍴AttributeTypeAndValue
                          :OrIf ##.SEQUENCE≢↑Tag AttributeType AttributeValue←AttributeTypeAndValue
                          :OrIf 2≠↑⍴AttributeType
                          :OrIf ##.OID≢↑Tag Type←AttributeType
                              StringRepresentation←''
                              #.RCode←#.Win.CRYPT_E_ASN1_BADTAG
                              :Return
                          :Else
                              :Select Type
                              :Case id_at_commonName ⋄ Name←'CN'
                              :Case id_at_surname ⋄ Name←'SN'
                              :Case id_at_countryName ⋄ Name←'C'
                              :Case id_at_localityName ⋄ Name←'L'
                              :Case id_at_stateOrProvinceName ⋄ Name←'ST'
                              :Case id_at_organizationName ⋄ Name←'O'
                              :Case id_at_organizationalUnitName ⋄ Name←'OU'
                              :Case pkcs_9_emailAddress ⋄ Name←'E'
                              :Case id_at_serialNumber ⋄ Name←'SerialNumber'
                              :Case id_at_streetAddress ⋄ Name←'Street'
                              :Case id_isismtt_at_nameDistinguisher ⋄ Name←'NameDistinguisher'
                              :Case id_isismtt_at_liabilityLimitationFlag ⋄ Name←'LiabilityLimitationFlag'
                              :Case id_domainComponent ⋄ Name←'DomainComponent'
                              :Case pkcs_9_unstructuredName ⋄ Name←'UnstructuredName'
                              :Case pkcs_9_unstructuredAddress ⋄ Name←'UnstructuredAddress'
                              :Case id_ldap_namingContexts ⋄ Name←'NamingContexts'
                              :Case id_ldap_altServer ⋄ Name←'AltServer'
                              :Case id_ldap_supportedExtension ⋄ Name←'SupportedExtension'
                              :Case id_ldap_supportedControl ⋄ Name←'SupportedControl'
                              :Case id_ldap_supportedSASLMechanisms ⋄ Name←'SupportedSASLMechanisms'
                              :Case id_ldap_supportedLDAPVersion ⋄ Name←'SupportedLDAPVersion'
                              :Case id_ldap_ldapSyntaxes ⋄ Name←'LdapSyntaxes'
                              :Case id_pda_dateOfBirth ⋄ Name←'DateOfBirth'
                              :Case id_pda_placeOfBirth ⋄ Name←'PlaceOfBirth'
                              :Case id_pda_gender ⋄ Name←'Gender'
                              :Case id_pda_countryOfCitizenship ⋄ Name←'CountryOfCitizenship'
                              :Case id_pda_countryOfResidence ⋄ Name←'CountryOfResidence'
                              :Case id_isismtt_at_nameAtBirth ⋄ Name←'MaidenName'
                              :Case id_at_objectClass ⋄ Name←'ObjectClass'
                              :Case id_at_aliasedEntryName ⋄ Name←'AliasedObjectName'
                              :Case id_at_knowledgeInformation ⋄ Name←'KnowledgeInformation'
                              :Case id_at_title ⋄ Name←'Title'
                              :Case id_at_description ⋄ Name←'Description'
                              :Case id_at_searchGuide ⋄ Name←'SearchGuide'
                              :Case id_at_businessCategory ⋄ Name←'BusinessCategory'
                              :Case id_at_postalAddress ⋄ Name←'PostalAddress'
                              :Case id_at_postalCode ⋄ Name←'PostalCode'
                              :Case id_at_postOfficeBox ⋄ Name←'PostOfficeBox'
                              :Case id_at_physicalDeliveryOfficeName ⋄ Name←'PhysicalDeliveryOfficeName'
                              :Case id_at_telephoneNumber ⋄ Name←'TelephoneNumber'
                              :Case id_at_telexNumber ⋄ Name←'TelexNumber'
                              :Case id_at_teletexTerminalIdentifier ⋄ Name←'TeletexTerminalIdentifier'
                              :Case id_at_facsimileTelephoneNumber ⋄ Name←'FacsimileTelephoneNumber'
                              :Case id_at_x121Address ⋄ Name←'X121Address'
                              :Case id_at_internationalISDNNumber ⋄ Name←'InternationaliSDNNumber'
                              :Case id_at_registeredAddress ⋄ Name←'RegisteredAddress'
                              :Case id_at_destinationIndicator ⋄ Name←'DestinationIndicator'
                              :Case id_at_preferredDeliveryMethod ⋄ Name←'PreferredDeliveryMethod'
                              :Case id_at_presentationAddress ⋄ Name←'PresentationAddress'
                              :Case id_at_supportedApplicationContext ⋄ Name←'SupportedApplicationContext'
                              :Case id_at_member ⋄ Name←'Member'
                              :Case id_at_owner ⋄ Name←'Owner'
                              :Case id_at_roleOccupant ⋄ Name←'RoleOccupant'
                              :Case id_at_seeAlso ⋄ Name←'SeeAlso'
                              :Case id_at_userPassword ⋄ Name←'UserPassword'
                              :Case id_at_userCertificate ⋄ Name←'UserCertificate'
                              :Case id_at_cACertificate ⋄ Name←'CACertificate'
                              :Case id_at_authorityRevocationList ⋄ Name←'AuthorityRevocationList'
                              :Case id_at_certificateRevocationList ⋄ Name←'CertificateRevocationList'
                              :Case id_at_crossCertificatePair ⋄ Name←'CrossCertificatePair'
                              :Case id_at_name ⋄ Name←'Name'
                              :Case id_at_givenName ⋄ Name←'GivenName'
                              :Case id_at_initials ⋄ Name←'Initials'
                              :Case id_at_generationQualifier ⋄ Name←'GenerationQualifier'
                              :Case id_at_uniqueIdentifier ⋄ Name←'X500UniqueIdentifier'
                              :Case id_at_dnQualifier ⋄ Name←'DnQualifier'
                              :Case id_at_enhancedSearchGuide ⋄ Name←'EnhancedSearchGuide'
                              :Case id_at_protocolInformation ⋄ Name←'ProtocolInformation'
                              :Case id_at_distinguishedName ⋄ Name←'DistinguishedName'
                              :Case id_at_uniqueMember ⋄ Name←'UniqueMember'
                              :Case id_at_houseIdentifier ⋄ Name←'HouseIdentifier'
                              :Case id_at_supportedAlgorithms ⋄ Name←'SupportedAlgorithms'
                              :Case id_at_deltaRevocationList ⋄ Name←'DeltaRevocationList'
                              :Case id_at_dmdName ⋄ Name←'DmdName'
                              :Case id_at_pseudonym ⋄ Name←'Pseudonym'
                              :Case id_oa_createTimestamp ⋄ Name←'CreateTimestamp'
                              :Case id_oa__modifyTimestamp ⋄ Name←'ModifyTimestamp'
                              :Case id_oa__creatorsName ⋄ Name←'CreatorsName'
                              :Case id_oa__modifiersName ⋄ Name←'ModifiersName'
                              :Case id_oa__subschemaSubentry ⋄ Name←'SubschemaSubentry'
                              :Case id_sa_dITStructureRules ⋄ Name←'DITStructureRules'
                              :Case id_sa_dITContentRules ⋄ Name←'DITContentRules'
                              :Case id_sa_matchingRules ⋄ Name←'MatchingRules'
                              :Case id_sa_attributeTypes ⋄ Name←'AttributeTypes'
                              :Case id_sa_objectClasses ⋄ Name←'ObjectClasses'
                              :Case id_sa_nameForms ⋄ Name←'NameForms'
                              :Case id_sa_matchingRuleUse ⋄ Name←'MatchingRuleUse'
                                  :Else Name←(⎕D,'.')[⎕D⍳⍕Type]
                              :EndSelect
                              :If 2≠↑⍴AttributeValue
                              :OrIf ~(⊂↑Tag Value←AttributeValue)∊##.UTF8STR ##.NUMERICSTR ##.PRINTABLESTR ##.T61STR ##.IA5STR ##.UNIVERSALSTR ##.BMPSTR
                                  Value←'#',#.Win.HexTxt 1 ##.Code AttributeValue
                              :Else
                                  Value←ReplaceLast ReplaceFirst ReplaceEscapes Value
                              :EndIf
                              NameValue ConcatenateWithPlus←Name,'=',Value
                          :EndIf
                      :EndFor
                      StringRepresentation ConcatenateWithComma←NameValue
                  :EndIf
              :EndFor
          :EndIf
        ∇

        FormatStringToMultiline←{{(~∨⌿('\',¨',+"\<>;')∘.⍷⍵)/¨⍵}(1++\{(~↑⍵)∧1=↑+/⍵}¯2 ¯1 ¯1⌽¨⍵∘∊¨'\,+')⊂⍵}

    :EndNamespace
    :Namespace OCSP
        ⎕IO ⎕ML ⎕WX ⎕PP ⎕DIV←1 3 1 16 1

        ∇ CertID←{UtoInteger}BuildCertID Parms;IssuerCertificate;CertificateOrSerialNumber;CertificateChain;digestAlgorithm_md2;digestAlgorithm_md4;digestAlgorithm_md5;id_sha1;hashAlgorithm_ripemd160;hashAlgorithm_ripemd128;algorithmHash;Algid;CertificateSerialNumber;SubjectCertificate;Issuer;issuerName;issuerNameHash;issuerKey;issuerKeyHash;Algorithm;Parameters;HashAlgorithm;IssuerNameHash;IssuerKeyHash;SerialNumber;CertID
     ⍝⍝ Encodieren einer Certificate Identification für einzelnen Request
     ⍝⍝ nach RFC2560 (PKIX.509 - Online Certificate Status Protocol - OCSP)
     ⍝
     ⍝Y Parms[1]      = CertificateOrSerialNumber Seriennummer eines abzufragenden Zertifikats
     ⍝Y Parms[2]      = IssuerCertificate         Zertifikat der ausstellenden CA (optional, wenn Parms[1]=Certificate)
     ⍝X UtoInteger    = Universal Tag Option für Integer CertificateSerialNumber (def numerisch/formatiert)
     ⍝
     ⍝R SingleRequest = Encodierter Request oder onError '' (vgl #.RCode)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
     ⍝ Init
     ⍝ Assign Parameters
          :If 1<≡Parms
              CertificateOrSerialNumber IssuerCertificate←2↑Parms
          :Else
              CertificateOrSerialNumber←Parms
              IssuerCertificate←''
          :EndIf
     ⍝ Universal Tag Options for CertificateSerialNumber
          :If 0=⎕NC'UtoInteger'
              UtoInteger←##.UTO_FMT+##.UTO_I53
          :EndIf
     ⍝ Retrieve CertificateSerialNumber and SubjectCertificate
          :If ''≢CertificateSerialNumber←##.X509.GetCertificateSerialNumber CertificateOrSerialNumber
              SubjectCertificate←CertificateOrSerialNumber
          :Else
              CertificateSerialNumber←CertificateOrSerialNumber
              SubjectCertificate←''
          :EndIf
     ⍝ Retrieve IssuerCertificate
          :If ''≡IssuerCertificate
              :If ''≡SubjectCertificate
                  #.RCode←#.Win.CERT_E_CHAINING
                  CertID←''
                  :Return
              :ElseIf 2≤↑⍴CertificateChain←##.X509.GetCertificateChain SubjectCertificate
                  IssuerCertificate←2⊃CertificateChain
              :EndIf
          :EndIf
     ⍝ Some useful algorithm OIDs
          digestAlgorithm_md2←1 2 840 113549 2 2
          digestAlgorithm_md4←1 2 840 113549 2 4
          digestAlgorithm_md5←1 2 840 113549 2 5
          id_sha1←1 3 14 3 2 26
          hashAlgorithm_ripemd160←1 3 36 3 2 1
          hashAlgorithm_ripemd128←1 3 36 3 2 2
     ⍝ Used algorithm
          algorithmHash←id_sha1
          Algid←#.Crypt.OidToAlgid algorithmHash
     ⍝ Analyze issuer's X.509 certificate to get the string hashes neccessary to identify the issuer authority
          :If ''≡IssuerCertificate
              issuerKeyHash←↑##.X509.Extension.ResolveAuthorityKeyIdentifier SubjectCertificate
          :ElseIf ''≡issuerKey←##.X509.GetCertificateSubjectPublicKey IssuerCertificate
          :OrIf ''≡issuerKeyHash←issuerKey #.Crypt.Hash Algid
              CertID←''
              :Return
          :EndIf
          :If ''≢Issuer←##.X509.GetCertificateIssuer SubjectCertificate
          :ElseIf ''≢Issuer←##.X509.GetCertificateSubject IssuerCertificate
          :Else
              CertID←''
              :Return
          :EndIf
          :If ''≡issuerName←1 ##.Code Issuer
          :OrIf ''≡issuerNameHash←issuerName #.Crypt.Hash Algid
              CertID←''
              :Return
          :EndIf
     ⍝ Construct Single Request as in RFC2560:
     ⍝
     ⍝ CertID      ::=        SEQUENCE {
     ⍝     hashAlgorithm      AlgorithmIdentifier,
     ⍝     issuerNameHash     OCTET STRING, -- Hash of Issuer's DN
     ⍝     issuerKeyHash      OCTET STRING, -- Hash of Issuers public key
     ⍝     serialNumber       CertificateSerialNumber }
           ⋄ ⋄ Algorithm←##.OID algorithmHash
           ⋄ ⋄ Parameters←##.NULLTAG
           ⋄ HashAlgorithm←##.SEQUENCE Algorithm Parameters
           ⋄ IssuerNameHash←##.OCTETSTRING issuerNameHash
           ⋄ IssuerKeyHash←##.OCTETSTRING issuerKeyHash
           ⋄ SerialNumber←##.INTEGER CertificateSerialNumber
          CertID←1(⍬ UtoInteger)##.Code ##.SEQUENCE HashAlgorithm IssuerNameHash IssuerKeyHash SerialNumber
        ∇

        ∇ OCSPRequest←BuildRequest Parms;SingleRequests;GeneralExtensions;SignatureCertificate;pkcs_1_md2WithRSAEncryption;pkcs_1_md4WithRSAEncryption;pkcs_1_md5WithRSAEncryption;pkcs_1_sha1WithRSAEncryption;algorithm_rsaSignatureWithripemd160;algorithm_rsaSignatureWithripemd128;algorithmSign;version;Version;TBSCertificate;Subject;RequestorName;Requests;CertID;SingleExtensions;SingleRequestExtensions;RequestList;GeneralRequestExtensions;TBSRequest;signature;Algorithm;Parameters;SignatureAlgorithm;Signature;Certificates;Certs;OptionalSignature
     ⍝⍝ Encodieren eines OCSP-Requests nach RFC2560 (PKIX.509 - Online Certificate Status Protocol - OCSP)
     ⍝
     ⍝Y Parms[1]    = SingleRequests       Vektor von (CertID1 SingleExtensions1)(CertID2 SingleExtensions2)..
     ⍝                 CertID              Zertifikats-ID: Resultat von #.ASN1.OCSP.BuildCertID
     ⍝                 SingleExtensions    Extensions für einzelnen Request: Argument für #.ASN1.X509.BuildExtensions
     ⍝Y Parms[2]    = GeneralExtensions    Optionale Extensions für gesamten  Request: Argument für #.ASN1.X509.BuildExtensions
     ⍝Y Parms[3]    = SignatureCertificate Optionales Zertifikat des Requestors
     ⍝
     ⍝R OCSPRequest = Encodierter Request oder onError '' (vgl #.RCode)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
     ⍝ Init
     ⍝ Assign Parameters
          :Select ↑⍴Parms
          :Case 1
              SingleRequests←↑Parms
              GeneralExtensions←''
              SignatureCertificate←''
          :Case 2
              SingleRequests GeneralExtensions←Parms
              SignatureCertificate←''
          :Else
              SingleRequests GeneralExtensions SignatureCertificate←3↑Parms
          :EndSelect
     ⍝ Some useful algorithm OIDs
          pkcs_1_md2WithRSAEncryption←1 2 840 113549 1 1 2
          pkcs_1_md4WithRSAEncryption←1 2 840 113549 1 1 3
          pkcs_1_md5WithRSAEncryption←1 2 840 113549 1 1 4
          pkcs_1_sha1WithRSAEncryption←1 2 840 113549 1 1 5
          algorithm_rsaSignatureWithripemd160←1 3 36 3 3 1 2
          algorithm_rsaSignatureWithripemd128←1 3 36 3 3 1 3
     ⍝ Used algorithms
          algorithmSign←pkcs_1_sha1WithRSAEncryption
     ⍝ Construct OCSP request as in RFC2560:
     ⍝
     ⍝ OCSPRequest ::=        SEQUENCE {
     ⍝     tbsRequest             TBSRequest,
     ⍝     optionalSignature      [0] EXPLICIT Signature OPTIONAL }
     ⍝ TBSRequest  ::=        SEQUENCE {
     ⍝     version                [0] EXPLICIT Version DEFAULT v1,
     ⍝     requestorName          [1] EXPLICIT GeneralName OPTIONAL,
     ⍝     requestList            SEQUENCE OF Request,
     ⍝     requestExtensions      [2] EXPLICIT Extensions OPTIONAL }
     ⍝ Signature   ::=        SEQUENCE {
     ⍝     signatureAlgorithm      AlgorithmIdentifier,
     ⍝     signature               BIT STRING,
     ⍝     certs                   [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
     ⍝ Version     ::=        INTEGER  { v1(0) }
     ⍝ Request     ::=        SEQUENCE {
     ⍝     reqCert                 CertID,
     ⍝     singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
           ⋄ ⋄ ⋄ version←v1
           ⋄ ⋄ Version←(##.CONTEXT 0)(##.INTEGER version)##.DEFAULT v1
          :If 0≠↑⍴SignatureCertificate
          :AndIf ''≢Subject←##.X509.GetCertificateSubject SignatureCertificate
               ⋄ ⋄ RequestorName←(##.CONTEXT 1)Subject ##.OPTIONAL ##.TRUE
          :Else
               ⋄ ⋄ RequestorName←''
          :EndIf
           ⋄ ⋄ ⋄ Requests←0⍴⊂''
          :For CertID SingleExtensions :In SingleRequests
               ⋄ ⋄ ⋄ ⋄ SingleRequestExtensions←0 ##.X509.BuildExtensions SingleExtensions
               ⋄ ⋄ ⋄ Requests,←⊂##.SEQUENCE CertID SingleRequestExtensions
          :EndFor
           ⋄ ⋄ RequestList←(⊂##.SEQUENCE),Requests
           ⋄ ⋄ GeneralRequestExtensions←2 ##.X509.BuildExtensions GeneralExtensions
           ⋄ TBSRequest←1 ##.Code ##.SEQUENCE Version RequestorName RequestList GeneralRequestExtensions
          :If 0≠↑⍴SignatureCertificate
          :AndIf 0≠↑⍴signature←TBSRequest #.Crypt.Sign SignatureCertificate(#.Crypt.OidToAlgid algorithmSign)
               ⋄ ⋄ ⋄ ⋄ Algorithm←##.OID algorithmSign
               ⋄ ⋄ ⋄ ⋄ Parameters←##.NULLTAG
               ⋄ ⋄ ⋄ SignatureAlgorithm←##.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ Signature←##.BITSTRING signature
               ⋄ ⋄ ⋄ Certs←(##.CONTEXT 0)Certificates ##.OPTIONAL 1<↑⍴Certificates←(⊂##.SEQUENCE),##.X509.GetCertificateChain SignatureCertificate
               ⋄ ⋄ Signature←##.SEQUENCE SignatureAlgorithm Signature Certs
               ⋄ OptionalSignature←(##.CONTEXT 0)Signature ##.OPTIONAL 0≠↑⍴signature
          :Else
               ⋄ OptionalSignature←''
          :EndIf
          OCSPRequest←1 ##.Code ##.SEQUENCE TBSRequest OptionalSignature
        ∇

        ∇ EqualFlag←CertID1 CompareCertIDs CertID2;HashAlgorithm1;IssuerNameHash1;IssuerKeyHash1;SerialNumber1;HashAlgorithm2;IssuerNameHash2;IssuerKeyHash2;SerialNumber2
     ⍝⍝ Vergleiche zwei Certificate Identifications auf Identität
     ⍝⍝ wobei für issuerKeyHash ein leerer Octetstring erlaubt ist
     ⍝⍝ nach RFC2560 (PKIX.509 - Online Certificate Status Protocol - OCSP)
     ⍝
     ⍝Y CertID1   = Erste  Certificate Identification
     ⍝X CertID2   = Zweite Certificate Identification
     ⍝
     ⍝R EqualFlag = TRUE oder FALSE
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
     ⍝
     ⍝ CertID      ::=        SEQUENCE {
     ⍝     hashAlgorithm      AlgorithmIdentifier,
     ⍝     issuerNameHash     OCTET STRING, -- Hash of Issuer's DN
     ⍝     issuerKeyHash      OCTET STRING, -- Hash of Issuers public key
     ⍝     serialNumber       CertificateSerialNumber }
     ⍝ Init
          :If EqualFlag←CertID1≡CertID2
          :ElseIf ##.SEQUENCE≡↑CertID1←3 ##.Code CertID1
          :AndIf (1+4)=↑⍴CertID1
          :AndIf ##.SEQUENCE ##.OCTETSTRING ##.OCTETSTRING ##.INTEGER≡↑¨HashAlgorithm1 IssuerNameHash1 IssuerKeyHash1 SerialNumber1←1↓CertID1
          :AndIf ##.SEQUENCE≡↑CertID2←3 ##.Code CertID2
          :AndIf (1+4)=↑⍴CertID2
          :AndIf ##.SEQUENCE ##.OCTETSTRING ##.OCTETSTRING ##.INTEGER≡↑¨HashAlgorithm2 IssuerNameHash2 IssuerKeyHash2 SerialNumber2←1↓CertID2
          :AndIf HashAlgorithm1 IssuerNameHash1 SerialNumber1≡HashAlgorithm2 IssuerNameHash2 SerialNumber2
              :If EqualFlag←IssuerKeyHash1≡IssuerKeyHash2
              :OrIf EqualFlag←##.OCTETSTRING''≡IssuerKeyHash1
              :OrIf EqualFlag←##.OCTETSTRING''≡IssuerKeyHash2
              :EndIf
          :EndIf
        ∇

        ∇ Exit
          ⎕EX⊃'OCS_NOANSWER' 'OCS_UNKNOWN' 'OCS_REVOKED' 'OCS_GOOD'
          ⎕EX⊃'ORS_CERTHASH_NO_MATCH' 'ORS_CERTIFICATE_NO_MATCH' 'ORS_NONCE_VALUE_NO_MATCH' 'ORS_NONCE_MISSING' 'ORS_MALFORMED_RESPONSE'
          ⎕EX⊃'ORS_INVALID_RESPONSE_SIGNATURE' 'ORS_HTTP_TRANSACTION_ERROR' 'ORS_UNKNOWN_RESPONSE_TYPE' 'ORS_REQUEST_BUILD_ERROR' 'ORS_UNAUTHORIZED'
          ⎕EX⊃'ORS_SIG_REQUIRED' 'ORS_INVALID_REQUEST_SIGNATURE' 'ORS_TRY_LATER' 'ORS_INTERNAL_ERROR' 'ORS_MALFORMED_REQUEST' 'ORS_SUCCESSFUL'
          ⎕EX⊃'id_isismtt_at_certHash' 'id_isismtt_at_certInDirSince' 'id_isismtt_at_requestedCertificate' 'id_isismtt_at_retrieveIfAllowed'
          ⎕EX⊃'id_pkix_ocsp_service_locator' 'id_pkix_ocsp_archive_cutoff' 'id_pkix_ocsp_nocheck' 'id_pkix_ocsp_response' 'id_pkix_ocsp_crl'
          ⎕EX⊃'id_pkix_ocsp_nonce' 'id_pkix_ocsp_basic' 'id_pkix_ocsp' 'id_kp_OCSPSigning' 'id_pe_authorityInfoAccess' 'id_ce_certificateIssuer'
          ⎕EX⊃'id_ce_invalidityDate' 'id_ce_holdInstructionCode' 'id_ce_cRLReason' 'v3' 'v2' 'v1'
        ∇

        ∇ CRLReasonText←GetCRLReasonText CRLReason
          :Select ↑#.Win.Sys.GetDefaultLangID
          :Case #.Win.LANG_GERMAN
              :Select CRLReason
              :Case #.Win.CRL_REASON_UNSPECIFIED
                  CRLReasonText←'Grund der Sperrung nicht angegeben'
              :Case #.Win.CRL_REASON_KEY_COMPROMISE
                  CRLReasonText←'Kompromittierung des privaten Schlüssels'
              :Case #.Win.CRL_REASON_CA_COMPROMISE
                  CRLReasonText←'Kompromittierung der CA'
              :Case #.Win.CRL_REASON_AFFILIATION_CHANGED
                  CRLReasonText←'Zugehörigkeit hat sich geändert'
              :Case #.Win.CRL_REASON_SUPERSEDED
                  CRLReasonText←'Ein aktuelleres Zertifikat liegt vor'
              :Case #.Win.CRL_REASON_CESSATION_OF_OPERATION
                  CRLReasonText←'Benutzung wurde eingestellt'
              :Case #.Win.CRL_REASON_CERTIFICATE_HOLD
                  CRLReasonText←'Benutzung wurde ausgesetzt'
              :Case #.Win.CRL_REASON_REMOVE_FROM_CRL
                  CRLReasonText←'Von Sperrliste entfernt'
              :Case #.Win.CRL_REASON_PRIVILEGE_WITHDRAWN
                  CRLReasonText←'Attribut entzogen'
              :Case #.Win.CRL_REASON_AA_COMPROMISE
                  CRLReasonText←'Kompromittierung der AA'
              :Else
                  CRLReasonText←'Grund der Sperrung unbekannt'
              :EndSelect
          :Else
              :Select CRLReason
              :Case #.Win.CRL_REASON_UNSPECIFIED
                  CRLReasonText←'Unspecified revocation reason'
              :Case #.Win.CRL_REASON_KEY_COMPROMISE
                  CRLReasonText←'Key compromise'
              :Case #.Win.CRL_REASON_CA_COMPROMISE
                  CRLReasonText←'CA compromise'
              :Case #.Win.CRL_REASON_AFFILIATION_CHANGED
                  CRLReasonText←'Affiliation changed'
              :Case #.Win.CRL_REASON_SUPERSEDED
                  CRLReasonText←'Superseded'
              :Case #.Win.CRL_REASON_CESSATION_OF_OPERATION
                  CRLReasonText←'Cessation of operation'
              :Case #.Win.CRL_REASON_CERTIFICATE_HOLD
                  CRLReasonText←'Certificate on hold'
              :Case #.Win.CRL_REASON_REMOVE_FROM_CRL
                  CRLReasonText←'Remove from CRL'
              :Case #.Win.CRL_REASON_PRIVILEGE_WITHDRAWN
                  CRLReasonText←'Privilege withdrawn'
              :Case #.Win.CRL_REASON_AA_COMPROMISE
                  CRLReasonText←'AA compromise'
              :Else
                  CRLReasonText←'Unknown revocation reason'
              :EndSelect
          :EndSelect
        ∇

        ∇ CertStatusText←GetCertStatusText CertStatus
          :Select ↑#.Win.Sys.GetDefaultLangID
          :Case #.Win.LANG_GERMAN
              :Select CertStatus
              :Case OCS_GOOD
                  CertStatusText←'Das Zertifikat ist gültig'
              :Case OCS_REVOKED
                  CertStatusText←'Das Zertifikat wurde gesperrt'
              :Case OCS_UNKNOWN
                  CertStatusText←'Der Responder kennt das Zertifikat nicht'
              :Case OCS_NOANSWER ⍝ Internal
                  CertStatusText←'Dieses Zertifikat wurde nicht beantwortet'
              :Else
                  CertStatusText←'Unbekannter Zertifikats-Status'
              :EndSelect
          :Else
              :Select CertStatus
              :Case OCS_GOOD
                  CertStatusText←'Positive response to the status inquiry'
              :Case OCS_REVOKED
                  CertStatusText←'Certificate has been revoked either permanantly or temporarily (on hold)'
              :Case OCS_UNKNOWN
                  CertStatusText←'The Responder does not know about the certificate being requested'
              :Case OCS_NOANSWER ⍝ Internal
                  CertStatusText←'No answer for this certificate in the response'
              :Else
                  CertStatusText←'Unknown certificate status'
              :EndSelect
          :EndSelect
        ∇

        ∇ NonceValue←GetNonceValueFromRequest Asn1Request;OCSPRequest;TBSRequest;Extensions;ExtensionList;Index;ExtensionValue
          OCSPRequest←¯4 ##.Code Asn1Request
          :If 2≤↑⍴OCSPRequest
          :AndIf ##.SEQUENCE≡↑OCSPRequest
          :AndIf 3≤↑⍴TBSRequest←2⊃OCSPRequest
          :AndIf ##.SEQUENCE≡↑TBSRequest
          :AndIf 1=↑⍴Extensions←{((↑¨⍵)∊⊂##.CONTEXT 2)/⍵}1↓TBSRequest
          :AndIf 0<↑⍴ExtensionList←2 ##.X509.ResolveExtensions↑Extensions
          :AndIf (↑⍴ExtensionList)≥Index←(↑¨ExtensionList)⍳⊂id_pkix_ocsp_nonce
          :AndIf 2=↑⍴ExtensionValue←¯2 ##.Code Index 3⊃ExtensionList
          :AndIf ##.OCTETSTRING≡↑ExtensionValue
              NonceValue←2⊃ExtensionValue
          :Else
              NonceValue←''
          :EndIf
        ∇

        ∇ RequestUrl←GetRequestUrlFromCertificate Certificate;CertificateExtensions;Index;AccessDescription;AccessLocation
     ⍝ Get the URL to send an OCSP request to from the certificate in question
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
          :If ''≢CertificateExtensions←##.X509.ResolveExtensions Certificate
          :AndIf (↑⍴CertificateExtensions)≥Index←(↑¨CertificateExtensions)⍳⊂id_pe_authorityInfoAccess
          :AndIf ##.SEQUENCE≡↑AccessDescription←¯4 ##.Code Index 3⊃CertificateExtensions
          :AndIf 0<↑⍴AccessDescription←1↓AccessDescription
          :AndIf ∧/(↑¨AccessDescription)∊⊂##.SEQUENCE
          :AndIf 2∧.=↑∘⍴¨AccessDescription←1↓¨AccessDescription
          :AndIf (↑⍴AccessDescription)≥Index←(↑¨AccessDescription)⍳⊂##.OID id_pkix_ocsp
          :AndIf 2=↑⍴AccessLocation←Index 2⊃AccessDescription
          :AndIf (##.CLASS_CONTEXT ##.FORM_PRIMITIVE 6)≡↑AccessLocation
              RequestUrl←2⊃AccessLocation
              :If ~∨/'://'⍷RequestUrl
                  RequestUrl←'http://',RequestUrl
              :EndIf
              :If 3>'/'+.=RequestUrl
                  RequestUrl,←'/'
              :EndIf
          :Else
              RequestUrl←''
          :EndIf
        ∇

        ∇ ResponseText←GetResponseStatusText ResponseStatus
          :Select ↑#.Win.Sys.GetDefaultLangID
          :Case #.Win.LANG_GERMAN
              :Select ResponseStatus
              :Case ORS_SUCCESSFUL
                  ResponseText←'OCSP-Bestätigung ist gültig'
              :Case ORS_MALFORMED_REQUEST
                  ResponseText←'OCSP-Anfrage fehlerhaft'
              :Case ORS_INTERNAL_ERROR
                  ResponseText←'Interner Responder-Fehler'
              :Case ORS_TRY_LATER
                  ResponseText←'OCSP-Anfrage bitte später wiederholen'
              :Case ORS_INVALID_REQUEST_SIGNATURE
                  ResponseText←'Signatur der OCSP-Anfrage ungültig'
              :Case ORS_SIG_REQUIRED
                  ResponseText←'OCSP-Anfrage muss signiert sein'
              :Case ORS_UNAUTHORIZED
                  ResponseText←'OCSP-Anfrage nicht autorisiert'
              :Case ORS_REQUEST_BUILD_ERROR        ⍝ Internal
                  ResponseText←'Die Anfrage konnte nicht erstellt werden'
              :Case ORS_UNKNOWN_RESPONSE_TYPE      ⍝ Internal
                  ResponseText←'OCSP-Bestätigung ist nicht ocsp-basic'
              :Case ORS_HTTP_TRANSACTION_ERROR     ⍝ Internal
                  ResponseText←'Http Transaktions-Fehler'
              :Case ORS_INVALID_RESPONSE_SIGNATURE ⍝ Internal
                  ResponseText←'Signatur der OCSP-Bestätigung ungültig'
              :Case ORS_MALFORMED_RESPONSE         ⍝ Internal
                  ResponseText←'ASN.1-Decodierung nicht möglich'
              :Case ORS_NONCE_MISSING              ⍝ Internal
                  ResponseText←'Nonce-Sequenz fehlt unerwartet'
              :Case ORS_NONCE_VALUE_NO_MATCH       ⍝ Internal
                  ResponseText←'Nonce-Wert stimmt nicht überein'
              :Case ORS_CERTIFICATE_NO_MATCH       ⍝ Internal
                  ResponseText←'Zurückgeliefertes Zertifikat passt nicht'
              :Case ORS_CERTHASH_NO_MATCH          ⍝ Internal
                  ResponseText←'Zurückgelieferter Fingerabdruck passt nicht'
              :Else
                  ResponseText←'Unbekannter Transaktions-Fehler'
              :EndSelect
          :Else
              :Select ResponseStatus
              :Case ORS_SUCCESSFUL
                  ResponseText←'Response has valid confirmations'
              :Case ORS_MALFORMED_REQUEST
                  ResponseText←'Malformed or illegal confirmation request'
              :Case ORS_INTERNAL_ERROR
                  ResponseText←'Internal error in responder'
              :Case ORS_TRY_LATER
                  ResponseText←'Try again later'
              :Case ORS_INVALID_REQUEST_SIGNATURE
                  ResponseText←'Invalid request signature'
              :Case ORS_SIG_REQUIRED
                  ResponseText←'Must sign the request'
              :Case ORS_UNAUTHORIZED
                  ResponseText←'Request unauthorized'
              :Case ORS_REQUEST_BUILD_ERROR        ⍝ Internal
                  ResponseText←'Request could not get generated properly'
              :Case ORS_UNKNOWN_RESPONSE_TYPE      ⍝ Internal
                  ResponseText←'No ocsp-basic response received'
              :Case ORS_HTTP_TRANSACTION_ERROR     ⍝ Internal
                  ResponseText←'Http transaction error'
              :Case ORS_INVALID_RESPONSE_SIGNATURE ⍝ Internal
                  ResponseText←'Could not validate response signature'
              :Case ORS_MALFORMED_RESPONSE         ⍝ Internal
                  ResponseText←'ASN.1 decode failed'
              :Case ORS_NONCE_MISSING              ⍝ Internal
                  ResponseText←'No Nonce respone, though requested'
              :Case ORS_NONCE_VALUE_NO_MATCH       ⍝ Internal
                  ResponseText←'The received NonceValue does not match the sent NonceValue'
              :Case ORS_CERTIFICATE_NO_MATCH       ⍝ Internal
                  ResponseText←'The received certificate does not match the request'
              :Case ORS_CERTHASH_NO_MATCH          ⍝ Internal
                  ResponseText←'The received certificate hash does not match the request'
              :Else
                  ResponseText←'Unknown transaction eror'
              :EndSelect
          :EndSelect
        ∇

        ∇ Init
          :If 0=⎕NC'v1'
              #.Win.Init
              #.ASN1.Init''
     ⍝ Assignments from X.509 / RFC2459
              v1 v2 v3←0 1 2                                    ⍝ Version values (default v1)
              id_ce_cRLReason←2 5 29 21                         ⍝ Reason for certificate revocation #.Win.CRL_REASON_xx
              id_ce_holdInstructionCode←2 5 29 23               ⍝ Action after a certificate has been placed on hold.
              id_ce_invalidityDate←2 5 29 24                    ⍝ Date on which certificate otherwise became invalid
              id_ce_certificateIssuer←2 5 29 29                 ⍝ Certificate Issuer
              id_pe_authorityInfoAccess←1 3 6 1 5 5 7 1 1       ⍝ Access-points for authority info
     ⍝ Assignments from RFC2560
              id_kp_OCSPSigning←1 3 6 1 5 5 7 3 9               ⍝ Delegated OCSP signing
              id_pkix_ocsp←1 3 6 1 5 5 7 48 1                   ⍝ Online Certificate Status Protocol
              id_pkix_ocsp_basic←1 3 6 1 5 5 7 48 1 1           ⍝ ResponseType for a basic OCSP responder
              id_pkix_ocsp_nonce←1 3 6 1 5 5 7 48 1 2           ⍝ Cryptographically binds request and response to prevent replay attacks
              id_pkix_ocsp_crl←1 3 6 1 5 5 7 48 1 3             ⍝ CRL reference on which revoked or onHold certificate is found
              id_pkix_ocsp_response←1 3 6 1 5 5 7 48 1 4        ⍝ Acceptable response types OCSP client understands
              id_pkix_ocsp_nocheck←1 3 6 1 5 5 7 48 1 5         ⍝ Trust a responder for the lifetime of responder certificate
              id_pkix_ocsp_archive_cutoff←1 3 6 1 5 5 7 48 1 6  ⍝ Retain revocation information beyond expiration
              id_pkix_ocsp_service_locator←1 3 6 1 5 5 7 48 1 7 ⍝ Route request to OCSP authoritative server
     ⍝ Assignments from ISIS-MTT
              id_isismtt_at_retrieveIfAllowed←1 3 36 8 3 9      ⍝ Single client extension to request the responder to send the certificate in the response message along with the status information
              id_isismtt_at_requestedCertificate←1 3 36 8 3 10  ⍝ Single response extension to RetrieveIfAllowed extension in the request, to return the certificate
              id_isismtt_at_certInDirSince←1 3 36 8 3 12        ⍝ Single response extension of date, when certificate has been published in the directory and status information has become available
              id_isismtt_at_certHash←1 3 36 8 3 13              ⍝ Single response extension to send the hash of the requested certificate to the requestor
     ⍝ OCSPResponseStatus values:
              ORS_SUCCESSFUL←0                  ⍝ Response has valid confirmations
              ORS_MALFORMED_REQUEST←1           ⍝ Illegal confirmation request
              ORS_INTERNAL_ERROR←2              ⍝ Internal error in responder
              ORS_TRY_LATER←3                   ⍝ Try again later
              ORS_INVALID_REQUEST_SIGNATURE←4   ⍝ Received from VeriSign !
              ORS_SIG_REQUIRED←5                ⍝ Must sign the request
              ORS_UNAUTHORIZED←6                ⍝ Request unauthorized
              ORS_REQUEST_BUILD_ERROR←90        ⍝ Internal: Request could not get generated properly
              ORS_UNKNOWN_RESPONSE_TYPE←91      ⍝ Internal: No id-pkix-ocsp-basic response received
              ORS_HTTP_TRANSACTION_ERROR←92     ⍝ Internal: Error occured
              ORS_INVALID_RESPONSE_SIGNATURE←93 ⍝ Internal: Could not verify signature of response
              ORS_MALFORMED_RESPONSE←94         ⍝ Internal: ASN.1 decode failed
              ORS_NONCE_MISSING←95              ⍝ Internal: No Nonce respone, though requested
              ORS_NONCE_VALUE_NO_MATCH←96       ⍝ Internal: The received NonceValue does not match the sent NonceValue
              ORS_CERTIFICATE_NO_MATCH←97       ⍝ Internal: The received certificate does not match the request
              ORS_CERTHASH_NO_MATCH←98          ⍝ Internal: The received certificate hash does not match the request
      ⍝ CertStatus values:
              OCS_GOOD←0     ⍝ Positive response to the status inquiry
              OCS_REVOKED←1  ⍝ Certificate has been revoked either permanantly or temporarily (on hold) #.Win.CRYPT_E_REVOKED
              OCS_UNKNOWN←2  ⍝ The Responder does not know about the certificate being requested
              OCS_NOANSWER←9 ⍝ Internal: No answer for this certificate in the response
     ⍝ Revocation reasons already defined in WinCrypt.H:
     ⍝    #.Win.CRL_REASON_UNSPECIFIED←0
     ⍝    #.Win.CRL_REASON_KEY_COMPROMISE←1
     ⍝    #.Win.CRL_REASON_CA_COMPROMISE←2
     ⍝    #.Win.CRL_REASON_AFFILIATION_CHANGED←3
     ⍝    #.Win.CRL_REASON_SUPERSEDED←4
     ⍝    #.Win.CRL_REASON_CESSATION_OF_OPERATION←5
     ⍝    #.Win.CRL_REASON_CERTIFICATE_HOLD←6
     ⍝    #.Win.CRL_REASON_REMOVE_FROM_CRL←8
          :EndIf
        ∇

        ∇ Retrn←Request PerformTransaction Parms;OcspUrl;RequestMethod;TCPTimeout;TCPDebugFlag;SignatureCertificate;RequestCertificates;IssuerCertificates;SingleRequExtnsList;RequExtns;RequestCertificate;IssuerCertificate;SingleRequExtns;SingleRequests;ValidFlag;CertIDs;CertID;Asn1Request;Asn1Response;OcspResponse;ResponseStatus;ResponseData;ResponderID;ProducedAt;ResponseList;RespExtns;RequIndex;RespIndex;CertStatus;CRLReason;RevocationTime;ThisUpdate;NextUpdate;SingleRespExtns;ExtnValue;AlgorithmIdentifier;Digest;Algorithm;Parameters;algorithmHash;CriticalState;NonceRequFlag
     ⍝ Build an ASN1 OCSP Request and send it out to the given request URL.
     ⍝ Then wait for ASN1 OCSP Response AND resolve it.
     ⍝
     ⍝ Parms[1]   = OcspUrl              Example: 'http://ocsp.verisign.com/ocsp/status'
     ⍝ Parms[2]   = RequestMethod        'POST' or 'GET'
     ⍝ Parms[3]   = TCPTimeout           in milliseconds eg 30000
     ⍝ Parms[4]   = TCPDebugFlag         boolean
     ⍝
     ⍝ Request[1] = RequestCertificates  Vector of Certificate to query
     ⍝ Request[2] = IssuerCertificates   (opt.) Vector (corresponding to RequestCertificates) of Certificate of the CAs which have signed the RequestCertificates to query
     ⍝ Request[3] = SingleRequExtnsList  (opt.) Vector (corresponding to RequestCertificates) of Vectors of (OID CriticalFlag ExtensionValue)
     ⍝ Request[4] = RequExtns            (opt.) Vector of (OID CriticalFlag ExtensionValue)
     ⍝ Request[5] = SignatureCertificate (opt.) Certificate to sign the request with or ''
     ⍝
     ⍝ Retrn[1]   = OcspResponse
     ⍝              OcspResponse[1]  = ResponseStatus    (#.ASN1.OCSP.ORS_SUCCESSFUL ORS_MALFORMED_REQUEST ORS_INTERNAL_ERROR ORS_TRY_LATER ORS_INVALID_REQUEST_SIGNATURE ORS_SIG_REQUIRED ORS_UNAUTHORIZED ORS_UNKNOWN_RESPONSE_TYPE ORS_INVALID_RESPONSE_SIGNATURE or ORS_MALFORMED_RESPONSE)
     ⍝              OcspResponse[2]  = ResponseData      If ResponseStatus=#.ASN1.OCSP.ORS_SUCCESSFUL:
     ⍝                                 ResponseData[1] = ResponderID  Name structure of the resopnder
     ⍝                                 ResponseData[2] = ProducedAt   ⎕TS at which the OCSP responder signed this response
     ⍝                                 ResponseData[3] = ResponseList Vector of (CertID CertStatus CRLReason RevocationTime ThisUpdate NextUpdate SingleRespExtns)(..repeated for each single requ..)
     ⍝                                 ResponseData[4] = RespExtns    Vector of (OID CriticalFlag ExtensionValue)(..)
     ⍝ Retrn[2]   = Asn1Response
     ⍝ Retrn[3]   = Asn1Request
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
     ⍝
     ⍝ Assign Parameters
          :Select ↑⍴Request
          :Case 1
              RequestCertificates←↑Request
              IssuerCertificates SingleRequExtnsList RequExtns SignatureCertificate←(0⍴⊂'')(0⍴⊂0⍴⊂⍬ 0 '')(0⍴⊂⍬ 0 '')''
          :Case 2
              RequestCertificates IssuerCertificates←Request
              SingleRequExtnsList RequExtns SignatureCertificate←(0⍴⊂0⍴⊂⍬ 0 '')(0⍴⊂⍬ 0 '')''
          :Case 3
              RequestCertificates IssuerCertificates SingleRequExtnsList←Request
              RequExtns SignatureCertificate←(0⍴⊂⍬ 0 '')''
          :Case 4
              RequestCertificates IssuerCertificates SingleRequExtnsList RequExtns←Request
              SignatureCertificate←''
          :Case 5
              RequestCertificates IssuerCertificates SingleRequExtnsList RequExtns SignatureCertificate←Request
          :EndSelect
     ⍝ Transaction Parameters
          OcspUrl RequestMethod TCPTimeout TCPDebugFlag←Parms
     ⍝ Build single sub-request(s)
          SingleRequests←0⍴⊂'' ''
          CertIDs←0⍴⊂''
          ValidFlag←1
          :For RequestCertificate IssuerCertificate SingleRequExtns :In ⊂[1]⊃RequestCertificates IssuerCertificates SingleRequExtnsList
              :If ValidFlag←''≢CertID←BuildCertID RequestCertificate IssuerCertificate
                  CertIDs,←⊂CertID
                  SingleRequests,←⊂CertID SingleRequExtns
              :Else
                  :Leave
              :EndIf
          :EndFor
          :If ValidFlag
     ⍝ Build ASN.1 encoded OCSP Request
          :AndIf ×↑⍴Asn1Request←BuildRequest SingleRequests RequExtns SignatureCertificate
     ⍝ Process HTTP Transaction
              :If ×↑⍴Asn1Response←Asn1Request ProcessTransaction OcspUrl RequestMethod TCPTimeout TCPDebugFlag
     ⍝ Resolve ASN.1 encoded OCSP Response
                  :If ORS_SUCCESSFUL=↑ResponseStatus ResponseData←CertIDs ResolveResponse Asn1Response
                      ResponderID ProducedAt ResponseList RespExtns←ResponseData
     ⍝ If supported, check for valid NonceValue, RequestedCertificate and CertHash
                      :If NonceRequFlag←(↑⍴RequExtns)≥RequIndex←(↑¨RequExtns)⍳⊂id_pkix_ocsp_nonce
                      :AndIf CriticalState←RequIndex 2⊃RequExtns
                      :AndIf (↑⍴RespExtns)<RespIndex←(↑¨RespExtns)⍳⊂id_pkix_ocsp_nonce
                          :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.TRUST_E_FAIL ⋄ :EndIf
                          ResponseStatus←ORS_NONCE_MISSING
                      :ElseIf NonceRequFlag
                      :AndIf (↑⍴RespExtns)≥RespIndex←(↑¨RespExtns)⍳⊂id_pkix_ocsp_nonce
                      :AndIf (1 ##.Code RequIndex 3⊃RequExtns)≢1 ##.Code RespIndex 3⊃RespExtns
                          :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_NO_MATCH ⋄ :EndIf
                          ResponseStatus←ORS_NONCE_VALUE_NO_MATCH
                      :ElseIf 0×(⍴ResponseList)≢⍴RequestCertificates
                          :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_NO_MATCH ⋄ :EndIf
                          ResponseStatus←ORS_CERTIFICATE_NO_MATCH
                      :Else
                          :For RequestCertificate CertID CertStatus CRLReason RevocationTime ThisUpdate NextUpdate SingleRespExtns SingleRequExtns :In (⊂¨RequestCertificates),¨ResponseList,¨⊂¨SingleRequExtnsList
                              :If (↑⍴SingleRequExtns)≥RequIndex←(↑¨SingleRequExtns)⍳⊂id_isismtt_at_retrieveIfAllowed
                                  CriticalState←RequIndex 2⊃SingleRequExtns
                              :Else
                                  CriticalState←¯1
                              :EndIf
                              :If (↑⍴SingleRespExtns)≥RespIndex←(↑¨SingleRespExtns)⍳⊂id_isismtt_at_requestedCertificate
                              :AndIf (∧/''RequestCertificate≢¨⊂1 ##.Code RespIndex 3⊃SingleRespExtns)∨CriticalState∊¯1 0
                              :AndIf (∧/(1 ##.Code(##.CONTEXT 0)(##.OCTETSTRING''))(1 ##.Code(##.CONTEXT 0)(##.OCTETSTRING RequestCertificate))(1 ##.Code(##.CONTEXT 1)(##.OCTETSTRING RequestCertificate))≢¨⊂1 ##.Code RespIndex 3⊃SingleRespExtns)∨CriticalState∊¯1
                                  :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_NO_MATCH ⋄ :EndIf
                                  ResponseStatus←ORS_CERTIFICATE_NO_MATCH
                                  :Leave
                              :ElseIf (↑⍴SingleRespExtns)≥RespIndex←(↑¨SingleRespExtns)⍳⊂id_isismtt_at_certHash
                                  :If (1+2)≠↑⍴ExtnValue←0 ##.Code RespIndex 3⊃SingleRespExtns
                                  :OrIf (1+2 1)≢↑∘⍴¨AlgorithmIdentifier Digest←1↓ExtnValue
                                  :OrIf ##.SEQUENCE ##.OCTETSTRING≢↑¨AlgorithmIdentifier Digest
                                  :OrIf (1+1 0)≢↑∘⍴¨Algorithm Parameters←1↓AlgorithmIdentifier
                                  :OrIf ##.OID(↑##.NULLTAG)≢↑¨Algorithm Parameters
                                      algorithmHash←↑1↓Algorithm
                                      Digest←↑1↓Digest
                                  :OrIf Digest≢RequestCertificate #.Crypt.Hash #.Crypt.OidToAlgid algorithmHash
                                      :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_HASH_VALUE ⋄ :EndIf
                                      ResponseStatus←ORS_CERTHASH_NO_MATCH
                                      :Leave
                                  :EndIf
                              :EndIf
                          :EndFor
                      :EndIf
                  :EndIf
              :Else
                  ResponseStatus←ORS_HTTP_TRANSACTION_ERROR
                  ResponseData←''
              :EndIf
          :Else
              Asn1Request←''
              Asn1Response←''
              ResponseStatus←ORS_REQUEST_BUILD_ERROR
              ResponseData←''
          :EndIf
          OcspResponse←ResponseStatus ResponseData
          Retrn←OcspResponse Asn1Response Asn1Request
        ∇

        ∇ OCSPResponse←OCSPRequest ProcessTransaction Parms;RequestUrl;RequestMethod;UserAgent;MailBox;TCPTimeout;TCPDebugFlag;Protocol;User;Password;Host;Port;UrlPath;RemoteUrl;ProxyFlag;HttpVersion;UrlEncodedRequest;RequestLine;RequestHeader;StatusLine;ResponseHeader;StatusCode;ReasonPhrase
     ⍝ Build an OCSP valid http-request from the OCSPRequest string and send it out to the
     ⍝ given request URL. Then wait for a http-response to extract the "OCSPResponse" out of it.
     ⍝ In case of error OCSPResponse is '' and #.RCode is set.
     ⍝
     ⍝ Parms[1]     = RequestUrl    To be derived from the value of AuthorityInfoAccess. Example: 'http://ocsp.verisign.com/ocsp/status'
     ⍝ Parms[2]     = RequestMethod (opt) 'GET' or (def) 'POST'
     ⍝ Parms[3]     = TCPTimeout    (opt) in msec (def 60 sec)
     ⍝ Parms[4]     = TCPDebugFlag  (opt) ##.TRUE: display debug messages or ##.FALSE (def): no session output
     ⍝
     ⍝ OCSPRequest  = ASN.1 DER encoding of the OCSPRequest
     ⍝ OCSPResponse = ASN.1 DER encoding of the OCSPResponse
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
     ⍝
     ⍝ Optional request header values:
          UserAgent←'Mozilla/4.0 (compatible; DYALOG; Win32)'
          MailBox←'e-secure@datev.de'
     ⍝ Resolve Parms
          :If 1<≡Parms
              :Select ↑⍴Parms
              :Case 1
                  RequestUrl←↑Parms
                  RequestMethod←''
                  TCPTimeout←60000
                  TCPDebugFlag←0
              :Case 2
                  RequestUrl RequestMethod←Parms
                  TCPTimeout←60000
                  TCPDebugFlag←0
              :Case 3
                  RequestUrl RequestMethod TCPTimeout←Parms
                  TCPDebugFlag←0
              :Else
                  RequestUrl RequestMethod TCPTimeout TCPDebugFlag←4↑Parms
              :EndSelect
          :Else
              RequestUrl←Parms
              RequestMethod←''
              TCPTimeout←60000
              TCPDebugFlag←0
          :EndIf
     ⍝ Check protocol and request method to build up request line:
          Protocol User Password Host Port UrlPath←#.TCPRequest.URL.Resolve RequestUrl
          :Select Protocol
          :Case 'http'
              :If ProxyFlag←×↑⍴RemoteUrl←#.TCPRequest.URL.GetDefaultProxy Protocol
                  RequestUrl←#.TCPRequest.URL.Build Protocol User Password Host Port UrlPath
              :Else
                  RemoteUrl←Host,':',Port
                  RequestUrl←((×↑⍴UrlPath)/'/'),UrlPath
              :EndIf
              HttpVersion←#.TCPRequest.HTTP.GetVersionDefault
              :If RequestMethod≡'GET'
              :AndIf 255>4+(↑⍴RequestUrl)+1+(⌊1.334×↑⍴OCSPRequest)+11
                  UrlEncodedRequest←2 #.TCPRequest.URL.Code ##.Base64.BaseEncode OCSPRequest
              :AndIf 255>4+(↑⍴RequestUrl)+1+(↑⍴UrlEncodedRequest)+11
                  RequestUrl,←(('/'≠↑⌽RequestUrl)/'/'),UrlEncodedRequest
                  OCSPRequest←''
              :Else
                  RequestMethod←'POST'
              :EndIf
              RequestLine←RequestMethod RequestUrl HttpVersion
              :Select RequestMethod
              :CaseList 'GET' 'POST'
             ⍝ Build up message header:
                  RequestHeader←0⍴⊂'' ''
                  RequestHeader,←⊂'Accept' 'application/ocsp-response'          ⍝ RFC 2616 14.1
                  RequestHeader,←(×↑⍴UserAgent)/⊂'User-Agent'UserAgent          ⍝ RFC 2616 14.43
                  RequestHeader,←(×↑⍴MailBox)/⊂'From'MailBox                    ⍝ RFC 2616 14.22
                  RequestHeader,←⊂'Host'(Host,('80'≢Port)/':',Port)             ⍝ RFC 2616 14.23
                  :If ⍬≢User                                                    ⍝ RFC 2616 14.8
                      RequestHeader,←⊂'Authorization'('Basic ',##.Base64.BaseEncode User,':',Password)
                  :EndIf
                  RequestHeader,←⊂'Connection' 'close'                          ⍝ RFC 2616 14.10
                  :If ProxyFlag
                      RequestHeader,←⊂'Pragma' 'no-cache'                       ⍝ RFC 2616 14.32 ⍝ PROXY
                      RequestHeader,←⊂'Cache-Control' 'no-cache'                ⍝ RFC 2616 14.9  ⍝ PROXY
                  :EndIf
                  :If 'POST'≡RequestMethod
                      RequestHeader,←⊂'Content-Type' 'application/ocsp-request' ⍝ RFC 2616 14.17 / RFC 2560
                  :EndIf
             ⍝ Perform OCSP request:
                  :If 0∊⍴↑↑StatusLine ResponseHeader OCSPResponse←RequestLine RequestHeader OCSPRequest #.TCPRequest.HTTP.Process RemoteUrl TCPTimeout TCPDebugFlag
                      HttpVersion StatusCode ReasonPhrase←StatusLine
                  :OrIf ~#.TCPRequest.HTTP.CheckStatusCode StatusCode
                  :OrIf 'application/ocsp-response'≢ResponseHeader #.TCPRequest.HTTP.GetFieldValueFromHeader'Content-Type'
                      :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.ERROR_INTERNET_INCORRECT_FORMAT ⋄ :EndIf
                      OCSPResponse←''
                  :EndIf
              :Else
                  #.RCode←#.Win.WSAENOPROTOOPT
                  OCSPResponse←''
              :EndSelect
          :Else
              #.RCode←#.Win.WSAEPROTONOSUPPORT
              OCSPResponse←''
          :EndSelect
        ∇

        ∇ Response←Request RebuildResponse Parms;OcspUrl;RequestMethod;TCPTimeout;TCPDebugFlag;SignatureCertificate;RequestCertificates;IssuerCertificates;SingleRequExtnsList;RequExtns;RequestCertificate;IssuerCertificate;SingleRequExtns;SingleRequests;ValidFlag;CertIDs;CertID;Asn1Request;Asn1Response;Response;ResponseStatus;ResponseData;ResponderID;ProducedAt;ResponseList;RespExtns;RequIndex;RespIndex;CertStatus;CRLReason;RevocationTime;ThisUpdate;NextUpdate;SingleRespExtns;ExtnValue;AlgorithmIdentifier;Digest;Algorithm;Parameters;algorithmHash;CriticalState;NonceRequFlag
     ⍝ Build an ASN1 OCSP Request and send it out to the given request URL.
     ⍝ Then wait for ASN1 OCSP Response AND resolve it.
     ⍝
     ⍝ Parms[1]    = Asn1Response
     ⍝ Parms[2]    = Asn1Request
     ⍝
     ⍝ Request[1] = RequestCertificates  Vector of Certificate to query
     ⍝ Request[2] = IssuerCertificates   (opt.) Vector (corresponding to RequestCertificates) of Certificate of the CAs which have signed the RequestCertificates to query
     ⍝ Request[3] = SingleRequExtnsList  (opt.) Vector (corresponding to RequestCertificates) of Vectors of (OID CriticalFlag ExtensionValue)
     ⍝ Request[4] = RequExtns            (opt.) Vector of (OID CriticalFlag ExtensionValue)
     ⍝ Request[5] = SignatureCertificate (opt.) Certificate to sign the request with or ''
     ⍝
     ⍝ Response[1] = ResponseStatus    (#.ASN1.OCSP.ORS_SUCCESSFUL ORS_MALFORMED_REQUEST ORS_INTERNAL_ERROR ORS_TRY_LATER ORS_INVALID_REQUEST_SIGNATURE ORS_SIG_REQUIRED ORS_UNAUTHORIZED ORS_UNKNOWN_RESPONSE_TYPE ORS_INVALID_RESPONSE_SIGNATURE or ORS_MALFORMED_RESPONSE)
     ⍝ Response[2] = ResponseData      If ResponseStatus=#.ASN1.OCSP.ORS_SUCCESSFUL:
     ⍝               ResponseData[1] = ResponderID  Name structure of the resopnder
     ⍝               ResponseData[2] = ProducedAt   ⎕TS at which the OCSP responder signed this response
     ⍝               ResponseData[3] = ResponseList Vector of (CertID CertStatus CRLReason RevocationTime ThisUpdate NextUpdate SingleRespExtns)(..repeated for each single requ..)
     ⍝               ResponseData[4] = RespExtns    Vector of (OID CriticalFlag ExtensionValue)(..)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
     ⍝
     ⍝ Assign Parameters
          :Select ↑⍴Request
          :Case 1
              RequestCertificates←↑Request
              IssuerCertificates SingleRequExtnsList RequExtns SignatureCertificate←(0⍴⊂'')(0⍴⊂0⍴⊂⍬ 0 '')(0⍴⊂⍬ 0 '')''
          :Case 2
              RequestCertificates IssuerCertificates←Request
              SingleRequExtnsList RequExtns SignatureCertificate←(0⍴⊂0⍴⊂⍬ 0 '')(0⍴⊂⍬ 0 '')''
          :Case 3
              RequestCertificates IssuerCertificates SingleRequExtnsList←Request
              RequExtns SignatureCertificate←(0⍴⊂⍬ 0 '')''
          :Case 4
              RequestCertificates IssuerCertificates SingleRequExtnsList RequExtns←Request
              SignatureCertificate←''
          :Case 5
              RequestCertificates IssuerCertificates SingleRequExtnsList RequExtns SignatureCertificate←Request
          :EndSelect
     ⍝ Transaction Parameters
          Asn1Response Asn1Request←Parms
     ⍝ Build single sub-request(s)
          SingleRequests←0⍴⊂'' ''
          CertIDs←0⍴⊂''
          ValidFlag←1
          :For RequestCertificate IssuerCertificate SingleRequExtns :In ⊂[1]⊃RequestCertificates IssuerCertificates SingleRequExtnsList
              :If ValidFlag←''≢CertID←BuildCertID RequestCertificate IssuerCertificate
                  CertIDs,←⊂CertID
                  SingleRequests,←⊂CertID SingleRequExtns
              :Else
                  :Leave
              :EndIf
          :EndFor
          :If ValidFlag
     ⍝ Resolve ASN.1 encoded OCSP Response
              :If ORS_SUCCESSFUL=↑ResponseStatus ResponseData←CertIDs ResolveResponse Asn1Response
                  ResponderID ProducedAt ResponseList RespExtns←ResponseData
     ⍝ If supported, check for valid NonceValue, RequestedCertificate and CertHash
                  :If NonceRequFlag←(↑⍴RequExtns)≥RequIndex←(↑¨RequExtns)⍳⊂id_pkix_ocsp_nonce
                  :AndIf CriticalState←RequIndex 2⊃RequExtns
                  :AndIf (↑⍴RespExtns)<RespIndex←(↑¨RespExtns)⍳⊂id_pkix_ocsp_nonce
                      :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.TRUST_E_FAIL ⋄ :EndIf
                      ResponseStatus←ORS_NONCE_MISSING
                  :ElseIf NonceRequFlag
                  :AndIf (↑⍴RespExtns)≥RespIndex←(↑¨RespExtns)⍳⊂id_pkix_ocsp_nonce
                  :AndIf (1 ##.Code RequIndex 3⊃RequExtns)≢1 ##.Code RespIndex 3⊃RespExtns
                      :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_NO_MATCH ⋄ :EndIf
                      ResponseStatus←ORS_NONCE_VALUE_NO_MATCH
                  :ElseIf 0×(⍴ResponseList)≢⍴RequestCertificates
                      :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_NO_MATCH ⋄ :EndIf
                      ResponseStatus←ORS_CERTIFICATE_NO_MATCH
                  :Else
                      :For RequestCertificate CertID CertStatus CRLReason RevocationTime ThisUpdate NextUpdate SingleRespExtns SingleRequExtns :In (⊂¨(⍴ResponseList)↑RequestCertificates),¨ResponseList,¨⊂¨(⍴ResponseList)↑SingleRequExtnsList
                          :If (↑⍴SingleRequExtns)≥RequIndex←(↑¨SingleRequExtns)⍳⊂id_isismtt_at_retrieveIfAllowed
                              CriticalState←RequIndex 2⊃SingleRequExtns
                          :Else
                              CriticalState←¯1
                          :EndIf
                          :If (↑⍴SingleRespExtns)≥RespIndex←(↑¨SingleRespExtns)⍳⊂id_isismtt_at_requestedCertificate
                          :AndIf (∧/''RequestCertificate≢¨⊂1 ##.Code RespIndex 3⊃SingleRespExtns)∨CriticalState∊¯1 0
                          :AndIf (∧/(1 ##.Code(##.CONTEXT 0)(##.OCTETSTRING''))(1 ##.Code(##.CONTEXT 0)(##.OCTETSTRING RequestCertificate))(1 ##.Code(##.CONTEXT 1)(##.OCTETSTRING RequestCertificate))≢¨⊂1 ##.Code RespIndex 3⊃SingleRespExtns)∨CriticalState∊¯1
                              :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_NO_MATCH ⋄ :EndIf
                              ResponseStatus←ORS_CERTIFICATE_NO_MATCH
                              :Leave
                          :ElseIf (↑⍴SingleRespExtns)≥RespIndex←(↑¨SingleRespExtns)⍳⊂id_isismtt_at_certHash
                              :If (1+2)≠↑⍴ExtnValue←0 ##.Code RespIndex 3⊃SingleRespExtns
                              :OrIf (1+2 1)≢↑∘⍴¨AlgorithmIdentifier Digest←1↓ExtnValue
                              :OrIf ##.SEQUENCE ##.OCTETSTRING≢↑¨AlgorithmIdentifier Digest
                              :OrIf (1+1 0)≢↑∘⍴¨Algorithm Parameters←1↓AlgorithmIdentifier
                              :OrIf ##.OID(↑##.NULLTAG)≢↑¨Algorithm Parameters
                                  algorithmHash←↑1↓Algorithm
                                  Digest←↑1↓Digest
                              :OrIf Digest≢RequestCertificate #.Crypt.Hash #.Crypt.OidToAlgid algorithmHash
                                  :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_HASH_VALUE ⋄ :EndIf
                                  ResponseStatus←ORS_CERTHASH_NO_MATCH
                                  :Leave
                              :EndIf
                          :EndIf
                      :EndFor
                  :EndIf
              :EndIf
          :Else
              Asn1Request←''
              Asn1Response←''
              ResponseStatus←ORS_REQUEST_BUILD_ERROR
              ResponseData←''
          :EndIf
          Response←ResponseStatus ResponseData
        ∇

        ∇ ResponseParms←{CertIDs}ResolveResponse OCSPResponse;CertIDsFlag;OCSPResponseStatus;ResponseStatus;ResponseBytes;ResponseType;Response;BasicOCSPResponse;ResponseData;AlgorithmIdentifier;Signature;Certs;Algorithm;Parameters;algorithmSign;AlgidSign;SequenceOfCerts;Certificate;Version;ResponderID;ProducedAt;Responses;ResponseExtensions;SingleResponse;ResponseList;Index;CertID;CertStatus;ThisUpdate;NextUpdate;SingleExtensions;RevocationTime;RevocationReason;CRLReason
     ⍝⍝ Decodieren eines OCSP-Response nach RFC2560 (PKIX.509 - Online Certificate Status Protocol - OCSP)
     ⍝
     ⍝X  OCSPResponse        = ASN.1 codierte Antwoer vom OCSP-Responder
     ⍝Y  CertIDs             = Optionaler Vektor von CertID zur Festlegung der Reihenfolge in "Responses"
     ⍝
     ⍝R  ResponseParms[1]    = ResponseStatus     ORS_SUCCESSFUL ORS_MALFORMED_REQUEST ORS_INTERNAL_ERROR ORS_TRY_LATER ORS_INVALID_REQUEST_SIGNATURE ORS_SIG_REQUIRED ORS_UNAUTHORIZED ORS_UNKNOWN_RESPONSE_TYPE ORS_INVALID_RESPONSE_SIGNATURE or ORS_MALFORMED_RESPONSE
     ⍝R  ResponseParms[2]    = ResponseData       ResponseStatus=ORS_SUCCESSFUL: see below, '' otherwise
     ⍝R   ResponseData[1]    = ResponderID        Name structure of the resopnder
     ⍝R   ResponseData[2]    = ProducedAt         ⎕TS at which the OCSP responder signed this response
     ⍝R   ResponseData[3]    = Responses          Vector of "SingleResponse":
     ⍝R    SingleResponse[1] = CertID             Encoded certificate identification
     ⍝R    SingleResponse[2] = CertStatus         OCS_GOOD OCS_REVOKED OCS_UNKNOWN or OCS_NOANSWER
     ⍝R    SingleResponse[3] = CRLReason          If CertStatus=OCS_REVOKED: #.Win.CRL_REASON_UNSPECIFIED #.Win.CRL_REASON_KEY_COMPROMISE #.Win.CRL_REASON_CA_COMPROMISE #.Win.CRL_REASON_AFFILIATION_CHANGED #.Win.CRL_REASON_SUPERSEDED #.Win.CRL_REASON_CESSATION_OF_OPERATION #.Win.CRL_REASON_CERTIFICATE_HOLD or #.Win.CRL_REASON_REMOVE_FROM_CRL
     ⍝R    SingleResponse[4] = RevocationTime     If CertStatus=OCS_REVOKED: ⎕TS when certificate has been revoked
     ⍝R    SingleResponse[5] = ThisUpdate         ⎕TS at which the status being indicated is known to be correct
     ⍝R    SingleResponse[6] = NextUpdate         ⎕TS at or before which newer information will be available about the status of the certificate
     ⍝R    SingleResponse[7] = SingleExtensions   Single extensions of the resonse
     ⍝R   ResponseData[4]    = ResponseExtensions Global extensions of the resonse
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
          CertIDsFlag←×⎕NC'CertIDs'
          ResponseStatus←ORS_SUCCESSFUL
          :If ×↑⍴OCSPResponse←6 ##.Code OCSPResponse                ⍝ OCSPResponse       ::= SEQUENCE {
          :AndIf (1+1)≤↑⍴OCSPResponse                               ⍝     responseStatus         OCSPResponseStatus,
          :AndIf ##.SEQUENCE≡↑OCSPResponse                          ⍝     responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
              OCSPResponseStatus ResponseBytes←2↑1↓OCSPResponse
          :AndIf (1+1)=↑⍴OCSPResponseStatus                         ⍝ OCSPResponseStatus ::= ENUMERATED {
          :AndIf ##.ENUMERATED≡↑OCSPResponseStatus                  ⍝     successful             (0=ORS_SUCCESSFUL),        --Response has valid confirmations
          :AndIf ORS_SUCCESSFUL=ResponseStatus←2⊃OCSPResponseStatus ⍝     malformedRequest       (1=ORS_MALFORMED_REQUEST), --Illegal confirmation request
          :AndIf (1+1)=↑⍴ResponseBytes                              ⍝     internalError          (2=ORS_INTERNAL_ERROR),    --Internal error in issuer
          :AndIf (##.CONTEXT 0)≡↑ResponseBytes                      ⍝     tryLater               (3=ORS_TRY_LATER),         --Try again later
          :AndIf (1+2)=↑⍴ResponseBytes←2⊃ResponseBytes              ⍝     sigRequired            (5=ORS_SIG_REQUIRED),      --Must sign the request
          :AndIf ##.SEQUENCE≡↑ResponseBytes                         ⍝     unauthorized           (6=ORS_UNAUTHORIZED) }     --Request unauthorized
              ResponseType Response←1↓ResponseBytes
          :AndIf (1+1)=↑⍴ResponseType                               ⍝ ResponseBytes      ::= SEQUENCE {
          :AndIf ##.OID≡↑ResponseType                               ⍝     responseType           OBJECT IDENTIFIER (id-pkix-ocsp-basic),
              #.RCode←#.Win.CRYPT_E_UNEXPECTED_ENCODING             ⍝     response               OCTET STRING BasicOCSPResponse }
          :AndIf id_pkix_ocsp_basic≡2⊃ResponseType
              #.RCode←#.Win.ERROR_SUCCESS                           ⍝ BasicOCSPResponse  ::= SEQUENCE {
          :AndIf (1+1)=↑⍴Response                                   ⍝     tbsResponseData        ResponseData,
          :AndIf ##.OCTETSTRING≡↑Response                           ⍝     signatureAlgorithm     AlgorithmIdentifier,
          :AndIf (1+4)=↑⍴BasicOCSPResponse←2⊃Response               ⍝     signature              BIT STRING,
          :AndIf ##.SEQUENCE≡↑BasicOCSPResponse                     ⍝     certs                  [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
              ResponseData AlgorithmIdentifier Signature Certs←1↓BasicOCSPResponse
              ResponseStatus←ORS_INVALID_RESPONSE_SIGNATURE
          :AndIf (1+1)≤↑⍴AlgorithmIdentifier←0 ##.Code AlgorithmIdentifier
          :AndIf ##.SEQUENCE≡↑AlgorithmIdentifier
              Algorithm Parameters←2↑(1↓AlgorithmIdentifier),⊂##.NULLTAG
          :AndIf (1+1)=↑⍴Algorithm                                  ⍝ AlgorithmIdentifier::= SEQUENCE  {
          :AndIf ##.OID≡↑Algorithm                                  ⍝     algorithm              OBJECT IDENTIFIER,
          :AndIf ##.NULLTAG≡Parameters                              ⍝     parameters             ANY DEFINED BY algorithm OPTIONAL }
          :AndIf 0≠AlgidSign←#.Crypt.OidToAlgid algorithmSign←2⊃Algorithm
          :AndIf (1+1)=↑⍴Signature←2 ##.Code Signature
          :AndIf ##.BITSTRING≡↑Signature
          :AndIf 0=8|↑⍴Signature←2⊃Signature
          :AndIf (1+1)=↑⍴Certs←3 ##.Code Certs
          :AndIf (##.CONTEXT 0)≡↑Certs
          :AndIf (1+1)≤↑⍴SequenceOfCerts←2⊃Certs
          :AndIf ##.SEQUENCE≡↑SequenceOfCerts
          :AndIf ×↑⍴SequenceOfCerts←##.X509.GetCertificateChain 1↓SequenceOfCerts
          :AndIf #.Win.TRUE∧.=##.X509.VerifyCertificateChain SequenceOfCerts
          :AndIf 1                                                  ⍝ Nachzutragen: Überprüfung der Vertrauensstellung des Root-Zertifikats
          :AndIf ×↑⍴Certificate←↑SequenceOfCerts
          :AndIf #.Win.TRUE=ResponseData #.Crypt.VerifySignature Certificate Signature AlgidSign
              ResponseStatus←ORS_SUCCESSFUL
          :AndIf (1+3)≤↑⍴ResponseData←4 ##.Code ResponseData
          :AndIf ##.SEQUENCE≡↑ResponseData
              :Select ↑¨ResponseData←1↓ResponseData
              :CaseList ((##.CONTEXT 1)##.GENERALIZEDTIME ##.SEQUENCE)((##.CONTEXT 2)##.GENERALIZEDTIME ##.SEQUENCE)
                  Version←⊂##.INTEGER v1
                  ResponderID ProducedAt Responses←1↓¨ResponseData
                  ResponseExtensions←⊂''
              :CaseList ((##.CONTEXT 0)(##.CONTEXT 1)##.GENERALIZEDTIME ##.SEQUENCE)((##.CONTEXT 0)(##.CONTEXT 2)##.GENERALIZEDTIME ##.SEQUENCE)
                  Version ResponderID ProducedAt Responses←1↓¨ResponseData
                  ResponseExtensions←⊂''
              :CaseList ((##.CONTEXT 1)##.GENERALIZEDTIME ##.SEQUENCE(##.CONTEXT 1))((##.CONTEXT 2)##.GENERALIZEDTIME ##.SEQUENCE(##.CONTEXT 1))
                  Version←⊂##.INTEGER v1
                  ResponderID ProducedAt Responses ResponseExtensions←1↓¨ResponseData
              :CaseList ((##.CONTEXT 0)(##.CONTEXT 1)##.GENERALIZEDTIME ##.SEQUENCE(##.CONTEXT 1))((##.CONTEXT 0)(##.CONTEXT 2)##.GENERALIZEDTIME ##.SEQUENCE(##.CONTEXT 1))
                  Version ResponderID ProducedAt Responses ResponseExtensions←1↓¨ResponseData
              :Else
                  Version ResponderID ProducedAt Responses ResponseExtensions←⊂''
              :EndSelect                                                 ⍝ ResponseData       ::= SEQUENCE {
          :AndIf ##.INTEGER v1≡↑Version                                  ⍝     version                [0] EXPLICIT Version DEFAULT v1,
          :AndIf 1=↑⍴ResponderID                                         ⍝     responderID            ResponderID,
          :AndIf ''≢ResponderID←##.LDAP.ConvertNameToString↑ResponderID  ⍝     producedAt             GeneralizedTime,
              ResponderID←##.LDAP.FormatStringToMultiline ResponderID   ⍝     responses              SEQUENCE OF SingleResponse,
          :AndIf 1=↑⍴ProducedAt                                          ⍝     responseExtensions     [1] EXPLICIT Extensions OPTIONAL }
              ProducedAt←↑ProducedAt
          :AndIf 1≤↑⍴Responses                                           ⍝ ResponderID        ::= CHOICE {
          :AndIf 1≥↑⍴ResponseExtensions                                  ⍝     byName                 [1] EXPLICIT Name,
              ResponseExtensions←↑ResponseExtensions                     ⍝     byKey                  [2] EXPLICIT OCTET STRING KeyHash }
              :If CertIDsFlag
                  ResponseList←,∘OCS_NOANSWER 0(0 0 0 0 0 0 0)(0 0 0 0 0 0 0)(0 0 0 0 0 0 0)(0⍴⊂⍬ 0 '')∘⊂¨CertIDs
              :Else
                  ResponseList←0⍴⊂''OCS_NOANSWER 0(0 0 0 0 0 0 0)(0 0 0 0 0 0 0)(0 0 0 0 0 0 0)(0⍴⊂⍬ 0 '')
              :EndIf
              :For SingleResponse :In Responses
                  :If ##.SEQUENCE≡↑SingleResponse                                       ⍝ SingleResponse     ::= SEQUENCE {
                      :Select ↑⍴SingleResponse←1↓SingleResponse                         ⍝     certID                 CertID,
                      :Case 3                                                           ⍝     certStatus             CertStatus,
                          CertID CertStatus ThisUpdate←SingleResponse                   ⍝     thisUpdate             GeneralizedTime,
                          NextUpdate←(##.CONTEXT 0)(##.GENERALIZEDTIME(0 0 0 0 0 0 0))  ⍝     nextUpdate             [0] EXPLICIT GeneralizedTime OPTIONAL,
                          SingleExtensions←''                                           ⍝     singleExtensions       [1] EXPLICIT Extensions OPTIONAL }
                      :Case 4
                          :Select ↑2 ##.Code 4⊃SingleResponse
                          :Case ##.CONTEXT 0
                              CertID CertStatus ThisUpdate NextUpdate←SingleResponse
                              SingleExtensions←''
                          :Case ##.CONTEXT 1
                              CertID CertStatus ThisUpdate SingleExtensions←SingleResponse
                              NextUpdate←(##.CONTEXT 0)(##.GENERALIZEDTIME(0 0 0 0 0 0 0))
                          :Else
                              #.RCode←#.Win.CRYPT_E_UNEXPECTED_ENCODING
                              :Leave
                          :EndSelect
                      :Case 5
                          CertID CertStatus ThisUpdate NextUpdate SingleExtensions←SingleResponse
                      :Else
                          #.RCode←#.Win.CRYPT_E_UNEXPECTED_ENCODING
                          :Leave
                      :EndSelect
                      :Select ↑CertStatus←0 ##.Code CertStatus                          ⍝ CertStatus         ::= CHOICE {
                      :Case ##.CLASS_CONTEXT ##.FORM_PRIMITIVE OCS_GOOD                 ⍝     good                   [0] IMPLICIT NULL,
                          CertStatus←OCS_GOOD                                           ⍝     revoked                [1] IMPLICIT RevokedInfo,
                          RevocationTime←0 0 0 0 0 0 0                                  ⍝     unknown                [2] IMPLICIT NULL }
                          CRLReason←#.Win.CRL_REASON_UNSPECIFIED
                      :Case ##.CLASS_CONTEXT ##.FORM_CONSTRUCTED OCS_REVOKED
                          :If 1≤↑⍴CertStatus←1↓CertStatus                               ⍝ RevokedInfo        ::= SEQUENCE {
                          :AndIf ##.GENERALIZEDTIME≡↑RevocationTime←↑CertStatus         ⍝     revocationTime         GeneralizedTime,
                              RevocationTime←2⊃RevocationTime                           ⍝     revocationReason       [0] EXPLICIT CRLReason OPTIONAL }
                              :If 2≤↑⍴CertStatus
                              :AndIf (##.CONTEXT 0)≡↑RevocationReason←2⊃CertStatus      ⍝ CRLReason          ::= ENUMERATED {
                              :AndIf ##.ENUMERATED≡↑RevocationReason←2⊃RevocationReason ⍝     unspecified            (0=#.Win.CRL_REASON_UNSPECIFIED),
                                  CRLReason←2⊃RevocationReason                          ⍝     keyCompromise          (1=#.Win.CRL_REASON_KEY_COMPROMISE),
                              :Else                                                     ⍝     cACompromise           (2=#.Win.CRL_REASON_CA_COMPROMISE),
                                  CRLReason←#.Win.CRL_REASON_UNSPECIFIED                ⍝     affiliationChanged     (3=#.Win.CRL_REASON_AFFILIATION_CHANGED),
                              :EndIf                                                    ⍝     superseded             (4=#.Win.CRL_REASON_SUPERSEDED),
                          :Else                                                         ⍝     cessationOfOperation   (5=#.Win.CRL_REASON_CESSATION_OF_OPERATION),
                              #.RCode←#.Win.CRYPT_E_UNEXPECTED_ENCODING                 ⍝     certificateHold        (6=#.Win.CRL_REASON_CERTIFICATE_HOLD),
                              :Leave                                                    ⍝     removeFromCRL          (8=#.Win.CRL_REASON_REMOVE_FROM_CRL) }
                          :EndIf
                          CertStatus←OCS_REVOKED
                      :Case ##.CLASS_CONTEXT ##.FORM_PRIMITIVE OCS_UNKNOWN
                          RevocationTime←0 0 0 0 0 0 0
                          CRLReason←#.Win.CRL_REASON_UNSPECIFIED
                          CertStatus←OCS_UNKNOWN
                      :Else
                          #.RCode←#.Win.CRYPT_E_UNEXPECTED_ENCODING
                          :Leave
                      :EndSelect
                  :AndIf (1+1)=↑⍴ThisUpdate←2 ##.Code ThisUpdate
                  :AndIf ##.GENERALIZEDTIME≡↑ThisUpdate
                      ThisUpdate←2⊃ThisUpdate
                  :AndIf (1+1)=↑⍴NextUpdate←3 ##.Code NextUpdate
                  :AndIf (##.CONTEXT 0)≡↑NextUpdate
                  :AndIf (1+1)=↑⍴NextUpdate←2⊃NextUpdate
                  :AndIf ##.GENERALIZEDTIME≡↑NextUpdate
                      NextUpdate←2⊃NextUpdate
                  :AndIf ''≢SingleExtensions←1 #.ASN1.X509.ResolveExtensions SingleExtensions
                      SingleResponse←CertID CertStatus CRLReason RevocationTime ThisUpdate NextUpdate SingleExtensions
                      :If CertIDsFlag
                      :AndIf (↑⍴ResponseList)≥Index←((CertID∘CompareCertIDs¨↑¨ResponseList)∧OCS_NOANSWER=2⊃¨ResponseList)⍳1
                          ResponseList[Index]←⊂SingleResponse
                      :Else
                          ResponseList,←⊂SingleResponse
                      :EndIf
                  :Else
                      :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_UNEXPECTED_ENCODING ⋄ :EndIf
                      :Leave
                  :EndIf
              :EndFor
          :AndIf #.RCode=#.Win.ERROR_SUCCESS
          :AndIf ''≢ResponseExtensions←#.ASN1.X509.ResolveExtensions ResponseExtensions
              ResponseData←ResponderID ProducedAt ResponseList ResponseExtensions
          :Else
              :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_UNEXPECTED_ENCODING ⋄ :EndIf
              :If ResponseStatus=ORS_SUCCESSFUL ⋄ ResponseStatus←ORS_MALFORMED_RESPONSE ⋄ :EndIf
              ResponseData←''
          :EndIf
          ResponseParms←ResponseStatus ResponseData
     ⍝ Exit
        ∇

        ∇ OcspResponse←Samples Selection;SignatureCertificate;RequestCertificates;IssuerCertificates;SingleRequExtnList;RequestExtensions;OcspUrl;RequestMethod;TCPTimeout;TCPDebugFlag;Asn1Request;Asn1Response;ExtensionRetrieveIfAllowed;NonceValue;ExtensionNonce;ExtensionResponse
          Init
          :Select Selection
          :Case 1
              RequestCertificates←,⊂852886005
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01.CRT'
              OcspUrl←'http://x0288v02.bk.datev.de/ocsp/status' ⍝ TC001:STBKN 10.230.33.46
          :Case 2
              RequestCertificates←,⊂852886915
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01.CRT'
              OcspUrl←'http://x0288v02.bk.datev.de/ocsp/status' ⍝ TC001:STBKN 10.230.33.46
          :Case 3
              RequestCertificates←,⊂7679852 7679852 76799887 454245 990210004 '123456789012345678987654321'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\SigG\CA_DATEV_D01.CRT'
              OcspUrl←'http://x0288v03.bk.datev.de/ocsp/status' ⍝ TC999:DATEV 10.230.33.47
          :Case 4
              RequestCertificates←,⊂'123456789012345678987654321'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\SigG\CA_DATEV_D01.CRT'
              OcspUrl←'http://x0288v05.bk.datev.de/ocsp/status' ⍝ P323 10.230.33.67
          :Case 5
              RequestCertificates←'3331597' '852885973' '3331631' '3331687' '3331708' '3331781' '3331760' '3331774' '3331798' '3331808' '3331811' '3331821' '3331824' '852885951' '852885955' '852885961' '852885927' '3331672'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01.CRT'
              OcspUrl←'http://www.dir.stbk-nuernberg.zsdk.de/' ⍝ TC001:STBKN 10.230.33.46
          :Case 6
              RequestCertificates←#.Win.File.Load¨'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01_3331597.CRT' 'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01_3331631.CRT' 'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01_3331687.CRT' 'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01_3331781.CRT' 'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01_3331774.CRT' 'C:\SperrClient\OCSP\Certificates\SigG\CA_STBKN_N01_852885951.CRT'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂''
              OcspUrl←GetRequestUrlFromCertificate↑CertificateOrSerialNumber
          :Case 12
              RequestCertificates←,⊂'11269502289130331777421905893784819869'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\VeriSign\VerisignTimeStampingService.cer'
              OcspUrl←GetRequestUrlFromCertificate↑IssuerCertificates
          :Case 13
              RequestCertificates←,⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\Hager\HAGER-ELECTRONICS.CER'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂''
              OcspUrl←'http://ocsp.verisign.com/ocsp/status'
          :Case 14
              RequestCertificates←,⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\Hager\Peter-Michael Hager.CER'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂''
              OcspUrl←'http://ocsp.verisign.com/ocsp/status'
          :Case 15
              RequestCertificates←,⊂'17047356887913397006293968768065587546'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\VeriSign\Class3Root.CER'
              OcspUrl←'http://ocsp.verisign.com/ocsp/status'
         
          :Case 20
              RequestCertificates←#.Win.File.Load¨'C:\SperrClient\OCSP\Certificates\ValiCert\PomeGranite-Good.CER' 'C:\SperrClient\OCSP\Certificates\ValiCert\PomeGranite-Bad.CER' 'C:\SperrClient\OCSP\Certificates\ValiCert\Vegetables-Good.CER' 'C:\SperrClient\OCSP\Certificates\ValiCert\Vegetables-Bad.CER'
              IssuerCertificates←(⍴RequestCertificates)⍴⊂#.Win.File.Load'C:\SperrClient\OCSP\Certificates\ValiCert\PomeGranite-Root.CER'
              OcspUrl←'http://ocsp2.valicert.net'
          :EndSelect
     ⍝ Transaction Parameters
          RequestMethod←'POST'
          TCPTimeout←10000
          TCPDebugFlag←0
     ⍝ Some typical extensions
          ExtensionRetrieveIfAllowed←id_isismtt_at_retrieveIfAllowed ##.TRUE(##.BOOLEAN ##.TRUE)
           ⋄ NonceValue←1 ##.Code ##.OCTETSTRING(#.Crypt.Random 20)
          ExtensionNonce←id_pkix_ocsp_nonce ##.FALSE NonceValue
          ExtensionResponse←id_pkix_ocsp_response ##.FALSE(##.SEQUENCE(##.OID id_pkix_ocsp_basic))
     ⍝ Applied extensions
          SingleRequExtnList←(⍴RequestCertificates)⍴⊂ExtensionRetrieveIfAllowed
          RequestExtensions←ExtensionNonce ExtensionResponse
     ⍝ Signature
          SignatureCertificate←'' ⍝ #.Win.File.Load'C:\SperrClient\OCSP\Certificates\Hager\Peter-Michael Hager.CER'
     ⍝
          OcspResponse Asn1Response Asn1Request←RequestCertificates IssuerCertificates SingleRequExtnList RequestExtensions SignatureCertificate PerformTransaction OcspUrl RequestMethod TCPTimeout TCPDebugFlag
          Exit
        ∇

        :Namespace Secunet
            ⎕IO ⎕ML ⎕WX ⎕PP ⎕DIV←1 3 1 16 1

            ∇ ModifyRequest←BuildLdapModifyRequest Parms;DName;signature;SignCert;algorithmOid;CertType;SperrNutzdaten;add;delete;replace;CertTypeValue;Object;Algorithm;Parameters;AlgorithmIdentifier;Signature;Operation;AttributeDescription;AttributeValue;AttributeTypeAndValues;ModificationSignature;ModificationType;ModificationData;Modification
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.102-103 4.3.6  LDAP-Komponente
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.143     7.2.2  Kodierung der Modify-/Sperr-Operation
     ⍝ Die Access_Config_List-Informationen entsprechen denen der ASN.1 Definition Signature
     ⍝
     ⍝ Parms[1] = DName          see below
     ⍝ Parms[1] = signature      Signature of the SperrNutzdaten as ASN.1 encoded bit string
     ⍝ Parms[2] = SignCert       Certificate used for signing the SperrNutzdaten with
     ⍝ Parms[3] = algorithmOid   OID of the signature as integer vector
     ⍝ Parms[4] = CertType       Certificate type 0=signature certificate 1=attribute certificate
     ⍝ Parms[5] = SperrNutzdaten ASN.1 encoded sequence
     ⍝
     ⍝ ModifyRequest = Encoded LDAP APPLICATION[6] ASN.1 Sequence
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
              DName signature SignCert algorithmOid CertType SperrNutzdaten←Parms
     ⍝ DName←'SNcertNr=7679934,SNissuerNameHash=9556fc2a3fecc479e553d21f9efe8f397781e8e8,SNcaName=EBEREICH'
     ⍝ #.ASN1.UTO_FMT #.ASN1.X509.GetCertificateSerialNumber Cert                      ⍝ 7679934
     ⍝ #.Win.HexTxt(#.ASN1.X509.GetCertificateIssuer Cert)#.Crypt.Hash #.Win.CALG_SHA1 ⍝ 9556FC2A3FECC479E553D21F9EFE8F397781E8E8
     ⍝ #.ASN1.LDAP.ConvertNameToString #.ASN1.X509.GetCertificateIssuer Cert           ⍝ CN = CA DATEV D01 1:PN  PM = 1  O = DATEV eG  C = DE
              add delete replace←0 1 2
              CertTypeValue←(1+CertType)⊃'MAINCERT' 'ATTRIBUTECERT'
               ⋄ Object←##.##.OCTETSTRING DName
               ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ Algorithm←##.##.OID algorithmOid
               ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ Parameters←##.##.NULLTAG
               ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ AlgorithmIdentifier←##.##.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ ⋄ Signature←##.##.SEQUENCE AlgorithmIdentifier signature((##.##.CONTEXT 0)##.##.SEQUENCE SignCert)
               ⋄ ⋄ ⋄ Operation←##.##.ENUMERATED replace
               ⋄ ⋄ ⋄ ⋄ AttributeDescription←##.##.OCTETSTRING'signature'
               ⋄ ⋄ ⋄ ⋄ AttributeValue←##.##.OCTETSTRING Signature
               ⋄ ⋄ ⋄ AttributeTypeAndValues←##.##.SEQUENCE AttributeDescription(##.##.SET AttributeValue)
               ⋄ ⋄ ModificationSignature←##.##.SEQUENCE Operation AttributeTypeAndValues
               ⋄ ⋄ ⋄ ⋄ AttributeDescription←##.##.OCTETSTRING'type'
               ⋄ ⋄ ⋄ ⋄ AttributeValue←##.##.OCTETSTRING CertTypeValue
               ⋄ ⋄ ⋄ AttributeTypeAndValues←##.##.SEQUENCE AttributeDescription(##.##.SET AttributeValue)
               ⋄ ⋄ ModificationType←##.##.SEQUENCE Operation AttributeTypeAndValues
               ⋄ ⋄ ⋄ ⋄ AttributeDescription←##.##.OCTETSTRING'data'
               ⋄ ⋄ ⋄ ⋄ AttributeValue←##.##.OCTETSTRING SperrNutzdaten
               ⋄ ⋄ ⋄ AttributeTypeAndValues←##.##.SEQUENCE AttributeDescription(##.##.SET AttributeValue)
               ⋄ ⋄ ModificationData←##.##.SEQUENCE Operation AttributeTypeAndValues
               ⋄ Modification←##.##.SEQUENCE ModificationSignature ModificationType ModificationData
              ModifyRequest←1 ##.##.Code(##.##.CLASS_APPLICATION ##.##.FORM_CONSTRUCTED 6)(##.##.SEQUENCE Object Modification)
            ∇

            ∇ SperrNutzdaten←BuildSperrNutzdaten Parms;TimeStampToGeneralizedTime;CrlReasonToSperrGrundID;CertOrSerialNumber;RevokeFlag;CrlTime;CrlReason;certNr;gesperrt;sperrDatum;sperrGrundID;CertNr;Gesperrt;SperrDatum;SperrGrundID
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.102-103 4.3.6  LDAP-Komponente
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.143     7.2.2  Kodierung der Modify-/Sperr-Operation
     ⍝
     ⍝ Parms[1] = CertOrSerialNumber X.509 Certificate or AttributeCertificate or CertificateSerialNumber
     ⍝ Parms[2] = RevokeFlag         #.Win.TRUE or #.Win.FALSE
     ⍝ Parms[3] = CrlTime            ⎕TS formatted time
     ⍝ Parms[4] = CrlReason          #.Win.CRL_REASON_KEY_COMPROMISE #.Win.CRL_REASON_CA_COMPROMISE #.Win.CRL_REASON_AFFILIATION_CHANGED or #.Win.CRL_REASON_CESSATION_OF_OPERATION
     ⍝
     ⍝ SperrNutzdaten                ASN.1 string for LDAP modify
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
              TimeStampToGeneralizedTime←{2⊃2(30⍴#.ASN1.UTO_STR)#.ASN1.Code 1 #.ASN1.Code #.ASN1.GENERALIZEDTIME ⍵}
              CrlReasonToSperrGrundID←{(#.Win.CRL_REASON_KEY_COMPROMISE #.Win.CRL_REASON_CA_COMPROMISE #.Win.CRL_REASON_AFFILIATION_CHANGED #.Win.CRL_REASON_SUPERSEDED #.Win.CRL_REASON_CESSATION_OF_OPERATION #.Win.CRL_REASON_CERTIFICATE_HOLD #.Win.CRL_REASON_REMOVE_FROM_CRL #.Win.CRL_REASON_PRIVILEGE_WITHDRAWN #.Win.CRL_REASON_AA_COMPROMISE⍳⊂⍵)⊃'KeyCompromise' 'CaCompromise' 'AffiliationChanged' 'Superseded' 'CessationOfOperation' 'CertificateHold' 'RemoveFromCrl' 'PrivilegeWithdrawn' 'AaCompromise' 'Unspecified'}
     ⍝
              CertOrSerialNumber RevokeFlag CrlTime CrlReason←4↑Parms
              :If 82≠⎕DR CertOrSerialNumber
                  certNr←1↓0⍕CertOrSerialNumber
              :ElseIf 0∊⍴CertOrSerialNumber~⎕D
                  certNr←CertOrSerialNumber
              :Else
                  certNr←##.##.UTO_FMT ##.##.X509.GetCertificateSerialNumber CertOrSerialNumber
              :EndIf
              :If ''≢certNr
                  :Select RevokeFlag
                  :Case ##.##.TRUE
                      gesperrt←'TRUE'
                      sperrDatum←TimeStampToGeneralizedTime CrlTime
                      sperrGrundID←CrlReasonToSperrGrundID CrlReason
                  :Case ##.##.FALSE
                      gesperrt←'FALSE'
                      sperrDatum←'NO_DATE'
                      sperrGrundID←'NOT_REVOKED'
                  :EndSelect
                   ⋄ CertNr←##.##.OCTETSTRING certNr             ⍝ certNr OCTETSTRING,      -- die dezimale Darstellung der Zertifikatsseriennummer als ASCII-String
                   ⋄ Gesperrt←##.##.OCTETSTRING gesperrt         ⍝ gesperrt OCTETSTRING,    -- muß bei Sperrung 'TRUE' sein
                   ⋄ SperrDatum←##.##.OCTETSTRING sperrDatum     ⍝ sperrDatum OCTETSTRING,  -- textuelle GeneralizedTime Darstellung
                   ⋄ SperrGrundID←##.##.OCTETSTRING sperrGrundID ⍝ sperrGrundID OCTETSTRING -- 'KeyCompromise' 'CaCompromise' 'AffiliationChanged' 'CessationOfOperation' 'NOT_REVOKED'
                  SperrNutzdaten←1 ##.##.Code ##.##.SEQUENCE CertNr Gesperrt SperrDatum SperrGrundID
              :Else
                  SperrNutzdaten←''
              :EndIf
            ∇

            ∇ FormattedString←FormatSperrNutzdaten Parms;FmtRevokeFlag;FmtDateTime;CertOrSerialNumber;SerialNumber;RevokeFlag;CrlTime;CrlReason;RevokeFlagText;CrlTimeText;CrlReasonText
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.102-103 4.3.6  LDAP-Komponente
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.143     7.2.2  Kodierung der Modify-/Sperr-Operation
     ⍝
     ⍝ Parms[1] = CertOrSerialNumber X.509 Certificate or AttributeCertificate or CertificateSerialNumber
     ⍝ Parms[2] = RevokeFlag         #.Win.TRUE or #.Win.FALSE
     ⍝ Parms[3] = CrlTime            ⎕TS formatted time
     ⍝ Parms[4] = CrlReason          #.Win.CRL_REASON_KEY_COMPROMISE #.Win.CRL_REASON_CA_COMPROMISE #.Win.CRL_REASON_AFFILIATION_CHANGED or #.Win.CRL_REASON_CESSATION_OF_OPERATION
     ⍝
     ⍝ FormattedString               Printable string about LADP entry
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
              FmtRevokeFlag←{⍵:'JA' ⋄ 'NEIN'}
              FmtDateTime←{0∧.=⍵:'' ⋄ ,'2(ZI2,<.>),ZI4,< >,2(ZI2,<:>),ZI2'⎕FMT 1 6⍴(⌽3↑⍵),3↑3↓⍵}
     ⍝
              CertOrSerialNumber RevokeFlag CrlTime CrlReason←4↑Parms
              :If 82≠⎕DR CertOrSerialNumber
                  SerialNumber←1↓0⍕CertOrSerialNumber
              :ElseIf 0∊⍴CertOrSerialNumber~⎕D
                  SerialNumber←CertOrSerialNumber
              :Else
                  SerialNumber←##.##.UTO_FMT ##.##.X509.GetCertificateSerialNumber CertOrSerialNumber
              :EndIf
              :If ''≢SerialNumber
                  RevokeFlagText←FmtRevokeFlag RevokeFlag
                  CrlTimeText←FmtDateTime CrlTime
                  CrlReasonText←##.GetCRLReasonText CrlReason
                  FormattedString←'Seriennummer: ',SerialNumber,' - Sperren: ',RevokeFlagText,' - Datum: ',CrlTimeText,' - Grund: ',CrlReasonText
              :Else
                  FormattedString←''
              :EndIf
            ∇

            ∇ Retrn←ResolveSperrNutzdaten SperrNutzdaten;GeneralizedTimeToTimeStamp;SperrGrundIDToCrlReason;SerialNumber;RevokeFlag;CrlTime;CrlReason;certNr;gesperrt;sperrDatum;sperrGrundID;CertNr;Gesperrt;SperrDatum;SperrGrundID
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.102-103 4.3.6  LDAP-Komponente
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.143     7.2.2  Kodierung der Modify-/Sperr-Operation
     ⍝
     ⍝ SperrNutzdaten          ASN.1 string for LDAP modify
     ⍝
     ⍝ Retrn[1] = SerialNumber Formatted certificate serial number
     ⍝ Retrn[2] = RevokeFlag   #.Win.TRUE or #.Win.FALSE
     ⍝ Retrn[3] = CrlTime      ⎕TS formatted time
     ⍝ Retrn[4] = CrlReason    #.Win.CRL_REASON_KEY_COMPROMISE #.Win.CRL_REASON_CA_COMPROMISE #.Win.CRL_REASON_AFFILIATION_CHANGED or #.Win.CRL_REASON_CESSATION_OF_OPERATION
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
              GeneralizedTimeToTimeStamp←{↑1↓2 #.ASN1.Code 1(30⍴#.ASN1.UTO_STR)#.ASN1.Code #.ASN1.GENERALIZEDTIME ⍵}
              SperrGrundIDToCrlReason←{('KeyCompromise' 'CaCompromise' 'AffiliationChanged' 'Superseded' 'CessationOfOperation' 'CertificateHold' 'RemoveFromCrl' 'PrivilegeWithdrawn' 'AaCompromise'⍳⊂⍵)⊃#.Win.CRL_REASON_KEY_COMPROMISE #.Win.CRL_REASON_CA_COMPROMISE #.Win.CRL_REASON_AFFILIATION_CHANGED #.Win.CRL_REASON_SUPERSEDED #.Win.CRL_REASON_CESSATION_OF_OPERATION #.Win.CRL_REASON_CERTIFICATE_HOLD #.Win.CRL_REASON_REMOVE_FROM_CRL #.Win.CRL_REASON_PRIVILEGE_WITHDRAWN #.Win.CRL_REASON_AA_COMPROMISE #.Win.CRL_REASON_UNSPECIFIED}
     ⍝
              :If ##.##.SEQUENCE≡↑SperrNutzdaten←3 ##.##.Code SperrNutzdaten
              :AndIf (1+4)=↑⍴SperrNutzdaten
              :AndIf ##.##.OCTETSTRING ##.##.OCTETSTRING ##.##.OCTETSTRING ##.##.OCTETSTRING≡↑¨CertNr Gesperrt SperrDatum SperrGrundID←1↓SperrNutzdaten
                  SerialNumber gesperrt sperrDatum sperrGrundID←2⊃¨CertNr Gesperrt SperrDatum SperrGrundID
                  :If gesperrt sperrDatum sperrGrundID≡'FALSE' 'NO_DATE' 'NOT_REVOKED'
                      RevokeFlag←##.##.FALSE
                      CrlTime←0 0 0 0 0 0 0
                      CrlReason←0
                  :Else
                      RevokeFlag←##.##.TRUE
                      CrlTime←GeneralizedTimeToTimeStamp sperrDatum
                      CrlReason←SperrGrundIDToCrlReason sperrGrundID
                  :EndIf
                  Retrn←SerialNumber RevokeFlag CrlTime CrlReason
              :Else
                  Retrn←'' 0(0 0 0 0 0 0 0)0
              :EndIf
            ∇

            ∇ Signature←SperrNutzdaten SignSperrNutzdaten Parms;Certificate;algorithmOid;Algid;signature
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.102-103 4.3.6  LDAP-Komponente
     ⍝ Secunet OCSP-RESPONDER SPEC OCSP-SPEK.PDF S.143     7.2.2  Kodierung der Modify-/Sperr-Operation
     ⍝ Die Access_Config_List-Informationen entsprechen denen der ASN.1 Definition Signature
     ⍝ Signature ::= SEQUENCE {signatureAlgorithm AlgorithmIdentifier,signature BIT STRING,certs [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL}
     ⍝
     ⍝ Parms[1]       = Certificate
     ⍝ Parms[2]       = Algorithm OID as integer vector
     ⍝ SperrNutzdaten = ASN.1 string to be signed
     ⍝ Signature      = Signature as ASN.1 encoded bit string
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
              Certificate algorithmOid←2↑Parms
              :If 0≠Algid←#.Crypt.OidToAlgid algorithmOid
              :AndIf ×↑⍴signature←SperrNutzdaten #.Crypt.Sign Certificate Algid
                  Signature←1 ##.##.Code ##.##.BITSTRING signature
              :Else
                  Signature←''
              :EndIf
            ∇

            ∇ ValidFlag←SperrNutzdaten VerifySperrNutzdatenSignature Parms;Certificate;Signature;algorithmOid;Algid;signature
     ⍝ Verify the Signature generated by #.ASN1.OCSP.Secunet.SignSperrNutzdaten
     ⍝
     ⍝ Parms[1]       = Certificate
     ⍝ Parms[2]       = Signature as ASN.1 encoded bit string
     ⍝ Parms[3]       = Algorithm OID as integer vector
     ⍝ SperrNutzdaten = ASN.1 string whose signature is to be verified
     ⍝
     ⍝ ValidFlag      = Validity of signature (#.Win.TRUE or #.Win.FALSE)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
              Certificate Signature algorithmOid←3↑Parms
              :If 0≠Algid←#.Crypt.OidToAlgid algorithmOid
              :AndIf ##.##.BITSTRING≡↑Signature←¯2 ##.##.Code Signature
                  signature←2⊃Signature
                  ValidFlag←SperrNutzdaten #.Crypt.VerifySignature Certificate signature Algid
              :Else
                  ValidFlag←0
              :EndIf
            ∇

        :EndNamespace
    :EndNamespace
    :Namespace PKCS1
        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        GenerateEMSASignPadding←{⍺←1024 ⋄ ⍵{8>⍵:'' ⋄ (1 1 ⍵ 1/#.Win.TxtInt 0 1 ¯1 0),⍺}(⌈⍺÷8)-3+↑⍴⍵}

          GetKeyIdentifierFromKey←{
              PublicKey←##.BITSTRING(KeyEncode 2↑KeyDecode ⍵)
              pkcs_1_rsaEncryption←1 2 840 113549 1 1 1
              Algorithm←##.SEQUENCE(##.OID pkcs_1_rsaEncryption)##.NULLTAG
              PublicKeyInfo←1 ##.Code ##.SEQUENCE Algorithm PublicKey
              #.Win.TxtHex'4',¯15↑#.Win.HexTxt PublicKeyInfo #.Crypt.Hash #.Win.CALG_SHA1}

        ∇ Bitlen←{Precision}GetKeyLength Sequence;UStrInt;Rnd;RSAKey;Modulus
     ⍝ Return the key length in bits from an RSAKey, a PKCS#1 encoded key or from a certificate's public RSA-key
     ⍝
     ⍝ Sequence  = RSAKey or PKCS#1  structure or certificate structure
     ⍝ Precision = 8(def) if a byte precise, 1 if a bit precise result is desired
     ⍝ Bitlen    = Leading length of the modulus in bits
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
          ##.Init
          UStrInt←{#.Win.TxtInt{(¯1 ¯2⌊.+(×⍵)⍳1 ¯1)↓⍵}0,#.Win.IntTxt{82=⎕DR ⍵:⍵ ⋄ #.Win.TxtInt 256 256 256 256 256 256⊤⍵}⍵}
          Rnd←{⍺←1 ⋄ ⍺×⌊0.5+⍵÷⍺}
          :If 2=≡Sequence
          :AndIf (↑⍴Sequence)∊2 8
              Modulus←↑Sequence
          :ElseIf 2≤↑⍴RSAKey←#.ASN1.PKCS1.KeyDecode Sequence
              Modulus←↑RSAKey
          :Else
              Modulus←''
          :EndIf
          :If 0=⎕NC'Precision'
              Precision←8
          :EndIf
          Bitlen←Precision Rnd+/∨\0.125 #.Win.IntTxt UStrInt Modulus
        ∇

        ∇ RSAKey←KeyBlobDecode KeyBlob;DecodedKeyBlob;Type;Version;reserved;aiKeyAlg;magic;bitlen;publicExponent;modulus;prime1;prime2;exponent1;exponent2;coefficient;privateExponent;RCode
     ⍝ Extracts 2 or 8 elements of the following parameters out of a CryptoAPI KeyBlob
     ⍝
     ⍝ RSAKey[1] = modulus
     ⍝ RSAKey[2] = publicExponent
     ⍝ RSAKey[3] = privateExponent
     ⍝ RSAKey[4] = prime1
     ⍝ RSAKey[5] = prime2
     ⍝ RSAKey[6] = exponent1
     ⍝ RSAKey[7] = exponent2
     ⍝ RSAKey[8] = coefficient
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 1999
          RCode←#.RCode ⋄ DecodedKeyBlob←#.Win.Crypt.KeyBlob.Decode KeyBlob ⋄ :If #.Win.ERROR_SUCCESS≠RCode ⋄ #.RCode←RCode ⋄ :EndIf
          :Select ↑DecodedKeyBlob
          :Case #.Win.PUBLICKEYBLOB
              Type Version reserved aiKeyAlg magic bitlen publicExponent modulus←DecodedKeyBlob
              :If magic≡'RSA1'
                  RSAKey←modulus publicExponent
              :Else
                  RSAKey←⊂''
                  :If #.RCode=#.Win.ERROR_SUCCESS
                      #.RCode←#.Win.NTE_BAD_TYPE
                  :EndIf
              :EndIf
          :Case #.Win.PRIVATEKEYBLOB
              Type Version reserved aiKeyAlg magic bitlen publicExponent modulus prime1 prime2 exponent1 exponent2 coefficient privateExponent←DecodedKeyBlob
              :If magic≡'RSA2'
                  RSAKey←modulus publicExponent privateExponent prime1 prime2 exponent1 exponent2 coefficient
              :Else
                  RSAKey←⊂''
                  :If #.RCode=#.Win.ERROR_SUCCESS
                      #.RCode←#.Win.NTE_BAD_TYPE
                  :EndIf
              :EndIf
          :Else
              RSAKey←⊂''
              :If #.RCode=#.Win.ERROR_SUCCESS
                  #.RCode←#.Win.NTE_BAD_TYPE
              :EndIf
          :EndSelect
        ∇

        ∇ KeyBlob←{aiKeyAlg}KeyBlobEncode RSAKey;Type;Version;reserved;magic;bitlen;publicExponent;modulus;prime1;prime2;exponent1;exponent2;coefficient;privateExponent;RCode
     ⍝ Builds a CryptoAPI KeyBlob out of the decoded PKCS-1 key
     ⍝
     ⍝ To build a Private KeyBlob:
     ⍝ RSAKey[1] = modulus
     ⍝ RSAKey[2] = publicExponent
     ⍝ RSAKey[3] = privateExponent
     ⍝ RSAKey[4] = prime1
     ⍝ RSAKey[5] = prime2
     ⍝ RSAKey[6] = exponent1
     ⍝ RSAKey[7] = exponent2
     ⍝ RSAKey[8] = coefficient
     ⍝
     ⍝ To build a Public KeyBlob:
     ⍝ RSAKey[1] = modulus
     ⍝ RSAKey[2] = publicExponent
     ⍝
     ⍝ aiKeyAlg  = def. #.Win.CALG_RSA_SIGN or #.Win.CALG_RSA_KEYX
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 1999
          :If 0=⎕NC'aiKeyAlg'
              aiKeyAlg←#.Win.CALG_RSA_SIGN
          :EndIf
          :If aiKeyAlg∊#.Win.CALG_RSA_SIGN #.Win.CALG_RSA_KEYX
              Version←2
              reserved←0
              bitlen←0
              :Select ↑⍴RSAKey
              :Case 2
                  modulus publicExponent←RSAKey
                  Type←#.Win.PUBLICKEYBLOB
                  magic←'RSA1'
                  RCode←#.RCode ⋄ KeyBlob←#.Win.Crypt.KeyBlob.Encode Type Version reserved aiKeyAlg magic bitlen publicExponent modulus ⋄ :If #.Win.ERROR_SUCCESS≠RCode ⋄ #.RCode←RCode ⋄ :EndIf
              :Case 8
                  modulus publicExponent privateExponent prime1 prime2 exponent1 exponent2 coefficient←RSAKey
                  Type←#.Win.PRIVATEKEYBLOB
                  magic←'RSA2'
                  RCode←#.RCode ⋄ KeyBlob←#.Win.Crypt.KeyBlob.Encode Type Version reserved aiKeyAlg magic bitlen publicExponent modulus prime1 prime2 exponent1 exponent2 coefficient privateExponent ⋄ :If #.Win.ERROR_SUCCESS≠RCode ⋄ #.RCode←RCode ⋄ :EndIf
              :Else
                  KeyBlob←''
                  :If #.RCode=#.Win.ERROR_SUCCESS
                      #.RCode←#.Win.NTE_BAD_TYPE
                  :EndIf
              :EndSelect
          :Else
              KeyBlob←''
              :If #.RCode=#.Win.ERROR_SUCCESS
                  #.RCode←#.Win.NTE_BAD_TYPE
              :EndIf
          :EndIf
        ∇

        ∇ RSAKey←{UtoInt}KeyDecode Sequence;Index;RCode;TbsCertificate;SubjectPublicKeyInfo;SubjectAlgorithm;SubjectPublicKey;pkcs_1_rsaEncryption
     ⍝ Return 2 or all 8 elements of the parameters from a
     ⍝ PKCS#1 encoded key or from a certificate's public RSA-key
     ⍝
     ⍝ Sequence  = PKCS#1  structure or certificate structure
     ⍝ UtoInt    = Integer Tag Options, combination of #.ASN1.UTO_STR(def) #.ASN1.UTO_FMT or #.ASN1.UTO_HEX+#.ASN1.UTO_I32 #.ASN1.UTO_I48(def) or #.ASN1.UTO_I53
     ⍝
     ⍝ RSAKey[1] = modulus
     ⍝ RSAKey[2] = publicExponent
     ⍝ RSAKey[3] = privateExponent
     ⍝ RSAKey[4] = prime1
     ⍝ RSAKey[5] = prime2
     ⍝ RSAKey[6] = exponent1
     ⍝ RSAKey[7] = exponent2
     ⍝ RSAKey[8] = coefficient
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
          ##.Init
          RCode←#.RCode
          :If ×⎕NC'UtoInt'
              Sequence←7(⍬ UtoInt)##.Code Sequence
          :Else
              Sequence←7 ##.Code Sequence
          :EndIf
          :If #.Win.ERROR_SUCCESS≠RCode ⋄ #.RCode←RCode ⋄ :EndIf
          :If ##.SEQUENCE≡↑Sequence
              :Select ↑⍴Sequence←1↓Sequence
              :Case 2
              ⍝ RSAPublicKey:=Sequence Of:
              ⍝ modulus         n=p×q
              ⍝ publicExponent  e
                  :If 2∧.=↑∘⍴¨Sequence
                  :AndIf ∧/##.INTEGER∘≡¨↑¨Sequence
                      RSAKey←(1 2)(2 2)⊃¨⊂Sequence
                  :Else
                      RSAKey←⊂''
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                  :EndIf
              :Case 3
                  pkcs_1_rsaEncryption←1 2 840 113549 1 1 1
                  :If ##.SEQUENCE≡↑TbsCertificate←↑Sequence
                  :AndIf 5=↑⍴TbsCertificate←(##.SEQUENCE∘≡¨↑¨TbsCertificate)/TbsCertificate←1↓TbsCertificate
                  :AndIf ##.SEQUENCE≡↑SubjectPublicKeyInfo←5⊃TbsCertificate
                  :AndIf ##.SEQUENCE ##.BITSTRING≡↑¨SubjectAlgorithm SubjectPublicKey←1↓SubjectPublicKeyInfo
                  :AndIf 2≤↑⍴SubjectAlgorithm
                  :AndIf ##.OID≡↑SubjectAlgorithm←2⊃SubjectAlgorithm
                  :AndIf pkcs_1_rsaEncryption≡2⊃SubjectAlgorithm
                  :AndIf ##.BITSTRING≡↑SubjectPublicKey
                  :AndIf ##.SEQUENCE≡↑SubjectPublicKey←2⊃SubjectPublicKey
                  :AndIf 2=↑⍴Sequence←1↓SubjectPublicKey
              ⍝ RSAPublicKey:=Sequence Of:
              ⍝ modulus         n=p×q
              ⍝ publicExponent  e
                  :AndIf 2∧.=↑∘⍴¨Sequence
                  :AndIf ∧/##.INTEGER∘≡¨↑¨Sequence
                      RSAKey←(1 2)(2 2)⊃¨⊂Sequence
                  :Else
                      RSAKey←⊂''
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                  :EndIf
              :Case 9
              ⍝ RSAPrivateKey:=Sequence Of:
              ⍝ version         (shall be 0)
              ⍝ modulus         n=p×q
              ⍝ publicExponent  e
              ⍝ privateExponent d
              ⍝ prime1          prime factor p of n
              ⍝ prime2          prime factor q of n
              ⍝ exponent1       d mod (p-1)
              ⍝ exponent2       d mod (q-1)
              ⍝ coefficient     (inverse of q) mod p (Chinese Remainder Theorem)
                  :If 2∧.=↑∘⍴¨Sequence
                  :AndIf ∧/##.INTEGER∘≡¨↑¨Sequence
                  :AndIf ∊∘0 '0' '00'(,'0')(↑⎕AV)(1↑⎕AV)⊂1 2⊃Sequence
                      RSAKey←(2 2)(3 2)(4 2)(5 2)(6 2)(7 2)(8 2)(9 2)⊃¨⊂Sequence
                  :Else
                      RSAKey←⊂''
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                  :EndIf
              :Else
                  RSAKey←⊂''
                  :If #.RCode=#.Win.ERROR_SUCCESS
                      #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                  :EndIf
              :EndSelect
          :Else
              RSAKey←⊂''
              :If #.RCode=#.Win.ERROR_SUCCESS
                  #.RCode←#.Win.CRYPT_E_BAD_ENCODE
              :EndIf
          :EndIf
        ∇

        ∇ Sequence←KeyEncode RSAKey;UStrInt;version;modulus;publicExponent;privateExponent;prime1;prime2;exponent1;exponent2;coefficient;RCode
     ⍝ Convert 2 or 8 elements of the following parameters into a PKCS-1 encoded key:
     ⍝
     ⍝ RSAKey[1] = modulus
     ⍝ RSAKey[2] = publicExponent
     ⍝ RSAKey[3] = privateExponent
     ⍝ RSAKey[4] = prime1
     ⍝ RSAKey[5] = prime2
     ⍝ RSAKey[6] = exponent1
     ⍝ RSAKey[7] = exponent2
     ⍝ RSAKey[8] = coefficient
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 1999
          ##.Init
          UStrInt←{#.Win.TxtInt(¯1 ¯2⌊.+(×⍵)⍳1 ¯1)↓⍵}∘{82=⎕DR ⍵:0,#.Win.IntTxt ⍵ ⋄ 0,#.Win.IntTxt #.Win.TxtInt 256 256 256 256 256 256⊤⍵}
          :Select ↑⍴RSAKey←UStrInt¨RSAKey
          :Case 8
              modulus publicExponent privateExponent prime1 prime2 exponent1 exponent2 coefficient←RSAKey
               ⋄ version←##.INTEGER 0
               ⋄ modulus←##.INTEGER modulus
               ⋄ publicExponent←##.INTEGER publicExponent
               ⋄ privateExponent←##.INTEGER privateExponent
               ⋄ prime1←##.INTEGER prime1
               ⋄ prime2←##.INTEGER prime2
               ⋄ exponent1←##.INTEGER exponent1
               ⋄ exponent2←##.INTEGER exponent2
               ⋄ coefficient←##.INTEGER coefficient
              RCode←#.RCode ⋄ Sequence←1 ##.Code ##.SEQUENCE version modulus publicExponent privateExponent prime1 prime2 exponent1 exponent2 coefficient ⋄ :If #.Win.ERROR_SUCCESS≠RCode ⋄ #.RCode←RCode ⋄ :EndIf
          :Case 2
              modulus publicExponent←RSAKey
               ⋄ modulus←##.INTEGER modulus
               ⋄ publicExponent←##.INTEGER publicExponent
              RCode←#.RCode ⋄ Sequence←1 ##.Code ##.SEQUENCE modulus publicExponent ⋄ :If #.Win.ERROR_SUCCESS≠RCode ⋄ #.RCode←RCode ⋄ :EndIf
          :Else
              Sequence←''
              :If #.RCode=#.Win.ERROR_SUCCESS
                  #.RCode←#.Win.CRYPT_E_BAD_ENCODE
              :EndIf
          :EndSelect
        ∇

        ∇ RSAKey←KeyGenerate Parms;Bitlen;ExponentOne;Algid;KeyBlob;Type;Version;reserved;aiKeyAlg;magic;bitlen;publicExponent;modulus;prime1;prime2;exponent1;exponent2;coefficient;privateExponent
     ⍝ Generates a decoded PKCS-1 RSA keypair
     ⍝
     ⍝ Parms[1]  = Bitlen
     ⍝ Parms[2]  = ExponentOne (def. #.Win.FALSE for generate true cryptographic key or #.Win.TRUE for a dummy key doing a null crypt)
     ⍝
     ⍝ RSAKey[1] = modulus         n=p×q
     ⍝ RSAKey[2] = publicExponent  e
     ⍝ RSAKey[3] = privateExponent d
     ⍝ RSAKey[4] = prime1          prime factor p of n
     ⍝ RSAKey[5] = prime2          prime factor q of n
     ⍝ RSAKey[6] = exponent1       d mod (p-1)
     ⍝ RSAKey[7] = exponent2       d mod (q-1)
     ⍝ RSAKey[8] = coefficient     (inverse of q) mod p (Chinese Remainder Theorem)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 1999
          #.Win.Init
          Bitlen ExponentOne←2↑Parms
          Algid←#.Win.CALG_RSA_SIGN
          :If ×↑⍴KeyBlob←#.Win.Crypt.KeyBlob.Generate Algid Bitlen ExponentOne
          :AndIf 14=↑⍴Type Version reserved aiKeyAlg magic bitlen publicExponent modulus prime1 prime2 exponent1 exponent2 coefficient privateExponent←#.Win.Crypt.KeyBlob.Decode KeyBlob
              RSAKey←modulus publicExponent privateExponent prime1 prime2 exponent1 exponent2 coefficient
          :Else
              RSAKey←⊂''
          :EndIf
        ∇

        RemoveEMSASignPadding←{⍵{0=⍵:'' ⋄ ⍵↓⍺}{⍵{⍵{(9<⍵)×⍺+⍵}{⍵{⍵×((⍵-1)↑2)≡1+(⍵-1)↑⍺}⍵⍳0}⍵↓⍺}+/∧\0=⍵}#.Win.IntTxt ⍵}

    :EndNamespace
    :Namespace PKCS12
⍝ === VARIABLES ===

        _←⍬
        _,←(⎕ucs 73 160 201 3),'c!'']⍀⌊<_',(⎕ucs 9474),'D⍱→',(⎕ucs 8 35 8216 241 9496 98 165),'_⍉⍎ø',(⎕ucs 13),'⍒óûÚI⍬;⍞ÄzÙeN7',(⎕ucs 160 10 219 88 9508),'AÜ2⊃Õ1þ⍞⍳↓',(⎕ucs 9508),'iXï',(⎕ucs 9524)
        _,←'^.Où≥≠y¯à⌈zÀÊf⍷',(⎕ucs 9484),'⍎!ò',(⎕ucs 9488 9496),'H8% ',(⎕ucs 12),'þ∪s⌶Õ',(⎕ucs 9474),'Ö/⌶Â!⌈',(⎕ucs 1 9049 9488),'|○¯∨eÉ]ûF9',(⎕ucs 9484),'QUØ',(⎕ucs 6),'¨∆l∊M!Ä-§⍒ú',(⎕ucs 9474),'A∧û''í:{ú'
        _,←(⎕ucs 253 64 3 8),'⊖Ò>ï1ÂGZÖ',(⎕ucs 183 251 118 3 240 8216),'⊤⍪⍋d⌹M7⍟TÀíY§',(⎕ucs 9488),'Pk⍳6×⍋''↑¢U§∪£Ü∣∘¢∣åM⊂g⍉S',(⎕ucs 38),'3£⍴ÕÎ-',(⎕ucs 9474),'''~A¯',(⎕ucs 13),'y⍬⌊þ',(⎕ucs 30),' ),Ñ⍟td'
        _,←(⎕ucs 27),'dP∘',(⎕ucs 31 9474 50 9054 9474),'Î⍬≥⍙⌈4b⍞FhÈ≥ÔQ',(⎕ucs 7),'LÚøA¨⍪⌊≥⍨öþî~îhUÈ',(⎕ucs 38),'Wê⌶',(⎕ucs 8),'S⍱→)þd⍳○',(⎕ucs 30),'-,wæv:|äe}?ÐwÅ}Â',(⎕ucs 8217),'↓↑çñ'
        _,←(⎕ucs 9524 619 221 9496 8744 88 9488),'/⍋⊥/',(⎕ucs 253 619),'îqF',(⎕ucs 38),'Éaq',(⎕ucs 5 9484 233 9033 38),'r^gK8B⍕16',(⎕ucs 8867 9488),'3Ò?',(⎕ucs 8216 167 12),'ïF∆$"]ÓÃ≥âd⌽',(⎕ucs 9508)
        _,←'ñõ¶pB2)0L',(⎕ucs 8),'!¶0<',(⎕ucs 7 30 5),'Ñ/t⍒∧C↑z+Eyù',(⎕ucs 8217),'\ßó',(⎕ucs 253),'E∆KÅÐq~⍣⍒e⊤⍲á)⊤',(⎕ucs 127),'∪⌽≤⍬⍞⍣%',(⎕ucs 9532),'ÕlÇ£⍋ÑEãþ',(⎕ucs 8364 113 9474),'⍳õ≤',(⎕ucs 31),'ï⌷ïÏ0'
        _,←(⎕ucs 9472 80 38),'ÆÄ=(',(⎕ucs 127 9484 81 210 13),'B-Ãl≡⎕⍀',(⎕ucs 164),'¢Tm3M[íÁc×⌷qlxâ∩u⍋ fEYF',(⎕ucs 8 9045 167 8364),'Û1Ê^óQ0Rp⌹⊖',(⎕ucs 9524 8593 52 8216),'>⍝m⍴⍳;3MB£⊖⍞'
        _,←(⎕ucs 9532 8217 9484 162 208 9488),'¯~→',(⎕ucs 6),';1lá÷',(⎕ucs 9508),'XØë^',(⎕ucs 164),'∧òT_⍀⍳Ü/T8Ó6+∊$)→Û',(⎕ucs 9492),'l⍎úLÉ',(⎕ucs 9508),'bÅ_E.ã å≢',(⎕ucs 9492),'Fï⍪⍣[',(⎕ucs 10),'¢A":Ý¢34'
        _,←(⎕ucs 3),'é≡+',(⎕ucs 9474),' ÀRmVbkÊ⍺ö',(⎕ucs 7 47 27),'+¯¨',(⎕ucs 9500),'iÂoÏq⊃+üñÉ⌹ñ≠ò',(⎕ucs 9508 84 212 0 9015 201)
        C←_

        D←''

        KEY←'_MÌ;Z§eÖ∣⊥''þ⍺⊤Ï⍀'

        PASSWORD←'password'

        _←⍬
        _,←'×"~Ä',(⎕ucs 9),'ø2ç\!õ×Ë○%bx',(⎕ucs 9),'ôJ!"',(⎕ucs 31),'2⍴Ì⍕.a8∆WtÅæ⍱ü',(⎕ucs 9474),'¡⍵M∊',(⎕ucs 6 54 2),'+⌈}⍋R⍳r8''(@cl/⍵Ó',(⎕ucs 27),'IÄT⊂R',(⎕ucs 8217),'()2ð∨ë',(⎕ucs 1 160 9067 220 9508 51 10)
        _,←'∇bW\6ÒLæ⍞¯[',(⎕ucs 9472 194 32 9488),'Jpx⍎',(⎕ucs 9472 8217 30),'⌶⌊¡∧s⍕',(⎕ucs 9484),'gçwíîÝf⎕',(⎕ucs 30),'∆Àa⍨wVqêßy:£5⍎r⋄Áé0⌿⍱U',(⎕ucs 1),'aã∩Ë',(⎕ucs 183),'7Ê¡⌿⊥Ì⌷⍀⍉',(⎕ucs 9484 253 31),':⍞¿'
        _,←(⎕ucs 164),'≡⍎¢',(⎕ucs 9508 9),'ÊD∪7⊃Á≡⍫⍒Æ⊥⊖4',(⎕ucs 9492),'DfATqXÑø⍬',(⎕ucs 0),'Õ⌈≤Öe:ÒÌê⊥à(Sõí',(⎕ucs 9472),'Ê0ñ',(⎕ucs 27 70 213 6),'JA¶×Ï''ÛÁ¡⍵è⍷',(⎕ucs 164 8739 165),'⌊(t',(⎕ucs 4)
        _,←'#∧xë%⍲⍷ÍG''⍴ø∊I',(⎕ucs 9516),'£,⌽k1⍷>!⊤a]⍪',(⎕ucs 253),'⌷4⍱z∩⊂ êNù⍕"ûþìN ⍒',(⎕ucs 9474 237 13),'/aì>4⊃ô¡"ó⌿¶⊥ó ⍪',(⎕ucs 9524 209 4),'¯≠⍞ÆÖôì!⍒÷ æm£',(⎕ucs 8364 9500),'⍺é⌶5ö',(⎕ucs 9484),'ÙÇ≢⌷⍉⍬x]'
        _,←(⎕ucs 10 9017 9472),'tþØ ÃÚGt9⍋⎕tâ"Eê→æqg⊖Õ≢ê]u⍕⍵',(⎕ucs 10),'àzØ⍙%',(⎕ucs 8 9488),'⍙[⍷,Õ',(⎕ucs 253),'⍟{w⌹^ú',(⎕ucs 9524 8216),'ð≤ã↑≥⍵',(⎕ucs 3),'⍨ÍC∆∊⍫V⍝',(⎕ucs 164 8805 208 0 8)
        _,←'∊U⍴KÍØÎL⍣¶T→∣X⌹y⍳∩ð+',(⎕ucs 160),'á9q+UH⍬¨[I§áà/',(⎕ucs 38),'k¶3⍎ú£3:→≥÷',(⎕ucs 8 162 87 27),'Çí@ê⍱tR',(⎕ucs 38),'⌽%5+k↓zQÎ',(⎕ucs 9488),'mÏQ"!⊖⍞ðÖ⌶⌷¢⍱Ö$',(⎕ucs 2 4),'eõj∇w}r',(⎕ucs 1 40 30)
        _,←'üpêUqpG⍙*vV',(⎕ucs 9496),'ç⍷Ü',(⎕ucs 30),'ø⋄Ç*ðD9ßÃùW1⍨⍱> Ê',(⎕ucs 9488),'Ê80§£í$v⍫≡⊃Ø',(⎕ucs 8),'1S:Feà',(⎕ucs 9524),'éãò↓',(⎕ucs 9500 221 8592 13 30),'cmg',(⎕ucs 13 225 93 253 9500),'ðIÎly8⊤'
        _,←(⎕ucs 8),'ÊøÔàx→ðE\',(⎕ucs 160),'Ê⋄Ã7+∊%↑⎕ú^⍕≠',(⎕ucs 8364),'N⍪þPèMÜûë',(⎕ucs 9492 8711 78)
        S←_

        _←⍬
        _,←(⎕ucs 109 59 9),'äÊT!⍣m;',(⎕ucs 9),'äÊT!⍣m;',(⎕ucs 9),'äÊT!⍣'
        SessionKey←_

        _←⍬
        _,←'×"~Ä',(⎕ucs 9),'ø2ç\!õ×Ë○%bx',(⎕ucs 9),'ôJ!"',(⎕ucs 31),'2⍴Ì⍕.a8∆WtÅæ⍱ü',(⎕ucs 9474),'¡⍵M∊',(⎕ucs 6 54 2),'+⌈}⍋R⍳r8''(@cl/⍵Ó',(⎕ucs 27),'IÄT⊂R',(⎕ucs 8217),'()2ð∨ë',(⎕ucs 1 160 9067 220 9508 51 10)
        _,←'∇bW\6ÒLæ⍞¯[',(⎕ucs 9472 194 32 9488),'Jpx⍎',(⎕ucs 9472 8217 30),'⌶⌊¡∧s⍕',(⎕ucs 9484),'gçwíîÝf⎕',(⎕ucs 30),'∆Àa⍨wVqêßy:£5⍎r⋄Áé0⌿⍱U',(⎕ucs 1),'aã∩Ë',(⎕ucs 183),'7Ê¡⌿⊥Ì⌷⍀⍉',(⎕ucs 9484 253 31),':⍞¿'
        _,←(⎕ucs 164),'≡⍎¢',(⎕ucs 9508 9),'ÊD∪7⊃Á≡⍫⍒Æ⊥⊖4',(⎕ucs 9492),'DfATqXÑø⍬',(⎕ucs 0),'Õ⌈≤Öe:ÒÌê⊥à(Sõí',(⎕ucs 9472),'Ê0ñ',(⎕ucs 27 70 213 6),'JA¶×Ï''ÛÁ¡⍵è⍷',(⎕ucs 164 8739 165),'⌊(t',(⎕ucs 4)
        _,←'#∧xë%⍲⍷ÍG''⍴ø∊I',(⎕ucs 9516),'£,⌽k1⍷>!⊤a]⍪',(⎕ucs 253),'⌷4⍱z∩⊂ êNù⍕"ûþìN ⍒',(⎕ucs 9474 237 13),'/aì>4⊃ô¡"ó⌿¶⊥ó ⍪',(⎕ucs 9524 209 4),'¯≠⍞ÆÖôì!⍒÷ æm£',(⎕ucs 8364 9500),'⍺é⌶5ö',(⎕ucs 9484),'ÙÇ≢⌷⍉⍬x]'
        _,←(⎕ucs 10 9017 9472),'tþØ ÃÚGt9⍋⎕tâ"Eê→æqg⊖Õ≢ê]u⍕⍵',(⎕ucs 10),'àzØ⍙%',(⎕ucs 8 9488),'⍙[⍷,Õ',(⎕ucs 253),'⍟{w⌹^ú',(⎕ucs 9524 8216),'ð≤ã↑≥⍵',(⎕ucs 3),'⍨ÍC∆∊⍫V⍝',(⎕ucs 164 8805 208 0 8)
        _,←'∊U⍴KÍØÎL⍣¶T→∣X⌹y⍳∩ð+',(⎕ucs 160),'á9q+UH⍬¨[I§áà/',(⎕ucs 38),'k¶3⍎ú£3:→≥÷',(⎕ucs 8 162 87 27),'Çí@ê⍱tR',(⎕ucs 38),'⌽%5+k↓zQÎ',(⎕ucs 9488),'mÏQ"!⊖⍞ðÖ⌶⌷¢⍱Ö$',(⎕ucs 2 4),'eõj∇w}r',(⎕ucs 1 40 30)
        _,←'üpêUqpG⍙*vV',(⎕ucs 9496),'ç⍷Ü',(⎕ucs 30),'ø⋄Ç*ðD9ßÃùW1⍨⍱> Ê',(⎕ucs 9488),'Ê80§£í$v⍫≡⊃Ø',(⎕ucs 8),'1S:Feà',(⎕ucs 9524),'éãò↓',(⎕ucs 9500 221 8592 13 30),'cmg',(⎕ucs 13 225 93 253 9500),'ðIÎly8⊤'
        _,←(⎕ucs 8),'ÊøÔàx→ðE\',(⎕ucs 160),'Ê⋄Ã7+∊%↑⎕ú^⍕≠',(⎕ucs 8364),'N⍪þPèMÜûë',(⎕ucs 9492 8711 78)
        Y←_

        ⎕ex '_'

⍝ === End of variables definition ===

        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        ∇ plainText←cipherText DecryptPbe(pbeOid password salt rounds);ToUnicode;FmtOid;ID_KEY;ID_IV;ID_MAC;AlgidSession;CipherMode;keyLength;derivedKey;derivedIV
          ToUnicode←{∊(↑⎕AV),¨⍵,(×⍴⍵)⍴⎕AV}
          FmtOid←{⍬≢0⍴⍵:'' ⋄ ⍵{⍵≤↑⍴#.ASN1.OidTab:↑#.ASN1.OidTab[⍵;2] ⋄ '0123456789.'['0123456789'⍳⍕⍺]}#.ASN1.OidTab[;1]⍳⊂⍵}
          ID_KEY ID_IV ID_MAC←⍳3       ⍝ PKCS#12v1.0 p.15: B.3 More on the ID byte
         
          password←ToUnicode password
         
          :Select FmtOid pbeOid
          :Case 'pkcs-5-pbeWithMD2AndDES-CBC'
              AlgidSession←#.Win.CALG_DES ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←64÷8
          :Case 'pkcs-5-pbeWithMD2AndRC2-CBC'
              AlgidSession←#.Win.CALG_RC2 ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←128÷8
          :Case 'pkcs-5-pbeWithMD5AndDES-CBC'
              AlgidSession←#.Win.CALG_DES ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←64÷8
          :Case 'pkcs-5-pbeWithMD5AndRC2-CBC'
              AlgidSession←#.Win.CALG_RC2 ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←128÷8
          :Case 'pkcs-5-pbeWithSHA1AndDES-CBC'
              AlgidSession←#.Win.CALG_DES ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←64÷8
          :Case 'pkcs-5-pbeWithSHA1AndRC2-CBC'
              AlgidSession←#.Win.CALG_RC2 ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←128÷8
          :Case 'pkcs-12-pbeWithSHAAnd128BitRC4'
              AlgidSession←#.Win.CALG_RC4 ⋄ CipherMode←0 ⋄ keyLength←128÷8
          :Case 'pkcs-12-pbeWithSHAAnd40BitRC4'
              AlgidSession←#.Win.CALG_RC4 ⋄ CipherMode←0 ⋄ keyLength←40÷8
          :Case 'pkcs-12-pbeWithSHAAnd3-KeyTripleDES-CBC'
              AlgidSession←#.Win.CALG_3DES ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←192÷8
          :Case 'pkcs-12-pbeWithSHAAnd2-KeyTripleDES-CBC'
              AlgidSession←#.Win.CALG_3DES2 ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←128÷8
          :Case 'pkcs-12-pbeWithSHAAnd128BitRC2-CBC'
              AlgidSession←#.Win.CALG_RC2 ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←128÷8
          :Case 'pkcs-12-pbewithSHAAnd40BitRC2-CBC'
              AlgidSession←#.Win.CALG_RC2 ⋄ CipherMode←#.Win.CRYPT_MODE_CBC ⋄ keyLength←40÷8
          :EndSelect
         
          derivedKey←DeriveKey(keyLength ID_KEY password salt rounds)
          ⎕←'derivedKey     ',#.Win.HexTxt derivedKey
          :If 0≠CipherMode
              derivedIV←DeriveKey(8 ID_IV password salt rounds)
          :Else
              derivedIV←''
          :EndIf
          ⎕←'derivedIV      ',#.Win.HexTxt derivedIV
         
          plainText←cipherText #.Crypt.SessionkeyDecrypt derivedKey derivedIV salt AlgidSession CipherMode
        ∇

        ∇ plainText←cipherText DecryptPbeNew(pbeOid password salt rounds);FmtOid;PKMode;IVMode;AlgIdHash;AlgIdCrypt;keyLength;derivedKey;derivedIV
          FmtOid←{⍬≢0⍴⍵:'' ⋄ ⍵{⍵≤↑⍴#.ASN1.OidTab:↑#.ASN1.OidTab[⍵;2] ⋄ '0123456789.'['0123456789'⍳⍕⍺]}#.ASN1.OidTab[;1]⍳⊂⍵}
         
          :Select FmtOid pbeOid
          :Case 'pkcs-5-pbeWithMD2AndDES-CBC'
              PKMode←5
              IVMode←1
              AlgIdHash←#.Crypt.HASH_MD2
              AlgIdCrypt←#.Crypt.CIPH_DES_CBC
              keyLength←8
          :Case 'pkcs-5-pbeWithMD2AndRC2-CBC'
              PKMode←5
              IVMode←1
              AlgIdHash←#.Crypt.HASH_MD2
              AlgIdCrypt←#.Crypt.CIPH_RC2_CBC
              keyLength←16
          :Case 'pkcs-5-pbeWithMD5AndDES-CBC'
              PKMode←5
              IVMode←1
              AlgIdHash←#.Crypt.HASH_MD5
              AlgIdCrypt←#.Crypt.CIPH_DES_CBC
              keyLength←8
          :Case 'pkcs-5-pbeWithMD5AndRC2-CBC'
              PKMode←5
              IVMode←1
              AlgIdHash←#.Crypt.HASH_MD5
              AlgIdCrypt←#.Crypt.CIPH_RC2_CBC
              keyLength←16
          :Case 'pkcs-5-pbeWithSHA1AndDES-CBC'
              PKMode←5
              IVMode←1
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_DES_CBC
              keyLength←8
          :Case 'pkcs-5-pbeWithSHA1AndRC2-CBC'
              PKMode←5
              IVMode←1
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_RC2_CBC
              keyLength←16
          :Case 'pkcs-12-pbeWithSHAAnd128BitRC4'
              PKMode←12
              IVMode←0
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_RC4
              keyLength←16
          :Case 'pkcs-12-pbeWithSHAAnd40BitRC4'
              PKMode←12
              IVMode←0
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_RC4
              keyLength←5
          :Case 'pkcs-12-pbeWithSHAAnd3-KeyTripleDES-CBC'
              PKMode←12
              IVMode←1
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_DES_CBC
              keyLength←24
          :Case 'pkcs-12-pbeWithSHAAnd2-KeyTripleDES-CBC'
              PKMode←12
              IVMode←1
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_DES_CBC
              keyLength←16
          :Case 'pkcs-12-pbeWithSHAAnd128BitRC2-CBC'
              PKMode←12
              IVMode←1
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_RC2_CBC
              keyLength←16
          :Case 'pkcs-12-pbewithSHAAnd40BitRC2-CBC'
              PKMode←12
              IVMode←1
              AlgIdHash←#.Crypt.HASH_SHA1
              AlgIdCrypt←#.Crypt.CIPH_RC2_CBC
              keyLength←5
          :EndSelect
         
          :Select PKMode
          :Case 5
              derivedKey←AlgIdHash #.Crypt.PKCS5.PBKDF1(password salt rounds keyLength)
              :If 0≠IVMode
                  derivedIV←AlgIdHash #.Crypt.PKCS5.PBKDF1(password salt rounds keyLength)
              :Else
                  derivedIV←''
              :EndIf
          :Case 12
              derivedKey←AlgIdHash #.Crypt.PKCS12.PBKDF(password salt rounds keyLength #.Crypt.PKCS12.ID_KEY)
              :If 0≠IVMode
                  derivedIV←AlgIdHash #.Crypt.PKCS12.PBKDF(password salt rounds 8 #.Crypt.PKCS12.ID_IV)
              :Else
                  derivedIV←''
              :EndIf
          :EndSelect
         
          ⎕←'derivedKey     ',#.Win.HexTxt derivedKey
          ⎕←'derivedIV      ',#.Win.HexTxt derivedIV
         
          plainText←1⊃AlgIdCrypt derivedKey derivedIV #.Crypt.Decrypt cipherText ⍝ salt ??
        ∇

        ∇ derived←DeriveKey(n ID P S r);AddTxt;Blockwise;u;v;p;s;D;I;A;B;i;Ai
          AddTxt←{0.125 #.Win.TxtInt{¯1↓+⌿1 0⌽(2 2⊤⍵),0}⍣≡(0.125 #.Win.IntTxt ⍺)+(0.125 #.Win.IntTxt ⍵)}
          Blockwise←{(+\1=⍺|⍳⍴⍵)⊂⍵}
     ⍝ n    ⍝ number of pseudorandom bytes requested       192÷8
     ⍝ ID   ⍝ ID_KEY=1 ID_IV=2 ID_MAC=3
          p←↑⍴P ⍝ (length of) password string
          s←↑⍴S ⍝ (length of) salt string
     ⍝ r    ⍝ iterations
          u←20  ⍝ digest output length of compression function 160÷8
          v←64  ⍝ mesage input length of compression function  512÷8
          D←v⍴#.Win.TxtInt ID ⍝ B.2.1
          S←(v×⌈s÷v)⍴S        ⍝ B.2.2
          P←(v×⌈p÷v)⍴P        ⍝ B.2.3
          I←S,P               ⍝ B.2.4
          A←''
          :While n>↑⍴A
              A,←Ai←({⍵ #.Crypt.Hash #.Win.CALG_SHA1}⍣r)D,I ⍝ B.2.6a
              B←v⍴Ai          ⍝ B.2.6b
              B←B AddTxt #.Win.TxtHex((¯1+2×v)⍴'0'),'1'
              I←∊B∘AddTxt¨v Blockwise I
          :EndWhile
          derived←n⍴A
        ∇

        ∇ derived←DeriveKey2(n ID P S r);AddTxt;Blockwise;v;p;s;D;I;A;B;i;Ai
          AddTxt←{0.125 #.Win.TxtInt{¯1↓+⌿1 0⌽(2 2⊤⍵),0}⍣≡(0.125 #.Win.IntTxt ⍺)+(0.125 #.Win.IntTxt ⍵)}
          Blockwise←{(+\1=⍺|⍳⍴⍵)⊂⍵}
     ⍝ n    ⍝ number of pseudorandom bytes requested       192÷8
     ⍝ ID   ⍝ ID_KEY=1 ID_IV=2 ID_MAC=3
          p←↑⍴P ⍝ (length of) password string
          s←↑⍴S ⍝ (length of) salt string
     ⍝ r    ⍝ iterations
     ⍝u←20  ⍝ digest output length of compression function 160÷8
          v←64  ⍝ mesage input length of compression function  512÷8
          D←v⍴#.Win.TxtInt ID ⍝ B.2.1
          S←(v×⌈s÷v)⍴S        ⍝ B.2.2
          P←(v×⌈p÷v)⍴P        ⍝ B.2.3
          I←S,P               ⍝ B.2.4
          A←''
          :Repeat
              A,←Ai←({⍵ #.Crypt.Hash #.Win.CALG_SHA1}⍣r)D,I ⍝ B.2.6a
              :If n≤↑⍴A
                  :Leave
              :EndIf
              B←v⍴Ai          ⍝ B.2.6b
              B←B AddTxt #.Win.TxtHex((¯1+2×v)⍴'0'),'1'
              I←∊B∘AddTxt¨v Blockwise I
          :EndRepeat
          derived←n⍴A
        ∇

        ∇ Derived←Param DeriveKeyBase Data;AddTxt;Blockwise;Algid;Count;DerivedLength;Id;B;BlockSize;Digest
          AddTxt←{0.125 #.Win.TxtInt{¯1↓+⌿1 0⌽(2 2⊤⍵),0}⍣≡(0.125 #.Win.IntTxt ⍺)+(0.125 #.Win.IntTxt ⍵)}
          Blockwise←{(+\1=⍺|⍳⍴⍵)⊂⍵}
          Algid Count DerivedLength Id←Param
          Derived←''
          :If Id∊0,⍳255     ⍝ PKCS#12
              BlockSize←64  ⍝ mesage input length of compression function  512÷8
              Id←BlockSize⍴#.Win.TxtInt Id
              :While DerivedLength>↑⍴Derived
                  Derived,←Digest←({⍵ #.Crypt.Hash #.Win.CALG_SHA1}⍣Count)Id,Data ⍝ B.2.6a
                  B←BlockSize⍴Digest          ⍝ B.2.6b
                  B←B AddTxt #.Win.TxtHex((¯1+2×BlockSize)⍴'0'),'1'
                  Data←∊B∘AddTxt¨BlockSize Blockwise Data
              :EndWhile
          :Else             ⍝ PEM
              Digest←''
              :Repeat
                  Derived,←Digest←({⍵ #.Crypt.Hash #.Win.CALG_MD5}⍣Count)Digest,Data
              :Until DerivedLength≤↑⍴Derived
          :EndIf
          Derived←DerivedLength↑Derived
        ∇

        ∇ derived←DeriveKeyNew(n ID P S r);AddTxt;Blockwise;u;v;p;s;D;I;A;B;i;Ai
          AddTxt←{0.125 #.Win.TxtInt{¯1↓+⌿1 0⌽(2 2⊤⍵),0}⍣≡(0.125 #.Win.IntTxt ⍺)+(0.125 #.Win.IntTxt ⍵)}
          Blockwise←{(+\1=⍺|⍳⍴⍵)⊂⍵}
     ⍝ n    ⍝ number of pseudorandom bytes requested       192÷8
     ⍝ ID   ⍝ ID_KEY=1 ID_IV=2 ID_MAC=3
          p←↑⍴P ⍝ (length of) password string
          s←↑⍴S ⍝ (length of) salt string
     ⍝ r    ⍝ iterations
          u←20  ⍝ digest output length of compression function 160÷8
          v←64  ⍝ mesage input length of compression function  512÷8
          D←v⍴#.Win.TxtInt ID ⍝ B.2.1
          S←(v×⌈s÷v)⍴S        ⍝ B.2.2
          P←(v×⌈p÷v)⍴P        ⍝ B.2.3
          I←S,P               ⍝ B.2.4
          A←''
          :While n>↑⍴A
              A,←Ai←({#.Crypt.HASH_SHA1 #.Crypt.Hash ⍵}⍣r)D,I ⍝ B.2.6a
              B←v⍴Ai          ⍝ B.2.6b
              B←B AddTxt #.Win.TxtHex((¯1+2×v)⍴'0'),'1'
              I←∊B∘AddTxt¨v Blockwise I
          :EndWhile
          derived←n⍴A
        ∇

        ∇ derived←DeriveKeyNew2(n ID P S r);u;v;p;s;I
     ⍝ n    ⍝ number of pseudorandom bytes requested       192÷8
     ⍝ ID   ⍝ ID_KEY=1 ID_IV=2 ID_MAC=3
          p←↑⍴P ⍝ (length of) password string
          s←↑⍴S ⍝ (length of) salt string
     ⍝ r    ⍝ iterations
          u←20  ⍝ digest output length of compression function 160÷8
          v←64  ⍝ mesage input length of compression function  512÷8
     ⍝                 ID ⍝ B.2.1
          S←(v×⌈s÷v)⍴S        ⍝ B.2.2
          P←(v×⌈p÷v)⍴P        ⍝ B.2.3
          I←S,P               ⍝ B.2.4
         
          derived←#.Crypt.HASH_SHA1 r n ID #.Crypt.Hash I
        ∇

        ∇ P12TEST CASE;FmtOid;p12;keyBag;pbeOid;salt;rounds;password;cipherText;plainText
          #.Win.Init
          #.ASN1.Init
          #.Crypt.Init
          FmtOid←{⍬≢0⍴⍵:'' ⋄ ⍵{⍵≤↑⍴#.ASN1.OidTab:↑#.ASN1.OidTab[⍵;2] ⋄ '0123456789.'['0123456789'⍳⍕⍺]}#.ASN1.OidTab[;1]⍳⊂⍵}
          :Select CASE
          :Case 1
              p12←#.ASN1.Code #.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\DTR_test_Mustermann_2048bit_20070305.p12'
              keyBag←3 3 2 2 2 3 2 2 5 3 2⊃p12
              password←'ZGQID71B'
          :Case 2
              p12←#.ASN1.Code #.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustAll2048_Enh.pfx'
              keyBag←3 3 2 2 2 3 2 2 2 3 2⊃p12
              password←''
          :Case 3
              p12←#.ASN1.Code #.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustMy2048_Base.pfx'
              keyBag←3 3 2 2 2 3 2 2 2 3 2⊃p12
              password←''
          :Case 4
              p12←#.ASN1.Code #.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustMy2048_Enh.pfx'
              keyBag←3 3 2 2 2 3 2 2 2 3 2⊃p12
              password←''
          :Case 5
              p12←#.ASN1.Code #.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustAll2048_Enh.pfx'
              keyBag←3 3 2 2 3 3 2 3⊃p12
              password←''
          :Case 6
              p12←#.ASN1.Code #.Win.File.Load'C:\Projects\Certs\midori-test\midori-test.p12'
              keyBag←3 3 2 2 2 3 2 2 2 3 2⊃p12
              password←'midori'
          :EndSelect
          :Select CASE
          :CaseList 1 2 3 4 6
              pbeOid←2 2 2⊃keyBag
              salt←2 3 2 2⊃keyBag   ⍝ Salt
              rounds←2 3 3 2⊃keyBag ⍝ Rounds
              cipherText←3 2⊃keyBag
          :Case 5
              pbeOid←3 2 2⊃keyBag
              salt←3 3 2 2⊃keyBag   ⍝ Salt
              rounds←3 3 3 2⊃keyBag ⍝ Rounds
              cipherText←4 2⊃keyBag
          :EndSelect
         
          ⎕←'pbeOid         ',FmtOid pbeOid
          ⎕←'Salt           ',#.Win.HexTxt salt
          ⎕←'Rounds         ',⍕rounds
         
          plainText←cipherText DecryptPbeNew(pbeOid password salt rounds)
         
          :Select CASE
          :Case 1
              plainText≡#.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\DTR_test_Mustermann_2048bit_20070305.SHROUDED'
          :Case 2
              plainText≡#.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustAll2048_Enh.SHROUDED'
          :Case 3
              plainText≡#.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustMy2048_Base.SHROUDED'
          :Case 4
              plainText≡#.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustMy2048_Enh.SHROUDED'
          :Case 5
              plainText≡#.Win.File.Load'C:\Projects\Cards\D-Trust Test PKCS#12\MS--PFX-P12\TestDTrustMy2048_Enh.CERTBAG'
          :Case 6
              plainText≡#.Win.File.Load'C:\Projects\Certs\midori-test\midori-test.CERTBAG'
          :EndSelect
         
          #.Crypt.Exit
          #.ASN1.Exit
          #.Win.Exit
        ∇

        ∇ {Ind}RECU asn;Treffer;Idx;element
          :If 0=⎕NC'Ind'
              Ind←⍬
          :EndIf
          Treffer←(0 0 6)(1 2 840 113549 1 12 1 3){1≥≡⍵:⍬ ⋄ {⍵/⍳⍴⍵}⍺∘≡¨⍵}asn
          :For Idx :In Treffer
              :If 0=⎕NC'OUTTAB'
                  OUTTAB←0⍴⊂⍬
              :EndIf
              OUTTAB,←⊂Ind,Idx
          :EndFor
         
         
          :For Idx :In (⍳⍴asn)~Treffer
              :If 1<≡element←Idx⊃asn
                  (Ind,Idx)RECU element
              :EndIf
          :EndFor
        ∇

        ∇ {Ind}RECUcert asn;Treffer;Idx;element
          :If 0=⎕NC'Ind'
              Ind←⍬
          :EndIf
          Treffer←(0 0 6)(1 2 840 113549 1 12 1 6){1≥≡⍵:⍬ ⋄ {⍵/⍳⍴⍵}⍺∘≡¨⍵}asn
          :For Idx :In Treffer
              :If 0=⎕NC'OUTTAB'
                  OUTTAB←0⍴⊂⍬
              :EndIf
              OUTTAB,←⊂Ind,Idx
          :EndFor
         
         
          :For Idx :In (⍳⍴asn)~Treffer
              :If 1<≡element←Idx⊃asn
                  (Ind,Idx)RECUcert element
              :EndIf
          :EndFor
        ∇

          RecuFromTree←{RecursiveConvert←{
                  326≠⎕DR ⍺:,⊂⍵(FmtHex ⍺)43
                  ClassFormTag←↑⍺ ⋄ Value←1↓⍺
                  State Name String←ClassFormTag GetStateNameString Value
                  (↑⍴Value)>1-2⊃ClassFormTag:(⊂(⍵,1)Name State),↑,/Value ∇¨⍵∘,¨1+⍳⍴Value
                  2<≡Value:(⊂(⍵,1)Name State),↑,/Value ∇¨⍵∘,¨1+⍳⍴Value
                  ,⊂⍵(Name,String)State}
              ⊂[1]⊃⍵ RecursiveConvert ⍬}

        :Namespace PEM
            ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

            ∇ derived←keylength DeriveKey(salt password);md
              derived←''
              md←''
              :Repeat
                  md←(md,password,salt)#.Crypt.Hash #.Win.CALG_MD5
                  derived,←md
              :Until keylength≤↑⍴derived
              derived←keylength↑derived
            ∇

            ∇ Return←{Password}Load FileName;Certificate;PrivateKey;Salt;Data;Text
              Data←#.ASN1.Base64.Decode #.Win.File.Load FileName
              :If ×⎕NC'Password'
              :AndIf 2 3≡⍴Data
              :AndIf Data[;1]≡'RSA PRIVATE KEY' 'CERTIFICATE'
              :AndIf 'DES-EDE3-CBC,'≡13↑Salt←↑(↑Data[1;2])[2;2]
                  Salt←#.Win.TxtHex 13↓Salt
                  PrivateKey←(↑Data[1;3])#.Crypt.SessionkeyDecrypt(24 DeriveKey Salt Password)Salt''#.Win.CALG_3DES #.Win.CRYPT_MODE_CBC
                  Certificate←↑Data[2;3]
                  Return←Certificate PrivateKey
              :ElseIf 1 3≡⍴Data
              :AndIf Data[1;1]≡⊂'CERTIFICATE'
                  Certificate←↑Data[1;3]
                  Return←Certificate
              :Else
                  Return←''
              :EndIf
            ∇

            ∇ Sample;password;salt;cipher;plain;Certificate;PrivateKey
              #.Win.Init
              #.ASN1.Init
             
              password←'password'
              salt←#.Win.TxtHex'6D3B09E4CA5421FF'
              cipher←#.Win.File.Load'C:\Projects\Certs\EricRescorla\client.pvkenc'
              plain←cipher #.Crypt.SessionkeyDecrypt(24 DeriveKey salt password)salt''#.Win.CALG_3DES #.Win.CRYPT_MODE_CBC
              plain #.Win.File.Save'C:\Projects\Certs\EricRescorla\client.pvk'
              cipher←plain #.Crypt.SessionkeyEncrypt(24 DeriveKey salt password)salt''#.Win.CALG_3DES #.Win.CRYPT_MODE_CBC
              cipher #.Win.File.Save'C:\Projects\Certs\EricRescorla\client.pvkencX'
             
              Certificate PrivateKey←password Load'C:\Projects\Certs\EricRescorla\client.pem'
              Certificate PrivateKey password Save'C:\Projects\Certs\EricRescorla\client.pemX'
             
              password←'password'
              salt←#.Win.TxtHex'5772A2A7BE34B611'
              cipher←#.Win.File.Load'C:\Projects\Certs\EricRescorla\server.pvkenc'
              plain←cipher #.Crypt.SessionkeyDecrypt(24 DeriveKey salt password)salt''#.Win.CALG_3DES #.Win.CRYPT_MODE_CBC
              plain #.Win.File.Save'C:\Projects\Certs\EricRescorla\server.pvk'
              cipher←plain #.Crypt.SessionkeyEncrypt(24 DeriveKey salt password)salt''#.Win.CALG_3DES #.Win.CRYPT_MODE_CBC
              cipher #.Win.File.Save'C:\Projects\Certs\EricRescorla\server.pvkencX'
             
              Certificate PrivateKey←password Load'C:\Projects\Certs\EricRescorla\server.pem'
              Certificate PrivateKey password Save'C:\Projects\Certs\EricRescorla\server.pemX'
             
              Certificate←Load'C:\Projects\Certs\EricRescorla\root.pem'
              Certificate Save'C:\Projects\Certs\EricRescorla\root.pemX'
             
              #.ASN1.Exit
              #.Win.Exit
            ∇

            ∇ {ValidFlag}←Params Save FileName;Certificate;PrivateKey;Password;Salt;Data;Text
              :If 2=≡Params
              :AndIf 3=↑⍴Params
                  Certificate PrivateKey Password←Params
                  Salt←#.Crypt.Random 8
                  Data←2 3⍴⊂''
                  Data[;1]←'RSA PRIVATE KEY' 'CERTIFICATE'
                  Data[1;2]←⊂2 2⍴'Proc-Type' '4,ENCRYPTED' 'DEK-Info'('DES-EDE3-CBC,',#.Win.HexTxt Salt)
                  Data[2;2]←⊂0 2⍴⊂''
                  Data[1;3]←⊂PrivateKey #.Crypt.SessionkeyEncrypt(24 DeriveKey Salt Password)Salt''#.Win.CALG_3DES #.Win.CRYPT_MODE_CBC
                  Data[2;3]←⊂Certificate
              :Else
                  Certificate←Params
                  Data←1 3⍴⊂''
                  Data[1;1]←⊂'CERTIFICATE'
                  Data[1;2]←⊂0 2⍴⊂''
                  Data[1;3]←⊂Certificate
              :EndIf
              (#.ASN1.Base64.Encode Data)#.Win.File.Save FileName
            ∇

        :EndNamespace
    :EndNamespace
    :Namespace PKCS7
        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        ∇ Response←TimesignHash Parms;Certificate;PrivateKey;HashAlgorithm;HashValue;v1;v3;telesec_attribute_nameDistinguisher;pkcs_1_rsaEncryption;pkcs_7_data;pkcs_7_signedData;pkcs_9_contentType;pkcs_9_messageDigest;pkcs_9_signingTime;sha1;rsaSignatureWithripemd160;id_at_commonName;id_at_countryName;id_at_organizationName
     ⍝ Parms[1]  = Certificate   X.509 encoded Certificate
     ⍝ Parms[2]  = PrivateKey    PKCS#1 encoded RSA PrivateKey
     ⍝ Parms[3]  = HashAlgorithm OID of Hash Algorithm
     ⍝ Parms[4]  = HashValue     To be signed message
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2001
     ⍝ mailto:Hager@Dortmund.net
          ##.Init
     ⍝ Versions:
          v1←1 ⍝ TSP/PKCS#7 Version
          v3←2 ⍝ X.509 Version
     ⍝ OID Values:
          telesec_attribute_nameDistinguisher←0 2 262 1 10 7 20
          pkcs_1_rsaEncryption←1 2 840 113549 1 1 1
          pkcs_7_data←1 2 840 113549 1 7 1
          pkcs_7_signedData←1 2 840 113549 1 7 2
          pkcs_9_contentType←1 2 840 113549 1 9 3
          pkcs_9_messageDigest←1 2 840 113549 1 9 4
          pkcs_9_signingTime←1 2 840 113549 1 9 5
          sha1←1 3 14 3 2 26
          rsaSignatureWithripemd160←1 3 36 3 3 1 2
          id_at_commonName←2 5 4 3
          id_at_countryName←2 5 4 6
          id_at_organizationName←2 5 4 10
         
          Certificate PrivateKey HashAlgorithm HashValue←4↑Parms
         
          Response←##.SEQUENCE
        ∇

    :EndNamespace
    :Namespace Samples
        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        ∇ CAThawteSample;OidToString;pkcs_1_rsaEncryption;pkcs_1_md2WithRSAEncryption;pkcs_1_md5WithRSAEncryption;pkcs_1_sha1WithRSAEncryption;pkcs_7_data;pkcs_7_signedData;pkcs_7_digestedData;pkcs_7_encryptedData;pkcs_9_at_emailAddress;ms_spcStatementType;ms_spcSpOpusInfo;id_at_commonName;id_at_countryName;id_at_localityName;id_at_stateOrProvinceName;id_at_streetAddress;id_at_organizationName;id_at_organizationalUnitName;id_ce_basicConstraints;PrivateKey;PublicKey;v1;v2;v3;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;Critical;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;CAThawte
          #.ASN1.Init
          #.Crypt.Init
          OidToString←{1<≡⍵:∇¨⍵ ⋄ 82=⎕DR ⍵:⍵ ⋄ ⍵{⍵≤↑⍴#.ASN1.OidTab:↑#.ASN1.OidTab[⍵;2] ⋄ (⎕D,'.')[⎕D⍳⍕⍺]}#.ASN1.OidTab[;1]⍳⊂⍵}
         
          pkcs_1_rsaEncryption←1 2 840 113549 1 1 1
          pkcs_1_md2WithRSAEncryption←1 2 840 113549 1 1 2
          pkcs_1_md5WithRSAEncryption←1 2 840 113549 1 1 4
          pkcs_1_sha1WithRSAEncryption←1 2 840 113549 1 1 5
          pkcs_7_data←1 2 840 113549 1 7 1
          pkcs_7_signedData←1 2 840 113549 1 7 2
          pkcs_7_digestedData←1 2 840 113549 1 7 5
          pkcs_7_encryptedData←1 2 840 113549 1 7 6
          pkcs_9_at_emailAddress←1 2 840 113549 1 9 1
          ms_spcStatementType←1 3 6 1 4 1 311 2 1 11
          ms_spcSpOpusInfo←1 3 6 1 4 1 311 2 1 12
          id_at_commonName←2 5 4 3
          id_at_countryName←2 5 4 6
          id_at_localityName←2 5 4 7
          id_at_stateOrProvinceName←2 5 4 8
          id_at_streetAddress←2 5 4 9
          id_at_organizationName←2 5 4 10
          id_at_organizationalUnitName←2 5 4 11
          id_ce_basicConstraints←2 5 29 19
         
     ⍝ For SubjectPublicKey und for signing we need a key pair:
          PrivateKey PublicKey←#.Crypt.PKEY_RSA #.Crypt.PKey 1024
     ⍝ Now we can build the to be signed TBSCertificate:
           ⋄ ⋄ ⋄ v1 v2 v3←0 1 2
           ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
           ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 0
           ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_md5WithRSAEncryption
           ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
           ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
           ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
           ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'ZA'
           ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
           ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_stateOrProvinceName
           ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'Western Cape'
           ⋄ ⋄ ⋄ StateOrProvinceName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
           ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_localityName
           ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'Cape Town'
           ⋄ ⋄ ⋄ LocalityName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
           ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
           ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'Thawte Consulting'
           ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
           ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationalUnitName
           ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'Certification Services Division'
           ⋄ ⋄ ⋄ OrganizationalUnitName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
           ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
           ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'Thawte Personal Basic CA'
           ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
           ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID pkcs_9_at_emailAddress
           ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR'personal-basic@thawte.com'
           ⋄ ⋄ ⋄ EmailAddress←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
           ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName StateOrProvinceName LocalityName OrganizationName OrganizationalUnitName CommonName EmailAddress
           ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(1996 1 1 1 0 0 0)
           ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2021 1 1 0 59 59 0)
           ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
           ⋄ ⋄ Subject←Issuer ⍝ On Rootcertificates Subject and Issuer identical
           ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
           ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
           ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
           ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
           ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
           ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
           ⋄ ⋄ ⋄ ⋄ Critical←#.ASN1.BOOLEAN #.ASN1.TRUE
           ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.BOOLEAN #.ASN1.TRUE))
           ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId Critical ExtnValue
           ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE BasicConstraints)
           ⋄ TBSCertificate←#.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Just append the signature, and the X.509 conforming certificate CAThawte is finished:
           ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_md5WithRSAEncryption
           ⋄ ⋄ Parameters←#.ASN1.NULLTAG
           ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
           ⋄ Signature←#.ASN1.BITSTRING(#.Crypt.PKEY_RSA_PK1S_MD5 PrivateKey #.Crypt.PKey #.Crypt.HASH_MD5 #.Crypt.Hash 1 #.ASN1.Code TBSCertificate)
          CAThawte←#.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
         
     ⍝ Lets try to encode/decode the private key from every possible to every possible depth:
          ⎕←≡¨(0,⍳3)∘.#.ASN1.Code(0,⍳3)#.ASN1.Code¨⊂PrivateKey
          ⎕←''
     ⍝ Compare each encoded with the original private key:
          ⎕←PrivateKey∘≡¨1 #.ASN1.Code¨(0,⍳3)∘.#.ASN1.Code(0,⍳3)#.ASN1.Code¨⊂PrivateKey
          ⎕←''
     ⍝ Do the same steps with the certificate CAThawte:
          ⎕←≡¨(0,⍳9)∘.#.ASN1.Code(0,⍳9)#.ASN1.Code¨⊂CAThawte
          ⎕←''
          ⎕←(1 #.ASN1.Code CAThawte)∘≡¨1 #.ASN1.Code¨(0,⍳9)∘.#.ASN1.Code(0,⍳9)#.ASN1.Code¨⊂CAThawte
         
          #.Crypt.Exit
          #.ASN1.Exit
        ∇

        ∇ LetterSample;Name;Street;Town;Sender;Addressee;Message;Date;Letter
          #.ASN1.Init
         
           ⋄ ⋄ Name←#.ASN1.PRINTABLESTR'Meiner Einer'
           ⋄ ⋄ Street←#.ASN1.PRINTABLESTR'Meine Str. 123'
           ⋄ ⋄ Town←#.ASN1.PRINTABLESTR'Heimatstadt'
           ⋄ Sender←#.ASN1.SEQUENCE Name Street Town
           ⋄ ⋄ Name←#.ASN1.PRINTABLESTR'Deiner Einer'
           ⋄ ⋄ Street←#.ASN1.PRINTABLESTR'Deine Str. 999'
           ⋄ ⋄ Town←#.ASN1.PRINTABLESTR'Fremdstadt'
           ⋄ Addressee←#.ASN1.SEQUENCE Name Street Town
           ⋄ Message←#.ASN1.T61STR'Grüße aus der Heimat'
           ⋄ Date←#.ASN1.UTCTIME(2002 1 18 17 30 0 0)
          Letter←#.ASN1.SEQUENCE Sender Addressee Message Date
          Letter≡1 #.ASN1.Code 0 #.ASN1.Code Letter
         
     ⍝ ⎕←''
     ⍝ ⎕←'      ≡Letter'
     ⍝ ≡Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      2 #.Display Letter'
     ⍝ 2 #.Display Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      ≡3 #.ASN1.Code Letter'
     ⍝ ≡3 #.ASN1.Code Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      2 #.Display 3 #.ASN1.Code Letter'
     ⍝ 2 #.Display 3 #.ASN1.Code Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      ≡2 #.ASN1.Code Letter'
     ⍝ ≡2 #.ASN1.Code Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      1 #.Display 2 #.ASN1.Code Letter'
     ⍝ 1 #.Display 2 #.ASN1.Code Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      ≡1 #.ASN1.Code Letter'
     ⍝ ≡1 #.ASN1.Code Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      ⍴1 #.ASN1.Code Letter'
     ⍝ ⍴1 #.ASN1.Code Letter
     ⍝ ⎕←''
     ⍝ ⎕←'      ¯89 #.Display 1 #.ASN1.Code Letter'
     ⍝ ¯89 #.Display 1 #.ASN1.Code Letter
         
          #.ASN1.Exit
        ∇

        ∇ UniqueId;OidToString;pkcs_1_rsaEncryption;pkcs_1_md2WithRSAEncryption;pkcs_1_md5WithRSAEncryption;pkcs_1_sha1WithRSAEncryption;pkcs_7_data;pkcs_7_signedData;pkcs_7_digestedData;pkcs_7_encryptedData;pkcs_9_at_emailAddress;ms_spcStatementType;ms_spcSpOpusInfo;id_at_commonName;id_at_countryName;id_at_localityName;id_at_stateOrProvinceName;id_at_streetAddress;id_at_organizationName;id_at_organizationalUnitName;id_ce_basicConstraints;KeyPair;PrivatKey;PublicKey;v1;v2;v3;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;Critical;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;IssuerUniqueId;SubjectUniqueId;CAThawte;PEM
          #.ASN1.Init
          OidToString←{1<≡⍵:∇¨⍵ ⋄ 82=⎕DR ⍵:⍵ ⋄ ⍵{⍵≤↑⍴#.ASN1.OidTab:↑#.ASN1.OidTab[⍵;2] ⋄ (⎕D,'.')[⎕D⍳⍕⍺]}#.ASN1.OidTab[;1]⍳⊂⍵}
         
          pkcs_1_rsaEncryption←1 2 840 113549 1 1 1
          pkcs_1_md2WithRSAEncryption←1 2 840 113549 1 1 2
          pkcs_1_md5WithRSAEncryption←1 2 840 113549 1 1 4
          pkcs_1_sha1WithRSAEncryption←1 2 840 113549 1 1 5
          pkcs_7_data←1 2 840 113549 1 7 1
          pkcs_7_signedData←1 2 840 113549 1 7 2
          pkcs_7_digestedData←1 2 840 113549 1 7 5
          pkcs_7_encryptedData←1 2 840 113549 1 7 6
          pkcs_9_at_emailAddress←1 2 840 113549 1 9 1
          ms_spcStatementType←1 3 6 1 4 1 311 2 1 11
          ms_spcSpOpusInfo←1 3 6 1 4 1 311 2 1 12
          id_at_commonName←2 5 4 3
          id_at_countryName←2 5 4 6
          id_at_localityName←2 5 4 7
          id_at_stateOrProvinceName←2 5 4 8
          id_at_streetAddress←2 5 4 9
          id_at_organizationName←2 5 4 10
          id_at_organizationalUnitName←2 5 4 11
          id_ce_basicConstraints←2 5 29 19
         
          :If 0
              CAThawte←#.Win.File.Load'CAThawte.CER'
          :Else
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivatKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 1024
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ ⋄ v1 v2 v3←0 1 2
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v2)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 0
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_md5WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_stateOrProvinceName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'NRW'
               ⋄ ⋄ ⋄ StateOrProvinceName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_localityName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'Dortmund'
               ⋄ ⋄ ⋄ LocalityName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'HAGER-ELECTRONICS GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationalUnitName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'TEST Services'
               ⋄ ⋄ ⋄ OrganizationalUnitName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'HE TEST CA'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID pkcs_9_at_emailAddress
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR'hager@dortmund.net'
               ⋄ ⋄ ⋄ EmailAddress←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName StateOrProvinceName LocalityName OrganizationName OrganizationalUnitName CommonName EmailAddress
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.GENERALIZEDTIME ⎕TS
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.GENERALIZEDTIME(⎕TS+7↑100)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ Subject←Issuer ⍝ Bei Rootzertifikaten sind Subject und Issuer identisch
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
         
               ⋄ ⋄ IssuerUniqueId←(#.ASN1.CONTEXT 1)(#.ASN1.BITSTRING(22⍴0 1))
               ⋄ ⋄ SubjectUniqueId←(#.ASN1.CONTEXT 2)(#.ASN1.BITSTRING(22⍴0 1))
         
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ Critical←#.ASN1.BOOLEAN #.ASN1.TRUE
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.BOOLEAN #.ASN1.TRUE))
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId Critical ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE BasicConstraints)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueId SubjectUniqueId Extensions
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_md5WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign PrivatKey #.Win.CALG_MD5)
              CAThawte←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
          :EndIf
         
         
          CAThawte #.Win.File.Save'C:\Dokumente und Einstellungen\Hager\Desktop\Certs\UniqueId\UniqueId.CER'
          PrivatKey #.Win.File.Save'C:\Dokumente und Einstellungen\Hager\Desktop\Certs\UniqueId\UniqueId.PVK'
          PEM←'CERTIFICATE' 'RSA PRIVATE KEY',(⊂0 2⍴''),[1.5]CAThawte PrivatKey
         
          (#.ASN1.Base64.Encode PEM)#.Win.File.Save'C:\Dokumente und Einstellungen\Hager\Desktop\Certs\UniqueId\UniqueId.PEM'
         
          #.ASN1.Exit
        ∇

        :Namespace DFrust
            ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

            ∇ BuildAll;id_seis_pe_cn;pkcs_1_rsaEncryption;pkcs_1_sha1WithRSAEncryption;id_at_commonName;id_at_countryName;id_at_organizationName;id_at_organizationalUnitName;pkcs_9_at_emailAddress;id_ce_extKeyUsage;id_kp_serverAuth;id_kp_clientAuth;id_ce_basicConstraints;id_ce_subjectKeyIdentifier;id_ce_authorityKeyIdentifier;id_ce_keyUsage;v1;v2;v3;Password;RootKey;RootCert;Sub1Key;Sub1Cert;Kar1Key;Kar1Cert;Kar2Key;Kar2Cert;Srv1Key;Srv1Cert;Srv2Key;Srv2Cert;Srv3Key;Srv3Cert;Srv3Domain
              #.Win.Init
              #.ASN1.Init
              id_seis_pe_cn←1 2 752 34 2 1
              pkcs_1_rsaEncryption←1 2 840 113549 1 1 1
              pkcs_1_sha1WithRSAEncryption←1 2 840 113549 1 1 5
              id_at_commonName←2 5 4 3
              id_at_countryName←2 5 4 6
              id_at_organizationName←2 5 4 10
              id_at_organizationalUnitName←2 5 4 11
              pkcs_9_at_emailAddress←1 2 840 113549 1 9 1
              id_ce_extKeyUsage←2 5 29 37
              id_kp_serverAuth←1 3 6 1 5 5 7 3 1
              id_kp_clientAuth←1 3 6 1 5 5 7 3 2
     ⍝id_ms_kp_sc_logon←
              id_ce_basicConstraints←2 5 29 19
              id_ce_subjectKeyIdentifier←2 5 29 14
              id_ce_authorityKeyIdentifier←2 5 29 35
              id_ce_keyUsage←2 5 29 15
              v1 v2 v3←0 1 2
             
     ⍝RootCert←#.Win.File.Load'C:\Projects\Certs\D-TRUST_SC\C70E-NWAuthRoot01.CER'
     ⍝Sub1Cert←#.Win.File.Load'C:\Projects\Certs\D-TRUST_SC\C00E-NWAuthSub01.CER'
     ⍝Kar1Cert←#.Win.File.Load'C:\Projects\Certs\D-TRUST_SC\4301-DVCATest1ccKarte1.CER'
     ⍝Kar2Cert←#.Win.File.Load'C:\Projects\Certs\D-TRUST_SC\4301-DVCATest1ccKarte2.CER'
             
              :If 1
                  Sub1Key←#.Win.File.Load'C:\Projects\Certs\D-FRUST_SW\C00E-NWAuthSub01.PVK'
              :Else
                  RootKey RootCert←BuildRoot
                  Sub1Key Sub1Cert←BuildSub1 RootKey
                  Kar1Key Kar1Cert←BuildKarte1 Sub1Key           ⍝ 218099
                  Kar2Key Kar2Cert←BuildKarte2 Sub1Key           ⍝ 218107
                  Srv1Key Srv1Cert←BuildServerS0410236 Sub1Key   ⍝ MarcoWenzel  s0410236.issh.de   172.20.109.226
                  Srv2Key Srv2Cert←BuildServerYKAM119088 Sub1Key ⍝ MichaelHager ykam119088.issh.de 172.20.109.189
              :EndIf
             
              Srv3Key Srv3Cert←BuildServerMynet2 Sub1Key     ⍝ MarcoWenzel  mynet2.bdr.de
              Password←'password'
              Srv3Domain←'mynet2.bdr.de'
              :If 1
                  Srv3Cert #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\',Srv3Domain,'.CER'
                  Srv3Key #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\',Srv3Domain,'.PVK'
                  Srv3Cert Srv3Key Password #.ASN1.PKCS12.PEM.Save'C:\Projects\Certs\D-FRUST_SW\',Srv3Domain,'.PEM'
              :Else
                  RootCert #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\C70E-NWAuthRoot01.CER'
                  RootKey #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\C70E-NWAuthRoot01.PVK'
                  RootCert RootKey Password #.ASN1.PKCS12.PEM.Save'C:\Projects\Certs\D-FRUST_SW\C70E-NWAuthRoot01.PEM'
             
                  Sub1Cert #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\C00E-NWAuthSub01.CER'
                  Sub1Key #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\C00E-NWAuthSub01.PVK'
                  Sub1Cert Sub1Key Password #.ASN1.PKCS12.PEM.Save'C:\Projects\Certs\D-FRUST_SW\C00E-NWAuthSub01.PEM'
             
                  Kar1Cert #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\4301-DVCATest1ccKarte1.CER'
                  Kar1Key #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\4301-DVCATest1ccKarte1.PVK'
                  Kar1Cert Kar1Key Password #.ASN1.PKCS12.PEM.Save'C:\Projects\Certs\D-FRUST_SW\4301-DVCATest1ccKarte1.PEM'
             
                  Kar2Cert #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\4301-DVCATest1ccKarte2.CER'
                  Kar2Key #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\4301-DVCATest1ccKarte2.PVK'
                  Kar2Cert Kar2Key Password #.ASN1.PKCS12.PEM.Save'C:\Projects\Certs\D-FRUST_SW\4301-DVCATest1ccKarte2.PEM'
             
                  Srv1Cert #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\s0410236.issh.de.CER'
                  Srv1Key #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\s0410236.issh.de.PVK'
                  Srv1Cert Srv1Key Password #.ASN1.PKCS12.PEM.Save'C:\Projects\Certs\D-FRUST_SW\s0410236.issh.de.PEM'
             
                  Srv2Cert #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\ykam119088.issh.de.CER'
                  Srv2Key #.Win.File.Save'C:\Projects\Certs\D-FRUST_SW\ykam119088.issh.de.PVK'
                  Srv2Cert Srv2Key Password #.ASN1.PKCS12.PEM.Save'C:\Projects\Certs\D-FRUST_SW\ykam119088.issh.de.PEM'
              :EndIf
              #.ASN1.Exit
              #.Win.Exit
            ∇

            ∇ (PrivateKey Certificate)←BuildKarte1 IssuerPrivateKey;KeyPair;PublicKey;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;SubjectKeyIdentifier;KeyUsage;AuthorityKeyIdentifier;SmartcardReference;ExtKeyUsage
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivateKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 2048
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
             
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 35630
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Sub 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(2007 5 10 11 12 31 0)
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2010 5 10 11 12 31 0)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'DFR'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'Test DVCA 2.0 1cc Karte 1'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Subject←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_extKeyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.OID id_kp_clientAuth))
               ⋄ ⋄ ⋄ ExtKeyUsage←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE'')
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_subjectKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.OCTETSTRING(#.ASN1.PKCS1.GetKeyIdentifierFromKey PublicKey))
               ⋄ ⋄ ⋄ SubjectKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_seis_pe_cn
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.PRINTABLESTR'218099')
               ⋄ ⋄ ⋄ SmartcardReference←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_authorityKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE((#.ASN1.IMPLICIT 0)(#.ASN1.PKCS1.GetKeyIdentifierFromKey IssuerPrivateKey)))
               ⋄ ⋄ ⋄ AuthorityKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_keyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.BITSTRING(,1))
               ⋄ ⋄ ⋄ KeyUsage←#.ASN1.SEQUENCE ExtnId(#.ASN1.BOOLEAN #.ASN1.TRUE)ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE ExtKeyUsage BasicConstraints SubjectKeyIdentifier SmartcardReference AuthorityKeyIdentifier KeyUsage)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Noch die Signatur darunter und das X.509-konforme Zertifikat D-FRUST ist fertig:
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign IssuerPrivateKey #.Win.CALG_SHA1)
              Certificate←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
            ∇

            ∇ (PrivateKey Certificate)←BuildKarte2 IssuerPrivateKey;KeyPair;PublicKey;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;SubjectKeyIdentifier;KeyUsage;AuthorityKeyIdentifier;SmartcardReference;ExtKeyUsage
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivateKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 2048
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
             
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 35631
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Sub 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(2007 5 10 11 12 31 0)
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2010 5 10 11 12 31 0)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'DFR'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'DVCA Test 1cc Karte 2'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Subject←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_extKeyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.OID id_kp_clientAuth))
               ⋄ ⋄ ⋄ ExtKeyUsage←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE'')
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_subjectKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.OCTETSTRING(#.ASN1.PKCS1.GetKeyIdentifierFromKey PublicKey))
               ⋄ ⋄ ⋄ SubjectKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_seis_pe_cn
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.PRINTABLESTR'218107')
               ⋄ ⋄ ⋄ SmartcardReference←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_authorityKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE((#.ASN1.IMPLICIT 0)(#.ASN1.PKCS1.GetKeyIdentifierFromKey IssuerPrivateKey)))
               ⋄ ⋄ ⋄ AuthorityKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_keyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.BITSTRING(,1))
               ⋄ ⋄ ⋄ KeyUsage←#.ASN1.SEQUENCE ExtnId(#.ASN1.BOOLEAN #.ASN1.TRUE)ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE ExtKeyUsage BasicConstraints SubjectKeyIdentifier SmartcardReference AuthorityKeyIdentifier KeyUsage)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Noch die Signatur darunter und das X.509-konforme Zertifikat D-FRUST ist fertig:
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign IssuerPrivateKey #.Win.CALG_SHA1)
              Certificate←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
            ∇

            ∇ (PrivateKey Certificate)←BuildRoot;KeyPair;PublicKey;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;SubjectKeyIdentifier;KeyUsage
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivateKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 2048
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
             
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 35465
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Root 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(2007 1 17 12 55 4 0)
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2012 1 17 12 55 4 0)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ Subject←Issuer ⍝ Bei Rootzertifikaten sind Subject und Issuer identisch
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.BOOLEAN #.ASN1.TRUE))
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId(#.ASN1.BOOLEAN #.ASN1.TRUE)ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_subjectKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.OCTETSTRING(#.ASN1.PKCS1.GetKeyIdentifierFromKey PublicKey))
               ⋄ ⋄ ⋄ SubjectKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_keyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.BITSTRING(0 0 0 0 0 1 1))
               ⋄ ⋄ ⋄ KeyUsage←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE BasicConstraints SubjectKeyIdentifier KeyUsage)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Noch die Signatur darunter und das X.509-konforme Zertifikat D-FRUST ist fertig:
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign PrivateKey #.Win.CALG_SHA1)
              Certificate←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
            ∇

            ∇ (PrivateKey Certificate)←BuildServerMynet2 IssuerPrivateKey;KeyPair;PublicKey;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;SubjectKeyIdentifier;KeyUsage;AuthorityKeyIdentifier;ExtKeyUsage
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivateKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 2048
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
             
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 35683
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Sub 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(2007 5 10 11 12 31 0)
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2010 5 10 11 12 31 0)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'Bundesdruckerei'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationalUnitName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'SH DD SW Software Development'
               ⋄ ⋄ ⋄ OrganizationalUnitName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR'mynet2.bdr.de'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID pkcs_9_at_emailAddress
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR'Marco.Wenzel@bdr.de'
               ⋄ ⋄ ⋄ EmailAddress←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Subject←#.ASN1.SEQUENCE CountryName OrganizationName OrganizationalUnitName CommonName EmailAddress
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_extKeyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.OID id_kp_serverAuth))
               ⋄ ⋄ ⋄ ExtKeyUsage←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE'')
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_subjectKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.OCTETSTRING(#.ASN1.PKCS1.GetKeyIdentifierFromKey PublicKey))
               ⋄ ⋄ ⋄ SubjectKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_authorityKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE((#.ASN1.IMPLICIT 0)(#.ASN1.PKCS1.GetKeyIdentifierFromKey IssuerPrivateKey)))
               ⋄ ⋄ ⋄ AuthorityKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_keyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.BITSTRING(1 0 1 0 1))
               ⋄ ⋄ ⋄ KeyUsage←#.ASN1.SEQUENCE ExtnId(#.ASN1.BOOLEAN #.ASN1.TRUE)ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE ExtKeyUsage BasicConstraints SubjectKeyIdentifier AuthorityKeyIdentifier KeyUsage)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Noch die Signatur darunter und das X.509-konforme Zertifikat D-FRUST ist fertig:
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign IssuerPrivateKey #.Win.CALG_SHA1)
              Certificate←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
            ∇

            ∇ (PrivateKey Certificate)←BuildServerS0410236 IssuerPrivateKey;KeyPair;PublicKey;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;SubjectKeyIdentifier;KeyUsage;AuthorityKeyIdentifier;ExtKeyUsage
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivateKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 2048
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
             
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 35681
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Sub 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(2007 5 10 11 12 31 0)
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2010 5 10 11 12 31 0)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'Bundesdruckerei'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationalUnitName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'SH DD SW Software Development'
               ⋄ ⋄ ⋄ OrganizationalUnitName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR's0410236.issh.de'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID pkcs_9_at_emailAddress
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR'Marco.Wenzel@bdr.de'
               ⋄ ⋄ ⋄ EmailAddress←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Subject←#.ASN1.SEQUENCE CountryName OrganizationName OrganizationalUnitName CommonName EmailAddress
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_extKeyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.OID id_kp_serverAuth))
               ⋄ ⋄ ⋄ ExtKeyUsage←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE'')
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_subjectKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.OCTETSTRING(#.ASN1.PKCS1.GetKeyIdentifierFromKey PublicKey))
               ⋄ ⋄ ⋄ SubjectKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_authorityKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE((#.ASN1.IMPLICIT 0)(#.ASN1.PKCS1.GetKeyIdentifierFromKey IssuerPrivateKey)))
               ⋄ ⋄ ⋄ AuthorityKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_keyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.BITSTRING(1 0 1 0 1))
               ⋄ ⋄ ⋄ KeyUsage←#.ASN1.SEQUENCE ExtnId(#.ASN1.BOOLEAN #.ASN1.TRUE)ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE ExtKeyUsage BasicConstraints SubjectKeyIdentifier AuthorityKeyIdentifier KeyUsage)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Noch die Signatur darunter und das X.509-konforme Zertifikat D-FRUST ist fertig:
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign IssuerPrivateKey #.Win.CALG_SHA1)
              Certificate←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
            ∇

            ∇ (PrivateKey Certificate)←BuildServerYKAM119088 IssuerPrivateKey;KeyPair;PublicKey;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;SubjectKeyIdentifier;KeyUsage;AuthorityKeyIdentifier;ExtKeyUsage
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivateKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 2048
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
             
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 35682
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Sub 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(2007 5 10 11 12 31 0)
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2010 5 10 11 12 31 0)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'Bundesdruckerei'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationalUnitName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'SH DD SW Software Development'
               ⋄ ⋄ ⋄ OrganizationalUnitName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR'ykam119088.issh.de'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID pkcs_9_at_emailAddress
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.IA5STR'Michael.Hager@bdr.de'
               ⋄ ⋄ ⋄ EmailAddress←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Subject←#.ASN1.SEQUENCE CountryName OrganizationName OrganizationalUnitName CommonName EmailAddress
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_extKeyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.OID id_kp_serverAuth))
               ⋄ ⋄ ⋄ ExtKeyUsage←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE'')
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_subjectKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.OCTETSTRING(#.ASN1.PKCS1.GetKeyIdentifierFromKey PublicKey))
               ⋄ ⋄ ⋄ SubjectKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_authorityKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE((#.ASN1.IMPLICIT 0)(#.ASN1.PKCS1.GetKeyIdentifierFromKey IssuerPrivateKey)))
               ⋄ ⋄ ⋄ AuthorityKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_keyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.BITSTRING(1 0 1 0 1))
               ⋄ ⋄ ⋄ KeyUsage←#.ASN1.SEQUENCE ExtnId(#.ASN1.BOOLEAN #.ASN1.TRUE)ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE ExtKeyUsage BasicConstraints SubjectKeyIdentifier AuthorityKeyIdentifier KeyUsage)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Noch die Signatur darunter und das X.509-konforme Zertifikat D-FRUST ist fertig:
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign IssuerPrivateKey #.Win.CALG_SHA1)
              Certificate←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
            ∇

            ∇ (PrivateKey Certificate)←BuildSub1 IssuerPrivateKey;KeyPair;PublicKey;Version;SerialNumber;Algorithm;Parameters;Signature;AttributeType;Value;CountryName;StateOrProvinceName;LocalityName;OrganizationName;OrganizationalUnitName;CommonName;EmailAddress;Issuer;NotBefore;NotAfter;Validity;Subject;SubjectPublicKey;SubjectPublicKeyInfo;ExtnId;ExtnValue;BasicConstraints;Extensions;TBSCertificate;AlgorithmIdentifier;IssuerTab;SubjectKeyIdentifier;KeyUsage;AuthorityKeyIdentifier
     ⍝ Für SubjectPublicKey und zum Signieren benötigen wir ein Schlüsselpaar:
              PrivateKey←#.ASN1.PKCS1.KeyEncode 8↑KeyPair←#.ASN1.PKCS1.KeyGenerate 2048
              PublicKey←#.ASN1.PKCS1.KeyEncode 2↑KeyPair
             
     ⍝ Nun können wir das zu unterzeichnende TBSCertificate zusammenbauen:
               ⋄ ⋄ Version←(#.ASN1.CONTEXT 0)(#.ASN1.INTEGER v3)
               ⋄ ⋄ SerialNumber←#.ASN1.INTEGER 35466
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ Signature←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Root 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Issuer←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ NotBefore←#.ASN1.UTCTIME(2007 1 17 12 55 4 0)
               ⋄ ⋄ ⋄ NotAfter←#.ASN1.UTCTIME(2012 1 17 12 55 4 0)
               ⋄ ⋄ Validity←#.ASN1.SEQUENCE NotBefore NotAfter
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_countryName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.PRINTABLESTR'DE'
               ⋄ ⋄ ⋄ CountryName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_organizationName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'D-FRUST GmbH'
               ⋄ ⋄ ⋄ OrganizationName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ ⋄ ⋄ AttributeType←#.ASN1.OID id_at_commonName
               ⋄ ⋄ ⋄ ⋄ Value←#.ASN1.UTF8STR'NW Auth Sub 01'
               ⋄ ⋄ ⋄ CommonName←#.ASN1.SET(#.ASN1.SEQUENCE AttributeType Value)
               ⋄ ⋄ Subject←#.ASN1.SEQUENCE CountryName OrganizationName CommonName
               ⋄ ⋄ ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_rsaEncryption
               ⋄ ⋄ ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ ⋄ ⋄ Algorithm←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ ⋄ ⋄ SubjectPublicKey←#.ASN1.BITSTRING PublicKey
               ⋄ ⋄ SubjectPublicKeyInfo←#.ASN1.SEQUENCE Algorithm SubjectPublicKey
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_basicConstraints
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE(#.ASN1.BOOLEAN #.ASN1.TRUE))
               ⋄ ⋄ ⋄ BasicConstraints←#.ASN1.SEQUENCE ExtnId(#.ASN1.BOOLEAN #.ASN1.TRUE)ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_subjectKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.OCTETSTRING(#.ASN1.PKCS1.GetKeyIdentifierFromKey PublicKey))
               ⋄ ⋄ ⋄ SubjectKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_authorityKeyIdentifier
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.SEQUENCE((#.ASN1.IMPLICIT 0)(#.ASN1.PKCS1.GetKeyIdentifierFromKey IssuerPrivateKey)))
               ⋄ ⋄ ⋄ AuthorityKeyIdentifier←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ ⋄ ⋄ ExtnId←#.ASN1.OID id_ce_keyUsage
               ⋄ ⋄ ⋄ ⋄ ExtnValue←#.ASN1.OCTETSTRING(#.ASN1.BITSTRING(0 0 0 0 0 1 1))
               ⋄ ⋄ ⋄ KeyUsage←#.ASN1.SEQUENCE ExtnId ExtnValue
               ⋄ ⋄ Extensions←(#.ASN1.CONTEXT 3)(#.ASN1.SEQUENCE BasicConstraints SubjectKeyIdentifier AuthorityKeyIdentifier KeyUsage)
               ⋄ TBSCertificate←1 #.ASN1.Code #.ASN1.SEQUENCE Version SerialNumber Signature Issuer Validity Subject SubjectPublicKeyInfo Extensions
     ⍝ Noch die Signatur darunter und das X.509-konforme Zertifikat D-FRUST ist fertig:
               ⋄ ⋄ Algorithm←#.ASN1.OID pkcs_1_sha1WithRSAEncryption
               ⋄ ⋄ Parameters←#.ASN1.NULLTAG
               ⋄ AlgorithmIdentifier←#.ASN1.SEQUENCE Algorithm Parameters
               ⋄ Signature←#.ASN1.BITSTRING(TBSCertificate #.Crypt.Sign IssuerPrivateKey #.Win.CALG_SHA1)
              Certificate←1 #.ASN1.Code #.ASN1.SEQUENCE TBSCertificate AlgorithmIdentifier Signature
            ∇

        :EndNamespace
    :EndNamespace
    :Namespace X501
        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        ∇ Name←FormatName NameList;GetFirstIndex;id_at_commonName;id_at_surname;id_at_serialNumber;id_at_organizationalUnitName;id_at_organizationName;Index
     ⍝ Extrahieren des anzeigbaren Namens aus einer NameList
     ⍝
     ⍝ NameList = Vektor von AttributeTypeAndValue (Resultat von #.ASN1.X501.ResolveName)
     ⍝ Name     = Vektor mit angezeigtem Namen
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
          GetFirstIndex←{↑{⍵/⍳⍴⍵}{⍵=⌊/⍵}⍺⍳⍵}
          id_at_commonName←2 5 4 3
          id_at_surname←2 5 4 4
          id_at_serialNumber←2 5 4 5
          id_at_organizationName←2 5 4 10
          id_at_organizationalUnitName←2 5 4 11
     ⍝
          :If ×Index←id_at_commonName id_at_surname id_at_serialNumber id_at_organizationName id_at_organizationalUnitName GetFirstIndex↑¨NameList
              Name←Index 2⊃NameList
          :Else
              Name←''
          :EndIf
        ∇

        ∇ NameList←ResolveName Name;UnivTagOptions;RelativeDistinguishedName;AttributeTypeAndValue;AttributeType;Value
     ⍝ Decodieren von Name (Issuer Subject RequestorName etc) nach RFC2459 (X.501)
     ⍝
     ⍝ Name                      = Encodierte Name Sequence
     ⍝
     ⍝ NameList                  = Vektor von AttributeTypeAndValue
     ⍝  AttributeTypeAndValue[1] = AttributeType ObjectIdentifier
     ⍝  AttributeTypeAndValue[2] = AttributeValue
     ⍝
     ⍝ On error NameList←'' ⋄ See #.RCode #.RText
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
          :If ×↑⍴Name
              ##.Init
              UnivTagOptions←##.UnivTagOptions
              UnivTagOptions[##.TAG_UTCTIME ##.TAG_GENERALIZEDTIME]←##.UTO_ZULU
              :If ##.SEQUENCE≡↑Name←¯6 UnivTagOptions ##.Code Name   ⍝ Name                      ::= CHOICE {
                  RelativeDistinguishedName←1↓Name                   ⍝     rdnSequence                   RDNSequence }
              :AndIf ∧/##.SET∘≡¨↑¨RelativeDistinguishedName          ⍝ RDNSequence               ::= SEQUENCE OF RelativeDistinguishedName
                  AttributeTypeAndValue←1↓¨RelativeDistinguishedName ⍝ RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
              :AndIf ∧/(1+2)=↑¨↑∘⍴¨¨AttributeTypeAndValue            ⍝ AttributeTypeAndValue     ::= SEQUENCE {
              :AndIf ∧/##.SEQUENCE∘≡¨↑¨↑¨¨AttributeTypeAndValue      ⍝     type                          ATTRIBUTE.&id ({SupportedAttributes}),
                  NameList←0⍴⊂⍬''                                    ⍝     value                         ATTRIBUTE.&Type ({SupportedAttributes}{@type})}
                  :For AttributeTypeAndValue :In ⌽1↓¨¨AttributeTypeAndValue
                      :For AttributeType Value :In ⌽AttributeTypeAndValue
                          :If ##.OID≢↑AttributeType
                              NameList←''
                              #.RCode←#.Win.CRYPT_E_INVALID_X500_STRING
                              :Return
                          :EndIf
                          :Select ↑Value
                          :CaseList ##.UTF8STR ##.PRINTABLESTR ##.T61STR ##.IA5STR ##.UNIVERSALSTR ##.BMPSTR ##.NUMERICSTR ##.GENERALIZEDTIME
                              NameList,←⊂(2⊃AttributeType)(2⊃Value)
                          :Case ##.SEQUENCE
                              :If 2∧.=↑∘⍴¨1↓Value
                              :AndIf ∧/∊∘##.UTF8STR ##.PRINTABLESTR ##.T61STR ##.IA5STR ##.UNIVERSALSTR ##.BMPSTR ##.NUMERICSTR ##.GENERALIZEDTIME↑¨1↓Value
                                  NameList,←⊂(2⊃AttributeType)(2⊃¨1↓Value)
                              :Else
                                  NameList←''
                                  #.RCode←#.Win.CRYPT_E_NOT_CHAR_STRING
                                  :Return
                              :EndIf
                          :Else
                              NameList←''
                              #.RCode←#.Win.CRYPT_E_NOT_CHAR_STRING
                              :Return
                          :EndSelect
                      :EndFor
                  :EndFor
              :Else
                  NameList←''
                  :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_INVALID_X500_STRING ⋄ :EndIf
              :EndIf
          :Else
              NameList←''
              :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CRYPT_E_INVALID_X500_STRING ⋄ :EndIf
          :EndIf
        ∇

    :EndNamespace
    :Namespace X509
        ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

        ∇ AlgorithmIdentifier←BuildAlgorithmIdentifier algorithm;Algorithm;Parameters
     ⍝⍝ Encodieren von AlgorithmIdentifier nach RFC3280 (PKIX.509 - Certificate and CRL Profile 4.1.1.2)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
     ⍝ mailto:Hager@Dortmund.net
          ##.Init
           ⋄ Algorithm←##.OID algorithm
           ⋄ Parameters←##.NULLTAG
          AlgorithmIdentifier←1 ##.Code ##.SEQUENCE Algorithm Parameters
        ∇

        ∇ Extensions←{ContextTag}BuildExtensions ExtensionList;Extension;extnId;critical;extnValue;ExtnId;Critical;ExtnValue
     ⍝⍝ Encodieren von Extensions (monadisch) als "Extensions::=SEQUENCE OF Extension"
     ⍝⍝                      oder  (dyadisch) als "Extensions::=[ContextTag] SEQUENCE OF Extension"
     ⍝⍝ nach RFC2459 (PKIX.509 - Certificate and CRL Profile 4.2)
     ⍝
     ⍝Y ExtensionList =           Extension oder Vektor von Extension
     ⍝   Extension[1] = ExtnId    OID der Extension als numerische Folge
     ⍝   Extension[2] = Critical  #.ASN1.TRUE oder #.ASN1.FALSE
     ⍝   Extension[3] = ExtnValue ASN.1-codierbarer oder codierter Wert der Extension
     ⍝
     ⍝X ContextTag    = Optionale Tag-Nummer des Extension CONTEXT
     ⍝
     ⍝R Extensions    = Encodierte CONTEXT Sequence
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
          ##.Init
          :If 2>≡ExtensionList
              Extensions←''
          :ElseIf 2>≡↑ExtensionList
              extnId critical extnValue←ExtensionList
               ⋄ ⋄ ⋄ ExtnId←##.OID extnId
               ⋄ ⋄ ⋄ Critical←##.BOOLEAN critical ##.DEFAULT ##.FALSE
               ⋄ ⋄ ⋄ ExtnValue←##.OCTETSTRING extnValue
               ⋄ ⋄ Extension←##.SEQUENCE ExtnId Critical ExtnValue
               ⋄ Extensions←##.SEQUENCE Extension
              :If ×⎕NC'ContextTag'
                  Extensions←(##.CONTEXT ContextTag)Extensions ##.OPTIONAL 1
              :Else
                  Extensions←Extensions ##.OPTIONAL 1
              :EndIf
              Extensions←1 ##.Code Extensions
          :Else
               ⋄ Extensions←,⊂##.SEQUENCE
              :For extnId critical extnValue :In ExtensionList
                   ⋄ ⋄ ⋄ ExtnId←##.OID extnId
                   ⋄ ⋄ ⋄ Critical←##.BOOLEAN critical ##.DEFAULT ##.FALSE
                   ⋄ ⋄ ⋄ ExtnValue←##.OCTETSTRING extnValue
                   ⋄ ⋄ Extension←##.SEQUENCE ExtnId Critical ExtnValue
                   ⋄ Extensions,←⊂Extension
              :EndFor
              :If ×⎕NC'ContextTag'
                  Extensions←(##.CONTEXT ContextTag)Extensions ##.OPTIONAL 0≠↑⍴ExtensionList
              :Else
                  Extensions←Extensions ##.OPTIONAL 0≠↑⍴ExtensionList
              :EndIf
              :If ''≢Extensions
                  Extensions←1 ##.Code Extensions
              :EndIf
          :EndIf
        ∇

        ∇ CertificateChain←GetCertificateChain CertificateCollection;Certificate;IssuerCertificates;TbsCertificate;AlgorithmIdentifier;Signature;Version;SerialNumber;SignatureAlgorithm;Issuer;Validity;Subject;SubjectPublicKeyInfo;IssuerUniqueID;SubjectUniqueID;Extensions;SubjectCertificate;FoundFlag;Flags
          :If 1<≡CertificateCollection
              Certificate←↑CertificateCollection
              IssuerCertificates←1↓CertificateCollection
          :Else
              Certificate←CertificateCollection
              IssuerCertificates←0⍴⊂''
          :EndIf
          :If 0=↑⍴IssuerCertificates
              IssuerCertificates,←#.Crypt.EnumCertStore'CA\SC'
              IssuerCertificates,←#.Crypt.EnumCertStore'Root\SC'
          :EndIf
          IssuerCertificates←∪IssuerCertificates
          CertificateChain←0⍴⊂''
          :Repeat
              :If 10=↑⍴↑TbsCertificate AlgorithmIdentifier Signature←3 ResolveCertificate Certificate
                  Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions←TbsCertificate
                  CertificateChain,←⊂Certificate
                  :If Issuer≡Subject
                      :If 1=↑⍴CertificateChain
                          CertificateChain,←⊂Certificate
                      :EndIf
                      :Return
                  :Else
                      SubjectCertificate←Certificate
                      FoundFlag←0
                      :For Certificate :In IssuerCertificates
                          :If FoundFlag←Issuer≡GetCertificateSubject Certificate
                              :Leave
                          :EndIf
                      :EndFor
                      :If FoundFlag
                      :ElseIf ×↑⍴↑Certificate Flags←#.Win.Cert.Store.GetIssuerCertificate SubjectCertificate
                      :Else
                          :Return
                      :EndIf
                  :EndIf
              :Else
                  :Return
              :EndIf
          :EndRepeat
        ∇

        ∇ Issuer←{Depth}GetCertificateIssuer Certificate;Type;Version;TbsCertificate;VxForm;GeneralNames;Index;DirectoryName;V2Form
     ⍝ Return a certificate's issuer
     ⍝
     ⍝ Certificate  = X.509 certificate structure
     ⍝ Issuer       = Name structure
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
          :If 0=⎕NC'Depth'
              Depth←1
          :EndIf
          Type Version←QueryCertificateType Certificate
          :Select Type
          :Case 1 ⍝ signature certificate
              TbsCertificate←1↓2⊃¯4 ##.Code Certificate
              Issuer←Depth ##.Code 2⊃((↑¨TbsCertificate)∊⊂##.SEQUENCE)/TbsCertificate
          :Case 2 ⍝ attribute certificate
              TbsCertificate←1↓2⊃¯5 ##.Code Certificate
              VxForm←2⊃(~(↑¨TbsCertificate)∊⊂##.INTEGER)/TbsCertificate
              :Select ↑VxForm
              :Case ##.SEQUENCE  ⍝ v1Form GeneralNames
                  GeneralNames←1↓VxForm
                  :If ∨/Index←(↑¨GeneralNames)∊⊂##.CONTEXT 4
                  :AndIf 2=↑⍴DirectoryName←↑Index/GeneralNames
                      Issuer←Depth ##.Code 2⊃DirectoryName
                  :Else
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                      Issuer←''
                  :EndIf
              :Case ##.CONTEXT 0 ⍝ v2Form [0]V2Form
                  :If ##.SEQUENCE≡↑V2Form←1↓¯3 ##.Code VxForm
                  :AndIf 2≤↑⍴V2Form
                  :AndIf ##.SEQUENCE≡↑GeneralNames←2⊃V2Form
                      GeneralNames←1↓GeneralNames
                  :AndIf ∨/Index←(↑¨GeneralNames)∊⊂##.CONTEXT 4
                  :AndIf 2=↑⍴DirectoryName←↑Index/GeneralNames
                      Issuer←Depth ##.Code 2⊃DirectoryName
                  :Else
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                      Issuer←''
                  :EndIf
              :Else
                  :If #.RCode=#.Win.ERROR_SUCCESS
                      #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                  :EndIf
                  Issuer←''
              :EndSelect
          :Else
              :If #.RCode=#.Win.ERROR_SUCCESS
                  #.RCode←#.Win.CRYPT_E_BAD_ENCODE
              :EndIf
              Issuer←''
          :EndSelect
         
     ⍝ AttributeCertificateInfo ::= SEQUENCE {..
     ⍝   subject            CHOICE {
     ⍝     baseCertificateID  [0] EXPLICIT IssuerSerial,
     ⍝     subjectName        [1] EXPLICIT GeneralNames,
     ⍝     holder             Holder},
     ⍝   issuer             CHOICE {
     ⍝     v1Form             GeneralNames,
     ⍝     v2Form             [0] V2Form},   ..}
         
     ⍝ GeneralNames ::= SEQUENCE OF GeneralName
     ⍝ GeneralName ::= CHOICE {
     ⍝   otherName                 [0] OtherName,
     ⍝   rfc822Name                [1] IA5String,
     ⍝   dNSName                   [2] IA5String,
     ⍝   x400Address               [3] ORAddress,
     ⍝   directoryName             [4] Name,
     ⍝   ediPartyName              [5] EDIPartyName,
     ⍝   uniformResourceIdentifier [6] IA5String,
     ⍝   iPAddress                 [7] OCTET STRING,
     ⍝   registeredID              [8] OBJECT IDENTIFIER}
         
     ⍝ V2Form ::= SEQUENCE {
     ⍝   issuerName            GeneralNames  OPTIONAL,        -- issuerName MUST be present in this profile
     ⍝   baseCertificateID     [0] IssuerSerial  OPTIONAL,    -- baseCertificateID MUST NOT be present in this profile
     ⍝   objectDigestInfo      [1] ObjectDigestInfo OPTIONAL} -- objectDigestInfo MUST NOT be present in this profile
     ⍝
         
     ⍝ IssuerSerial   ::= SEQUENCE {
     ⍝   issuer    GeneralNames,
     ⍝   serial    CertificateSerialNumber,
     ⍝   issuerUID UniqueIdentifier OPTIONAL }
        ∇

        ∇ Subject←{Depth}GetCertificateSUBJECT Certificate;Type;Version;TbsCertificate;Holder;GeneralNames;Index;DirectoryName;V2Form
     ⍝ Return a certificate's subject
     ⍝
     ⍝ Certificate  = X.509 certificate structure
     ⍝ Subject      = Name structure
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
          :If 0=⎕NC'Depth'
              Depth←1
          :EndIf
          Type Version←QueryCertificateType Certificate
          :Select Type
          :Case 1 ⍝ signature certificate
              TbsCertificate←1↓2⊃¯4 ##.Code Certificate
              Subject←Depth ##.Code 4⊃((↑¨TbsCertificate)∊⊂##.SEQUENCE)/TbsCertificate
          :Case 2 ⍝ attribute certificate
              TbsCertificate←1↓2⊃¯5 ##.Code Certificate
              Holder←1⊃(~(↑¨TbsCertificate)∊⊂##.INTEGER)/TbsCertificate
              :Select ↑Holder
              :Case ##.SEQUENCE  ⍝ holder Holder
         
     ⍝ Holder ::= SEQUENCE {
     ⍝   baseCertificateID   [0] IssuerSerial OPTIONAL,     -- the issuer and serial number of the holder's Public Key Certificate
     ⍝   entityName          [1] GeneralNames OPTIONAL,     -- the name of the claimant or role
     ⍝   objectDigestInfo    [2] ObjectDigestInfo OPTIONAL} -- used to directly authenticate the holder, for example, an executable
         
                  GeneralNames←1↓Holder
                  :If ∨/Index←(↑¨GeneralNames)∊⊂##.CONTEXT 4
                  :AndIf 2=↑⍴DirectoryName←↑Index/GeneralNames
                      Subject←Depth ##.Code 2⊃DirectoryName
                  :Else
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                      Subject←''
                  :EndIf
              :Case ##.CONTEXT 0 ⍝ baseCertificateID [0]IssuerSerial
         
     ⍝ IssuerSerial   ::= SEQUENCE {
     ⍝   issuer    GeneralNames,
     ⍝   serial    CertificateSerialNumber,
     ⍝   issuerUID UniqueIdentifier OPTIONAL }
         
                  :If ##.SEQUENCE≡↑GeneralNames←1↓¯3 ##.Code Holder
                  :AndIf 2≤↑⍴GeneralNames
                  :AndIf ##.SEQUENCE≡↑GeneralNames←2⊃GeneralNames
                      GeneralNames←1↓GeneralNames
                  :AndIf ∨/Index←(↑¨GeneralNames)∊⊂##.CONTEXT 4
                  :AndIf 2=↑⍴DirectoryName←↑Index/GeneralNames
                      Subject←Depth ##.Code 2⊃DirectoryName
                  :Else
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                      Subject←''
                  :EndIf
         
         
              :Case ##.CONTEXT 1 ⍝ subjectName [1]GeneralNames
                  :If ##.SEQUENCE≡↑GeneralNames←1↓¯3 ##.Code Holder
                  :AndIf 2≤↑⍴GeneralNames
                  :AndIf ##.SEQUENCE≡↑GeneralNames←2⊃GeneralNames
                      GeneralNames←1↓GeneralNames
                  :AndIf ∨/Index←(↑¨GeneralNames)∊⊂##.CONTEXT 4
                  :AndIf 2=↑⍴DirectoryName←↑Index/GeneralNames
                      Subject←Depth ##.Code 2⊃DirectoryName
                  :Else
                      :If #.RCode=#.Win.ERROR_SUCCESS
                          #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                      :EndIf
                      Subject←''
                  :EndIf
              :Else
                  :If #.RCode=#.Win.ERROR_SUCCESS
                      #.RCode←#.Win.CRYPT_E_BAD_ENCODE
                  :EndIf
                  Subject←''
              :EndSelect
          :Else
              :If #.RCode=#.Win.ERROR_SUCCESS
                  #.RCode←#.Win.CRYPT_E_BAD_ENCODE
              :EndIf
              Subject←''
          :EndSelect
         
     ⍝ AttributeCertificateInfo ::= SEQUENCE {..
     ⍝   subject            CHOICE {
     ⍝     holder             Holder,
     ⍝     baseCertificateID  [0] EXPLICIT IssuerSerial,
     ⍝     subjectName        [1] EXPLICIT GeneralNames},..}
         
     ⍝ IssuerSerial   ::= SEQUENCE {
     ⍝   issuer    GeneralNames,
     ⍝   serial    CertificateSerialNumber,
     ⍝   issuerUID UniqueIdentifier OPTIONAL }
         
     ⍝ GeneralNames ::= SEQUENCE OF GeneralName
     ⍝ GeneralName ::= CHOICE {
     ⍝   otherName                 [0] OtherName,
     ⍝   rfc822Name                [1] IA5String,
     ⍝   dNSName                   [2] IA5String,
     ⍝   x400Address               [3] ORAddress,
     ⍝   directoryName             [4] Name,
     ⍝   ediPartyName              [5] EDIPartyName,
     ⍝   uniformResourceIdentifier [6] IA5String,
     ⍝   iPAddress                 [7] OCTET STRING,
     ⍝   registeredID              [8] OBJECT IDENTIFIER}
         
     ⍝ Holder ::= SEQUENCE {
     ⍝   baseCertificateID   [0] IssuerSerial OPTIONAL,     -- the issuer and serial number of the holder's Public Key Certificate
     ⍝   entityName          [1] GeneralNames OPTIONAL,     -- the name of the claimant or role
     ⍝   objectDigestInfo    [2] ObjectDigestInfo OPTIONAL} -- used to directly authenticate the holder, for example, an executable
        ∇

        ∇ SerialNumber←{UtoInteger}GetCertificateSerialNumber Certificate;Type;Version;TbsCertificate;IntegerIndex
     ⍝ Return a certificate's serial number
     ⍝
     ⍝ Certificate  = X.509 certificate structure
     ⍝ UtoInteger   = Integer Tag Options, combination of #.ASN1.UTO_STR #.ASN1.UTO_FMT(def) or #.ASN1.UTO_HEX+#.ASN1.UTO_I32 #.ASN1.UTO_I48(def) or #.ASN1.UTO_I53
     ⍝
     ⍝ SerialNumber = serial number of the certificate
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
          ##.Init
          :If 0=⎕NC'UtoInteger'
              UtoInteger←##.UTO_FMT+##.UTO_I48
          :EndIf
          Type Version←QueryCertificateType Certificate
          :If Type∊1 2
              TbsCertificate←1↓2⊃¯4(⍬ UtoInteger)##.Code Certificate
              IntegerIndex←{↑⌽⍵/⍳⍴⍵}(↑¨TbsCertificate)∊⊂##.INTEGER
              SerialNumber←IntegerIndex 2⊃TbsCertificate
          :Else
              :If #.RCode=#.Win.ERROR_SUCCESS
                  #.RCode←#.Win.CRYPT_E_BAD_ENCODE
              :EndIf
              SerialNumber←''
          :EndIf
        ∇

        ∇ Subject←{Depth}GetCertificateSubject Certificate;TbsCertificate;AlgorithmIdentifier;Signature;Version;SerialNumber;SignatureAlgorithm;Issuer;Validity;SubjectPublicKeyInfo;IssuerUniqueID;SubjectUniqueID;Extensions;FormattedSubject
          :If 0=⎕NC'Depth'
              Depth←3
          :EndIf
          :If 10=↑⍴↑TbsCertificate AlgorithmIdentifier Signature←Depth ResolveCertificate Certificate
              Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions←TbsCertificate
          :Else
              Subject←''
          :EndIf
        ∇

        ∇ SubjectPublicKey←GetCertificateSubjectPublicKey Certificate;TbsCertificate;AlgorithmIdentifier;Signature;Version;SerialNumber;SignatureAlgorithm;Issuer;Validity;Subject;SubjectPublicKeyInfo;IssuerUniqueID;SubjectUniqueID;Extensions;FormattedSubject;Algorithm
     ⍝ Return the PKCS#1 encoded SubjectPublicKey from a Certificate
     ⍝ May get resolved with "#.ASN1.UTO_FMT #.ASN1.PKCS1.KeyDecode SubjectPublicKey"
          :If 10=↑⍴↑TbsCertificate AlgorithmIdentifier Signature←5 ResolveCertificate Certificate
              Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions←TbsCertificate
          :AndIf 2=↑⍴SubjectPublicKeyInfo
              Algorithm SubjectPublicKey←SubjectPublicKeyInfo
              SubjectPublicKey←1 ##.Code SubjectPublicKey
          :Else
              SubjectPublicKey←''
          :EndIf
        ∇

        ∇ Validity←{Depth}GetCertificateValidity Certificate;TbsCertificate;AlgorithmIdentifier;Signature;Version;SerialNumber;SignatureAlgorithm;Issuer;Subject;SubjectPublicKeyInfo;IssuerUniqueID;SubjectUniqueID;Extensions;FormattedSubject
          :If 0=⎕NC'Depth'
              Depth←5
          :EndIf
          :If 10=↑⍴↑TbsCertificate AlgorithmIdentifier Signature←Depth ResolveCertificate Certificate
              Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions←TbsCertificate
          :Else
              Validity←(0 0 0 0 0 0 0)(0 0 0 0 0 0 0)
          :EndIf
        ∇

        ∇ Retrn←QueryCertificateType Certificate;v1;v2;v3;TbsCertificate;TbsSequenceCount;VersionContent;VersionInfo;Type;Version
     ⍝ Check the type and version of a certificate
     ⍝
     ⍝ Certificate = X.509 signature certificate or attribute certificate structure
     ⍝
     ⍝ Retrn[1]    = Type:    0=unknown 1=signature certificate 2=attribute certificate
     ⍝ Retrn[2]    = Version: 0=v1 1=v2 2=v3
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2003
          ##.Init
          v1←0 ⋄ v2←1 ⋄ v3←2
          :If ##.SEQUENCE≡↑Certificate←¯5 ##.Code Certificate
          :AndIf ##.SEQUENCE ##.SEQUENCE ##.BITSTRING≡↑¨Certificate←1↓Certificate
              TbsSequenceCount←↑⍴TbsCertificate←1↓↑Certificate
          :AndIf 6≤TbsSequenceCount
          :AndIf 10≥TbsSequenceCount
              :Select (7⌊TbsSequenceCount)↑↑¨TbsCertificate
              :Case ##.INTEGER ##.SEQUENCE ##.SEQUENCE ##.SEQUENCE ##.SEQUENCE ##.SEQUENCE
                  Type←1 ⋄ Version←0
              :Case (##.CONTEXT 0)##.INTEGER ##.SEQUENCE ##.SEQUENCE ##.SEQUENCE ##.SEQUENCE ##.SEQUENCE
                  :If 2=↑⍴VersionContent←↑TbsCertificate
                  :AndIf ##.INTEGER≡↑VersionInfo←2⊃VersionContent
                      Type←1 ⋄ Version←2⊃VersionInfo
                      :Select 7↓↑¨TbsCertificate
                      :CaseList (0⍴⊂##.CONTEXT 0)(,⊂##.CONTEXT 1)(,⊂##.CONTEXT 2)((##.CONTEXT 1)(##.CONTEXT 2))
                          :If Version∊v2 v3
                          :Else
                              Type←0 ⋄ Version←0
                          :EndIf
                      :CaseList (,⊂##.CONTEXT 3)((##.CONTEXT 1)(##.CONTEXT 3))((##.CONTEXT 2)(##.CONTEXT 3))((##.CONTEXT 1)(##.CONTEXT 2)(##.CONTEXT 3))
                          :If Version∊v3
                          :Else
                              Type←0 ⋄ Version←0
                          :EndIf
                      :Else
                          Type←0 ⋄ Version←0
                      :EndSelect
                  :Else
                      Type←0 ⋄ Version←0
                  :EndIf
              :Else
                  :If ##.INTEGER≢↑↑TbsCertificate
                      TbsCertificate←(⊂##.INTEGER v1),TbsCertificate
                  :EndIf
                  :Select 7↓↑¨TbsCertificate
                  :CaseList (0⍴⊂##.INTEGER)(,⊂##.BITSTRING)(,⊂##.SEQUENCE)(##.BITSTRING ##.SEQUENCE)
                      :Select ↑¨(7⌊TbsSequenceCount)↑TbsCertificate
                      :CaseList (##.INTEGER ##.SEQUENCE ##.SEQUENCE ##.SEQUENCE ##.INTEGER ##.SEQUENCE ##.SEQUENCE)(##.INTEGER(##.CONTEXT 0)##.SEQUENCE ##.SEQUENCE ##.INTEGER ##.SEQUENCE ##.SEQUENCE)(##.INTEGER(##.CONTEXT 1)##.SEQUENCE ##.SEQUENCE ##.INTEGER ##.SEQUENCE ##.SEQUENCE)
                          Type←2 ⋄ Version←2⊃VersionInfo←↑TbsCertificate
                      :Else
                          Type←0 ⋄ Version←0
                      :EndSelect
                  :Else
                      Type←0 ⋄ Version←0
                  :EndSelect
              :EndSelect
          :Else
              Type←0 ⋄ Version←0
          :EndIf
          Retrn←Type Version
        ∇

        ∇ Content←Parms ResolveCertificate Certificate;Depth;TbsCertificate;AlgorithmIdentifier;Signature;TbsCertificate3;Version;SerialNumber;SignatureAlgorithm;Issuer;Validity;Subject;SubjectPublicKeyInfo;IssuerUniqueID;SubjectUniqueID;Extensions;Algorithm;Parameters;AlgorithmSignature;ParametersSignature;NotBefore;NotAfter;SubjectAlgorithm;SubjectPublicKey;AlgorithmSubject;ParametersSubject;PublicKey
     ⍝ Resolve an X.509 certificate into a nested structure
     ⍝
     ⍝ Certificate X.509 certificate as ASN.1 sequence or APL nested structure
     ⍝
     ⍝ Parms[1] =  Depth          See #.ASN1.Code for details
     ⍝ Parms[2] =  UnivTagOptions See #.ASN1.Code for details (optional)
     ⍝
     ⍝ Content  =  Certificate, resolved "Depth" levels deep:
     ⍝
     ⍝ Depth=1  :  Certificate←Content
     ⍝
     ⍝ Depth≥2  :  TbsCertificate AlgorithmIdentifier Signature←Content
     ⍝
     ⍝ Depth≥3  :  Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions←TbsCertificate
     ⍝             Algorithm Parameters←AlgorithmIdentifier
     ⍝
     ⍝ Depth≥4  :  AlgorithmSignature ParametersSignature←SignatureAlgorithm
     ⍝             NotBefore NotAfter←Validity
     ⍝             SubjectAlgorithm SubjectPublicKey←SubjectPublicKeyInfo
     ⍝
     ⍝ Depth≥5  :  AlgorithmSubject ParametersSubject←SubjectAlgorithm
     ⍝
     ⍝ Upon error the result is all ''
     ⍝ Check #.RCode and #.RText for further information.
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
          Depth←|↑Parms
          :If 1=Depth
              Content←Certificate
          :ElseIf (1+3)=↑⍴Certificate←Parms ##.Code Certificate
          :AndIf ##.SEQUENCE≡↑Certificate
               ⋄ TbsCertificate AlgorithmIdentifier Signature←1↓Certificate
              :If 2=Depth
                  Content←TbsCertificate AlgorithmIdentifier Signature
              :ElseIf (1+6)≤↑⍴TbsCertificate
              :AndIf ##.SEQUENCE≡↑TbsCertificate
                  :If 3≤≡TbsCertificate
                      TbsCertificate3←TbsCertificate
                  :Else
                      TbsCertificate3←3 ##.Code TbsCertificate
                  :EndIf
                  :If ~(⊂##.CONTEXT 0)∊↑¨1↓TbsCertificate3                             ⍝ Check for Version
                      TbsCertificate←((1+0)↑TbsCertificate),(⊂''),(1+0)↓TbsCertificate ⍝ Insert as '' if not there
                  :EndIf
                  :If ~(⊂##.CLASS_CONTEXT ##.FORM_PRIMITIVE 1)∊↑¨1↓TbsCertificate3     ⍝ Check for IssuerUniqueID
                      TbsCertificate←((1+7)↑TbsCertificate),(⊂''),(1+7)↓TbsCertificate ⍝ Insert as '' if not there
                  :EndIf
                  :If ~(⊂##.CLASS_CONTEXT ##.FORM_PRIMITIVE 2)∊↑¨1↓TbsCertificate3     ⍝ Check for SubjectUniqueID
                      TbsCertificate←((1+8)↑TbsCertificate),(⊂''),(1+8)↓TbsCertificate ⍝ Insert as '' if not there
                  :EndIf
                  :If ~(⊂##.CONTEXT 3)∊↑¨1↓TbsCertificate3                             ⍝ Check for Extensions
                      TbsCertificate←((1+9)↑TbsCertificate),(⊂''),(1+9)↓TbsCertificate ⍝ Insert as '' if not there
                  :EndIf
              :AndIf (1+10)=↑⍴TbsCertificate                                           ⍝ Now we can assign all ten fields at once
                   ⋄ ⋄ Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions←1↓TbsCertificate
              :AndIf (1+2)=↑⍴AlgorithmIdentifier
              :AndIf ##.SEQUENCE≡↑AlgorithmIdentifier
                   ⋄ ⋄ Algorithm Parameters←1↓AlgorithmIdentifier
              :AndIf ##.BITSTRING≡↑Signature
                   ⋄ ⋄ Signature←↑1↓Signature
                  :If 3=Depth
                      Content←(Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions)(Algorithm Parameters)Signature
                  :ElseIf (0∊⍴Version)∨(##.CONTEXT 0)≡↑Version
                      :If 0∊⍴Version
                           ⋄ ⋄ ⋄ Version←''
                      :Else
                           ⋄ ⋄ ⋄ Version←↑1↓Version
                      :EndIf
                  :AndIf ##.INTEGER≡↑SerialNumber
                       ⋄ ⋄ ⋄ SerialNumber←↑1↓SerialNumber
                  :AndIf (1+2)=↑⍴SignatureAlgorithm
                  :AndIf ##.SEQUENCE≡↑SignatureAlgorithm
                       ⋄ ⋄ ⋄ AlgorithmSignature ParametersSignature←1↓SignatureAlgorithm
                  :AndIf ##.SEQUENCE≡↑Issuer
                       ⋄ ⋄ ⋄ Issuer←1↓Issuer
                  :AndIf (1+2)=↑⍴Validity
                  :AndIf ##.SEQUENCE≡↑Validity
                       ⋄ ⋄ ⋄ NotBefore NotAfter←1↓Validity
                  :AndIf ##.SEQUENCE≡↑Subject
                       ⋄ ⋄ ⋄ Subject←1↓Subject
                  :AndIf (1+2)=↑⍴SubjectPublicKeyInfo
                  :AndIf ##.SEQUENCE≡↑SubjectPublicKeyInfo
                       ⋄ ⋄ ⋄ SubjectAlgorithm SubjectPublicKey←1↓SubjectPublicKeyInfo
                  :AndIf (0∊⍴IssuerUniqueID)∨(⊂##.CLASS_CONTEXT ##.FORM_PRIMITIVE 1)≡↑IssuerUniqueID
                      :If 0∊⍴IssuerUniqueID
                           ⋄ ⋄ ⋄ IssuerUniqueID←''
                      :Else
                           ⋄ ⋄ ⋄ IssuerUniqueID←↑1↓IssuerUniqueID
                      :EndIf
                  :AndIf (0∊⍴SubjectUniqueID)∨(⊂##.CLASS_CONTEXT ##.FORM_PRIMITIVE 2)≡↑SubjectUniqueID
                      :If 0∊⍴SubjectUniqueID
                           ⋄ ⋄ ⋄ SubjectUniqueID←''
                      :Else
                           ⋄ ⋄ ⋄ SubjectUniqueID←↑1↓SubjectUniqueID
                      :EndIf
                  :AndIf (0∊⍴Extensions)∨(##.CONTEXT 3)≡↑Extensions
                      :If 0∊⍴Extensions
                           ⋄ ⋄ ⋄ Extensions←''
                      :Else
                           ⋄ ⋄ ⋄ Extensions←↑1↓Extensions
                      :EndIf
                  :AndIf ##.OID≡↑Algorithm
                       ⋄ ⋄ ⋄ Algorithm←↑1↓Algorithm
                  :AndIf ∊∘(↑##.NULLTAG)##.SEQUENCE⊂↑Parameters
                      :If ##.NULLTAG≡Parameters
                           ⋄ ⋄ ⋄ Parameters←''
                      :Else
                           ⋄ ⋄ ⋄ Parameters←1↓Parameters
                      :EndIf
                      :If 4=Depth
                          Content←(Version SerialNumber(AlgorithmSignature ParametersSignature)Issuer(NotBefore NotAfter)Subject(SubjectAlgorithm SubjectPublicKey)IssuerUniqueID SubjectUniqueID Extensions)(Algorithm Parameters)Signature
                      :ElseIf (0∊⍴Version)∨##.INTEGER≡↑Version
                          :If 0∊⍴Version
                               ⋄ ⋄ ⋄ ⋄ Version←0
                          :Else
                               ⋄ ⋄ ⋄ ⋄ Version←↑1↓Version
                          :EndIf
                      :AndIf ##.OID≡↑AlgorithmSignature
                           ⋄ ⋄ ⋄ ⋄ AlgorithmSignature←↑1↓AlgorithmSignature
                      :AndIf ∊∘(↑##.NULLTAG)##.SEQUENCE⊂↑ParametersSignature
                          :If ##.NULLTAG≡ParametersSignature
                               ⋄ ⋄ ⋄ ⋄ ParametersSignature←''
                          :Else
                               ⋄ ⋄ ⋄ ⋄ ParametersSignature←1↓ParametersSignature
                          :EndIf
                      :AndIf ∧/##.SET∘≡¨↑¨Issuer
                           ⋄ ⋄ ⋄ ⋄ Issuer←1↓¨Issuer
                      :AndIf ∊∘##.UTCTIME ##.GENERALIZEDTIME⊂↑NotBefore
                           ⋄ ⋄ ⋄ ⋄ NotBefore←↑1↓NotBefore
                      :AndIf ∊∘##.UTCTIME ##.GENERALIZEDTIME⊂↑NotAfter
                           ⋄ ⋄ ⋄ ⋄ NotAfter←↑1↓NotAfter
                      :AndIf ∧/##.SET∘≡¨↑¨Subject
                           ⋄ ⋄ ⋄ ⋄ Subject←1↓¨Subject
                      :AndIf (1+2)=↑⍴SubjectAlgorithm
                      :AndIf ##.SEQUENCE≡↑SubjectAlgorithm
                           ⋄ ⋄ ⋄ ⋄ AlgorithmSubject ParametersSubject←1↓SubjectAlgorithm
                      :AndIf ##.BITSTRING≡↑SubjectPublicKey
                           ⋄ ⋄ ⋄ ⋄ PublicKey←↑1↓SubjectPublicKey
                      :AndIf (0∊⍴Extensions)∨##.SEQUENCE≡↑Extensions
                          :If 0∊⍴Extensions
                               ⋄ ⋄ ⋄ ⋄ Extensions←''
                          :Else
                               ⋄ ⋄ ⋄ ⋄ Extensions←1↓Extensions
                          :EndIf
                          :If 5=Depth
                              Content←(Version SerialNumber(AlgorithmSignature ParametersSignature)Issuer(NotBefore NotAfter)Subject((AlgorithmSubject ParametersSubject)PublicKey)IssuerUniqueID SubjectUniqueID Extensions)(Algorithm Parameters)Signature
                          :ElseIf ∧/(1+2)=↑¨↑∘⍴¨¨Issuer
                          :AndIf ∧/##.SEQUENCE∘≡¨↑¨↑¨¨Issuer
                               ⋄ ⋄ ⋄ ⋄ ⋄ Issuer←1↓¨¨Issuer
                          :AndIf ∧/(1+2)=↑¨↑∘⍴¨¨Subject
                          :AndIf ∧/##.SEQUENCE∘≡¨↑¨↑¨¨Subject
                               ⋄ ⋄ ⋄ ⋄ ⋄ Subject←1↓¨¨Subject
                          :AndIf ##.OID≡↑AlgorithmSubject
                               ⋄ ⋄ ⋄ ⋄ ⋄ AlgorithmSubject←↑1↓AlgorithmSubject
                          :AndIf ∊∘(↑##.NULLTAG)##.SEQUENCE⊂↑ParametersSubject
                              :If ##.NULLTAG≡ParametersSubject
                                   ⋄ ⋄ ⋄ ⋄ ⋄ ParametersSubject←''
                              :Else
                                   ⋄ ⋄ ⋄ ⋄ ⋄ ParametersSubject←1↓ParametersSubject
                              :EndIf
                          :AndIf ##.SEQUENCE≡↑PublicKey
                               ⋄ ⋄ ⋄ ⋄ ⋄ PublicKey←2↑1↓PublicKey
                          :AndIf (0∊⍴Extensions)∨∧/##.SEQUENCE∘≡¨↑¨Extensions
                              :If 0∊⍴Extensions
                                   ⋄ ⋄ ⋄ ⋄ ⋄ Extensions←''
                              :Else
                                   ⋄ ⋄ ⋄ ⋄ ⋄ Extensions←1↓¨Extensions
                              :EndIf
                              :If 6=Depth
                                  Content←(Version SerialNumber(AlgorithmSignature ParametersSignature)Issuer(NotBefore NotAfter)Subject((AlgorithmSubject ParametersSubject)PublicKey)IssuerUniqueID SubjectUniqueID Extensions)(Algorithm Parameters)Signature
                              :ElseIf ∧/##.OID∘≡¨↑¨↑¨¨↑¨¨¨Issuer
                              :AndIf ∧/∊∘##.UTF8STR ##.PRINTABLESTR ##.T61STR ##.IA5STR ##.UNIVERSALSTR ##.BMPSTR↑¨↑∘⌽¨¨↑¨¨¨Issuer
                                   ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ Issuer←↑¨¨¨1↓¨¨¨Issuer
                              :AndIf ∧/##.OID∘≡¨↑¨↑¨¨↑¨¨¨Subject
                                   ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ Subject←↑¨¨¨1↓¨¨¨Subject
                              :AndIf ∧/##.INTEGER∘≡¨↑¨PublicKey
                                   ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ PublicKey←↑¨1↓¨PublicKey
                              :AndIf ∧/∊∘(##.OID ##.OCTETSTRING)(##.OID ##.BOOLEAN ##.OCTETSTRING)↑¨¨Extensions
                                   ⋄ ⋄ ⋄ ⋄ ⋄ ⋄ Extensions←{2=↑⍴⍵:(1↑⍵),0,1↓⍵ ⋄ ⍵}¨↑¨¨1↓¨¨Extensions
                                  Content←(Version SerialNumber(AlgorithmSignature ParametersSignature)Issuer(NotBefore NotAfter)Subject((AlgorithmSubject ParametersSubject)PublicKey)IssuerUniqueID SubjectUniqueID Extensions)(Algorithm Parameters)Signature
                              :Else
                                  #.RCode←#.Win.CERT_E_MALFORMED
                                  Content←'' '' ''
                              :EndIf
                          :Else
                              #.RCode←#.Win.CERT_E_MALFORMED
                              Content←'' '' ''
                          :EndIf
                      :Else
                          #.RCode←#.Win.CERT_E_MALFORMED
                          Content←'' '' ''
                      :EndIf
                  :Else
                      #.RCode←#.Win.CERT_E_MALFORMED
                      Content←'' '' ''
                  :EndIf
              :Else
                  #.RCode←#.Win.CERT_E_MALFORMED
                  Content←'' '' ''
              :EndIf
          :Else
              #.RCode←#.Win.CERT_E_MALFORMED
              Content←'' '' ''
          :EndIf
        ∇

        ∇ ExtensionList←{ContextTag}ResolveExtensions Extensions;v3;Certificate;TbsCertificate;ExtensionContext
     ⍝⍝ Decodieren von Extensions (monadisch) aus einem X.509v3-Zertifikat
     ⍝⍝                      oder (monadisch) aus "Extensions::=SEQUENCE OF Extension"
     ⍝⍝                      oder  (dyadisch) aus "Extensions::=[ContextTag] SEQUENCE OF Extension"
     ⍝⍝ nach RFC2459 (PKIX.509 - Certificate and CRL Profile 4.2)
     ⍝
     ⍝Y Extensions    = Encodierte (CONTEXT) Sequence oder X.509v3-Zertifikat
     ⍝
     ⍝X ContextTag    = Optionale Tag-Nummer des Extension CONTEXT
     ⍝
     ⍝R ExtensionList =           Vektor von Extension
     ⍝   Extension[1] = ExtnId    OID der Extension als numerische Folge
     ⍝   Extension[2] = Critical  #.ASN1.TRUE oder #.ASN1.FALSE
     ⍝   Extension[3] = ExtnValue ASN.1-codierter Wert der Extension
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
          v3←2
          :If ×↑⍴Extensions
              :If 0=⎕NC'ContextTag'
                  Extensions←¯4 ##.Code Extensions
                  :If ##.SEQUENCE≡↑Certificate←Extensions
                  :AndIf 3=↑⍴Certificate←1↓Certificate
                  :AndIf ##.SEQUENCE≡↑TbsCertificate←↑Certificate
                  :AndIf (##.CONTEXT 0)≡↑↑TbsCertificate←1↓TbsCertificate
                  :AndIf 8≤↑⍴TbsCertificate
                  :AndIf 10≥↑⍴TbsCertificate
                  :AndIf (1+1)=↑⍴ExtensionContext←(⍴TbsCertificate)⊃TbsCertificate
                  :AndIf (##.CONTEXT 3)≡↑ExtensionContext
                      Extensions←¯4 ##.Code 2⊃ExtensionContext
                  :EndIf
              :ElseIf 2=↑⍴Extensions←¯5 ##.Code Extensions
              :AndIf (##.CONTEXT ContextTag)≡↑Extensions
                  Extensions←2⊃Extensions
              :Else
                  ExtensionList←''
                  :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CERT_E_MALFORMED ⋄ :EndIf
                  :Return
              :EndIf
              :If ##.SEQUENCE≡↑Extensions
                   ⋄ Extensions←1↓Extensions
              :AndIf ∧/##.SEQUENCE∘≡¨↑¨Extensions
                   ⋄ ⋄ Extensions←1↓¨Extensions
              :AndIf ∧/∊∘(##.OID ##.OCTETSTRING)(##.OID ##.BOOLEAN ##.OCTETSTRING)↑¨¨Extensions
                   ⋄ ⋄ ⋄ ExtensionList←{2=↑⍴⍵:(1↑⍵),0,1↓⍵ ⋄ ⍵}¨↑¨¨1↓¨¨Extensions
              :Else
                  ExtensionList←''
                  :If #.RCode=#.Win.ERROR_SUCCESS ⋄ #.RCode←#.Win.CERT_E_MALFORMED ⋄ :EndIf
              :EndIf
          :Else
              ExtensionList←0⍴⊂⍬ 0 ''
              #.RCode←#.Win.ERROR_SUCCESS
          :EndIf
        ∇

        ∇ ValidFlags←VerifyCertificateChain Certificates;SelectCertificatePairs;SubjectCertificate;IssuerCertificate;TbsCertificate;AlgorithmIdentifier;Signature;Version;SerialNumber;SignatureAlgorithm;Issuer;Validity;Subject;SubjectPublicKeyInfo;IssuerUniqueID;SubjectUniqueID;Extensions;SubjectTbsCertificate;AlgorithmSignature;ParametersSignature;Algid;RCode
          SelectCertificatePairs←{0∊⍴⍵:0⍴⊂'' '' ⋄ ⍵∘{⍺[⍵]}¨{⍵⌊0 1∘+¨⍳⍵}↑⍴⍵}
          ValidFlags←⍬
          RCode←#.Win.ERROR_SUCCESS
          :For SubjectCertificate IssuerCertificate :In SelectCertificatePairs Certificates
              :If (GetCertificateIssuer SubjectCertificate)≡GetCertificateSubject IssuerCertificate
                  TbsCertificate AlgorithmIdentifier Signature←2 ResolveCertificate SubjectCertificate
                  SubjectTbsCertificate←TbsCertificate
                  :If 10=↑⍴↑TbsCertificate AlgorithmIdentifier Signature←0 ResolveCertificate SubjectCertificate
                      Version SerialNumber SignatureAlgorithm Issuer Validity Subject SubjectPublicKeyInfo IssuerUniqueID SubjectUniqueID Extensions←TbsCertificate
                      AlgorithmSignature ParametersSignature←SignatureAlgorithm
                  :AndIf ''≡ParametersSignature
                  :AndIf 0≠Algid←#.Crypt.OidToAlgid AlgorithmSignature
                  :AndIf SubjectTbsCertificate #.Crypt.VerifySignature IssuerCertificate Signature Algid
                      ValidFlags,←1
                  :Else
                      ValidFlags,←0
                      :If RCode=#.Win.ERROR_SUCCESS ⋄ RCode←#.RCode ⋄ :EndIf
                  :EndIf
              :Else
                  ValidFlags,←0
                  :If RCode=#.Win.ERROR_SUCCESS ⋄ RCode←#.Win.CERT_E_ISSUERCHAINING ⋄ :EndIf
              :EndIf
          :EndFor
          #.RCode←RCode
        ∇

        :Namespace Extension
            ⎕IO ⎕ML ⎕WX ⎕CT←1 3 1 9.999999999999998E¯15

            ∇ AuthorityKeyIdentifier←ResolveAuthorityKeyIdentifier ExtensionList;id_ce_authorityKeyIdentifier;KeyIdentifier;AuthorityCertIssuer;AuthorityCertSerialNumber;Index;Content;ClassFormTag;Class;Form;Tag;Value
     ⍝ Get the AuthorityKeyIdentifier from a Certificate or its ExtensionList
     ⍝
     ⍝ AuthorityKeyIdentifier[1] = KeyIdentifier             (Hash of Issuer PublicKey)
     ⍝ AuthorityKeyIdentifier[1] = AuthorityCertIssuer       Vector out of these elements: (0 OtherName)(1 Rfc822Name)(2 DNSName)(3 X400Address)(4 DirectoryName)(5 EdiPartyName)(6 UniformResourceIdentifier)(7 IPAddress)(8 RegisteredID)
     ⍝ AuthorityKeyIdentifier[1] = AuthorityCertSerialNumber Integer or formatted numeric string
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
              id_ce_authorityKeyIdentifier←2 5 29 35
              KeyIdentifier←''
              AuthorityCertIssuer←0⍴⊂0 ''
              AuthorityCertSerialNumber←''
              :If 3>≡ExtensionList
                  ExtensionList←##.ResolveExtensions ExtensionList
              :EndIf
              :If ''≢ExtensionList
              :AndIf (↑⍴ExtensionList)≥Index←(↑¨ExtensionList)⍳⊂id_ce_authorityKeyIdentifier
              :AndIf ##.##.SEQUENCE≡↑Content←¯4 ##.##.Code Index 3⊃ExtensionList
                  :For Content :In 1↓Content
                      Value←1↓Content
                      :Select ↑Content
                      :Case ##.##.CLASS_CONTEXT ##.##.FORM_PRIMITIVE 0   ⍝ KeyIdentifier
                          KeyIdentifier←↑Value
                      :Case ##.##.CLASS_CONTEXT ##.##.FORM_CONSTRUCTED 1 ⍝ AuthorityCertIssuer
                          :For ClassFormTag Value :In Value
                              Class Form Tag←ClassFormTag
                              :If Class≡##.##.CLASS_CONTEXT
                                  AuthorityCertIssuer,←⊂Tag Value
                              :EndIf
                          :EndFor
                      :Case ##.##.CLASS_CONTEXT ##.##.FORM_PRIMITIVE 2   ⍝ AuthorityCertSerialNumber
                          AuthorityCertSerialNumber←2⊃0(⍬(##.##.UTO_I48+##.##.UTO_FMT))##.##.Code 1(⍬ ##.##.UTO_STR)##.##.Code ##.##.INTEGER(↑Value)
                      :EndSelect
                  :EndFor
              :EndIf
              AuthorityKeyIdentifier←KeyIdentifier AuthorityCertIssuer AuthorityCertSerialNumber
            ∇

            ∇ IssuerAltName←ResolveIssuerAltName ExtensionList;id_ce_issuerAltName;Index;Content;ClassFormTag;Class;Form;Tag;Value
     ⍝ Get the IssuerAltName from a Certificate or its ExtensionList
     ⍝
     ⍝ SubjectAltName = Vector out of these elements: (0 OtherName)(1 Rfc822Name)(2 DNSName)(3 X400Address)(4 DirectoryName)(5 EdiPartyName)(6 UniformResourceIdentifier)(7 IPAddress)(8 RegisteredID)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
              id_ce_issuerAltName←2 5 29 18
              IssuerAltName←0⍴⊂0 ''
              :If 3>≡ExtensionList
                  ExtensionList←##.ResolveExtensions ExtensionList
              :EndIf
              :If ''≢ExtensionList
              :AndIf (↑⍴ExtensionList)≥Index←(↑¨ExtensionList)⍳⊂id_ce_issuerAltName
              :AndIf ##.##.SEQUENCE≡↑Content←¯3 ##.##.Code Index 3⊃ExtensionList
                  :For ClassFormTag Value :In 1↓Content
                      Class Form Tag←ClassFormTag
                      :If Class≡##.##.CLASS_CONTEXT
                          IssuerAltName,←⊂Tag Value
                      :EndIf
                  :EndFor
              :EndIf
            ∇

            ∇ KeyUsage←ResolveKeyUsage ExtensionList;id_ce_keyUsage;Index;Content
     ⍝ Get the KeyUsage from a Certificate or its ExtensionList
     ⍝
     ⍝ KeyUsage = Nummeric vector with these possible elements: 0=DigitalSignature 1=NonRepudiation 2=KeyEncipherment 3=DataEncipherment 4=KeyAgreement 5=KeyCertSign 6=CRLSign 7=EncipherOnly 8=DecipherOnly
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
              id_ce_keyUsage←2 5 29 15
              :If 3>≡ExtensionList
                  ExtensionList←##.ResolveExtensions ExtensionList
              :EndIf
              :If ''≢ExtensionList
              :AndIf (↑⍴ExtensionList)≥Index←(↑¨ExtensionList)⍳⊂id_ce_keyUsage
              :AndIf 2=↑⍴Content←¯2 ##.##.Code Index 3⊃ExtensionList
              :AndIf ##.##.BITSTRING≡↑Content
                  KeyUsage←{¯1+⍵/⍳⍴⍵}2⊃Content
              :Else
                  KeyUsage←⍬
              :EndIf
            ∇

            ∇ SubjectAltName←ResolveSubjectAltName ExtensionList;id_ce_subjectAltName;Index;Content;ClassFormTag;Class;Form;Tag;Value
     ⍝ Get the SubjectAltName from a Certificate or its ExtensionList
     ⍝
     ⍝ SubjectAltName = Vector out of these elements: (0 OtherName)(1 Rfc822Name)(2 DNSName)(3 X400Address)(4 DirectoryName)(5 EdiPartyName)(6 UniformResourceIdentifier)(7 IPAddress)(8 RegisteredID)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
              id_ce_subjectAltName←2 5 29 17
              SubjectAltName←0⍴⊂0 ''
              :If 3>≡ExtensionList
                  ExtensionList←##.ResolveExtensions ExtensionList
              :EndIf
              :If ''≢ExtensionList
              :AndIf (↑⍴ExtensionList)≥Index←(↑¨ExtensionList)⍳⊂id_ce_subjectAltName
              :AndIf ##.##.SEQUENCE≡↑Content←¯3 ##.##.Code Index 3⊃ExtensionList
                  :For ClassFormTag Value :In 1↓Content
                      Class Form Tag←ClassFormTag
                      :If Class≡##.##.CLASS_CONTEXT
                          SubjectAltName,←⊂Tag Value
                      :EndIf
                  :EndFor
              :EndIf
            ∇

            ∇ SubjectKeyIdentifier←ResolveSubjectKeyIdentifier ExtensionList;id_ce_subjectKeyIdentifier;Index;Content
     ⍝ Get the SubjectKeyIdentifier from a Certificate or its ExtensionList
     ⍝
     ⍝ SubjectKeyIdentifier = KeyIdentifier (Hash of Subject PublicKey)
     ⍝
     ⍝ (c) Peter-Michael Hager, Dortmund (Germany) 2002
     ⍝ mailto:Hager@Dortmund.net
              id_ce_subjectKeyIdentifier←2 5 29 14
              :If 3>≡ExtensionList
                  ExtensionList←##.ResolveExtensions ExtensionList
              :EndIf
              :If ''≢ExtensionList
              :AndIf (↑⍴ExtensionList)≥Index←(↑¨ExtensionList)⍳⊂id_ce_subjectKeyIdentifier
              :AndIf 2=↑⍴Content←¯2 ##.##.Code Index 3⊃ExtensionList
              :AndIf ##.##.OCTETSTRING≡↑Content
                  SubjectKeyIdentifier←2⊃Content
              :Else
                  SubjectKeyIdentifier←''
              :EndIf
            ∇

        :EndNamespace
    :EndNamespace
:EndNamespace
