from OpenSSL import crypto
import hashlib
from dateutil import parser
import tldextract
from app.util import *

# List of attributes that we need to parse
inserted_list = ['serial_number', 'subject_key_identifier', 'public_key_sha1', 'public_key_sha256', 'der_sha1',
    '_id', 'not_before', 'not_after','signature_algorithm', 'version', 'country', 'organization', 'locality_name',
    'common_name', 'organizational_unit_name', 'state_or_province_name', 'email_address', 'business_category', 'issuer_id',
    'issuer_serial_number', 'issuer_country', 'issuer_organization', 'issuer_locality_name', 'issuer_common_name',
    'issuer_organizational_unit_name', 'issuer_state_or_province_name', 'issuer_email_address', 'issuer_business_category',
    'subject_alt_name', 'dns_san', 'email_san', 'ip_san', 'is_ct_precert', 'basic_constraints', 'authority_key_identifier',
    'key_usage', 'crl_distribution_points', 'extended_key_usage', 'authority_info_access', 'ct_precert_poison',
    'ct_precert_scts', 'is_ca', 'slds', 'ips', 'emails', 'domains'
    ]

# Name Switcher
subject_switcher = {
    'c': 'country',
    'o': 'organization',
    'l': 'locality_name',
    'cn': 'common_name',
    'ou': 'organizational_unit_name',
    'st': 'state_or_province_name',
    'dc': 'domain_component',
    'emailaddress': 'email_address',
    'businesscategory': 'business_category',
    'serialnumber': 'serial_number',
    'street': "street",
    'postalcode': 'postal_code',
    'postofficebox': 'post_office_box',
    'organizationidentifier': 'organization_identifier'
}

issuer_switcher = {
    'c': 'issuer_country',
    'o': 'issuer_organization',
    'l': 'issuer_locality_name',
    'cn': 'issuer_common_name',
    'ou': 'issuer_organizational_unit_name',
    'st': 'issuer_state_or_province_name',
    'dc': 'issuer_domain_component',
    'emailaddress': 'issuer_email_address',
    'businesscategory': 'issuer_business_category',
    'serialnumber': 'issuer_serial_number',
    'street': "issuer_street",
    'postalcode': 'postal_code'
}

extension_switcher = {
    'subjectaltname': 'subject_alt_name',
    'subject_alternative_name': 'subject_alt_name',
    'basicconstraints': 'basic_constraints',
    'subjectkeyidentifier': 'subject_key_identifier',
    'authoritykeyidentifier': 'authority_key_identifier',
    'extendedkeyusage': 'extended_key_usage',
    'authorityinfoaccess': 'authority_info_access',
    'keyusage': 'key_usage',
    'certificatepolicies': 'certificate_policies',
    'crldistributionpoints': 'crl_distribution_points',
    'crl_distribution_points': 'crl_distribution_points',
    'privatekeyusageperiod': 'private_key_usage_period',
    'policymappings': 'policy_mappings',
    'policyconstraints': 'policy_constraints',
    'subjectinfoaccess': 'subject_info_access',
    'ct_precert_scts': 'ct_precert_scts',
    'ct_precert_poison': 'ct_precert_poison'
}

oid_switcher = {
    '2.5.4.3': 'common_name',
    '2.5.4.5': 'serial_number',
    '2.5.4.6': 'country_name',
    '2.5.4.7': 'locality_name',
    '2.5.4.8': 'state_or_province_name',
    '2.5.4.9': 'street_address',
    '2.5.4.10': 'organization',
    '2.5.4.11': 'organizational_unit_name',
    '2.5.4.15': 'business_category',
    '2.5.29.14': 'subject_key_identifier',
    '2.5.29.15': 'key_usage',
    '2.5.29.17': 'subject_alt_name',
    '2.5.29.18': 'issuer_alt_name',
    '2.5.29.19': 'basic_constraint',
    '1.2.840.113549.1.9.1': 'email_address',
    '1.3.6.1.4.1.311.60.2.1.3': 'country_name',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption'
}

san_switcher = {
    'DNS': 'dns_san',
    'IP Address': 'ip_san',
    'email': "email_san"
}

certPolicy_switcher = {
    'Policy': 'policy_oid',
    'CPS': 'cert_policies_pointer',
    'User Notice': 'user_notice_text'
}

crlDistribution_switcher = {
    'Full Name': 'full_name',
    'URI': 'crl_distribution_uri',
    'Relative Name': 'relative_name',
    'DirName': 'dir_name'
}

crlDirName_switcher = {
    'C': 'crl_issuer_country',
    'O': 'crl_issuer_organization',
    'L': 'crl_issuer_locality_name',
    'CN': 'crl_issuer_common_name',
    'OU': 'crl_issuer_organizational_unit_name',
    'ST': 'crl_issuer_state_or_province_name',
    'emailaddress': 'crl_issuer_email_address',
    'businesscategory': 'crl_issuer_business_category',
    'serialnumber': 'crl_issuer_serial_number',
    'street': "crl_issuer_street"
}

def parse_attribute_detail(cert_json):
    """
    Parse each certificate attributes dict in detail
    :param cert_json: certificate info dict
    :return: detailed info dict
    """
    all_domain_list = []
    all_sld_list = []
    all_ip_list = []
    all_email_list = []

    # Subject Alternative Name
    if cert_json.get("subject_alt_name"):
        SANlist = cert_json["subject_alt_name"].split(", ")
        othersans = {}
        for san in SANlist:
            try:
                key = san.strip().split(":")[0]
                value = san.strip().split(":")[1]
                key = san_switcher.get(key, key)
                if key == "dns_san":
                    if cert_json.get(key):
                        cert_json[key].append(value)
                    else:
                        cert_json[key] = [value]
                    ret = tldextract.extract(value)

                    if ret.fqdn:
                        all_domain_list.append(ret.fqdn)
                        all_sld_list.append(ret.registered_domain)
                elif key == "ip_san":
                    if cert_json.get(key):
                        cert_json[key].append(value)
                    else:
                        cert_json[key] = [value]
                    ret = tldextract.extract(value)
                    if ret.ipv4:
                        all_ip_list.append(ret.ipv4)
                elif key == 'email_san':
                    if cert_json.get(key):
                        cert_json[key].append(value)
                    else:
                        cert_json[key] = [value]
                    all_email_list.append(value)
                else:
                    if othersans.get(key):
                        othersans[key].append(value)
                    else:
                        othersans[key] = [value]

            except Exception as e:
                print("Parse SAN detail error: {}".format(e.args[0]))
        if othersans:
            cert_json["subject_alt_name"] = othersans

    # Subject Common Name
    if cert_json.get("common_name"):
        cn = cert_json["common_name"]
        ret = tldextract.extract(cn)
        if ret.fqdn:
            all_domain_list.append(ret.fqdn)
            all_sld_list.append(ret.registered_domain)
        elif ret.ipv4:
            all_ip_list.append(cn)

    # Subject emailAddress
    if cert_json.get("email_address"):
        email = cert_json["email_address"]
        all_email_list.append(email)

    ### Domain List & sld list & IP List & email list
    if all_domain_list:
        cert_json["domains"] = list(set(all_domain_list))
    if all_sld_list:
        cert_json["slds"] = list(set(all_sld_list))
    if all_ip_list:
        cert_json["ips"] = list(set(all_ip_list))
    if all_email_list:
        cert_json["emails"] = list(set(all_email_list))

    # Other Extensions
    if cert_json.get("basic_constraints"):
        if cert_json['basic_constraints'].startswith("CA:TRUE, pathlen:"):
            cert_json["is_ca"] = True
            idx = cert_json['basic_constraints'].find("pathlen")
            cert_json["pathlen"] = int(cert_json['basic_constraints'][idx + 8:])
        elif cert_json['basic_constraints'].startswith("CA:TRUE"):
            cert_json["is_ca"] = True
        elif cert_json['basic_constraints'].startswith("CA:FALSE"):
            cert_json["is_ca"] = False
        else:
            print("cert:{}, new basic_constraints:{}".format(cert_json["_id"], cert_json["basic_constraints"]))

    if cert_json.get("subject_key_identifier"):
        ski = cert_json["subject_key_identifier"].replace(":", "").lower()
        cert_json["subject_key_identifier"] = ski

    if cert_json.get("ct_precert_poison"):
        cert_json["is_ct_precert"] = True

    if cert_json.get("ct_precert_scts"):
        cert_json["is_ct_precert"] = True

    # Ignore below
    #TODO: other attributes to parse, some are not finished yet.
    if cert_json.get("authority_key_identifier"):
        aki = cert_json["authority_key_identifier"].replace("keyid:","").replace(":","").lower()
        cert_json["authority_key_identifier"] = aki

    if cert_json.get("key_usage"):
        usage_list = []
        ret = cert_json["key_usage"].split(", ")
        for usage in ret:
            usage_list.append(usage)
        cert_json["key_usage"] = list(set(usage_list))

    if cert_json.get("extended_key_usage"):
        ext_usage_list = []
        ret = cert_json["extended_key_usage"].split(", ")
        for usage in ret:
            ext_usage_list.append(usage)
        cert_json["extended_key_usage"] = list(set(ext_usage_list))

    if cert_json.get("certificate_policies"):
        policy_list = {}
        ret = cert_json['certificate_policies'].split(", ")
        for item in ret:
            try:
                l = item.split(": ")
                if len(l) > 1:
                    key = l[0].strip()
                    value = l[1].strip()
                    key = certPolicy_switcher.get(key, key)
                    policy_list[key] = value
            except:
                continue
        cert_json["certificate_policies"] = policy_list

    if cert_json.get("crl_distribution_points"):
        ret = cert_json['crl_distribution_points'].split(", ")
        for item in ret:
            try:
                i = item.find(":")
                if not i:
                    continue
                key = item[:i].strip()
                value = item[i+1:].strip()
                key = crlDistribution_switcher.get(key, key)
                if key == "crl_distribution_uri":
                    cert_json[key] = value
            except:
                continue

    if cert_json.get("private_key_usage_period"):
        privkey_period = cert_json["private_key_usage_period"]
        if privkey_period.startswith("Not After:"):
            cert_json["priv_key_usg_not_after"] = privkey_period[4:]
        elif privkey_period.startswith("Not Before:"):
            cert_json["priv_key_usg_not_before"] = privkey_period[4:]
        else:
            print ("cert:{}, certificate private key usage period:{}".format(cert_json["_id"], cert_json["private_key_usage_period"]))


    if cert_json.get("policy_mappings"):
        policymp_list = []
        ret = cert_json['policy_mappings'].split(",")
        for item in ret:
            policymp_list.append(item.strip())
        cert_json['policy_mappings'] = policymp_list

    if cert_json.get("policy_constraints"):
        policyConstraint_list = {}
        ret = cert_json["policy_constraints"].split(", ")
        for item in ret:
            try:
                key = item.split(":")[0]
                value = int(item.split(":")[1])
                policyConstraint_list[key] = value
            except:
                print ("cert:{}, policy_constraints error: {}".format(cert_json["_id"], cert_json["policy_constraints"]))
        cert_json["policy_constraints"] = policyConstraint_list

    if cert_json.get("subject_info_access"):
        carepo = {}
        i = cert_json["subject_info_access"].find("URI")
        carepo["CARepository"]  = cert_json["subject_info_access"][i+4:]
        cert_json["subject_info_access"] = carepo

    if cert_json.get("authority_info_access"):
        aia_info = {}
        ret = cert_json["authority_info_access"].split(",")
        for item in ret:
            item = item.strip()
            if item.startswith("CA Issuer"):
                i = item.find("URI")
                aia_info["CAIssuer"] = item[i+4:]
            elif item.startswith("OCSP"):
                i = item.find("URI")
                aia_info["OCSP"] = item[i + 4:]
        cert_json["authority_info_access"] = aia_info

    return cert_json


def parse_certinfo(cert):
    """
    parse the information of an X.509 certificate
    :param cert: The X509 object (e.g., crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string))
    :return: certificate attributes dict
    """
    cert_json = dict()

    # get basic information from a certificate
    cert_json["version"] = cert.get_version()

    # subject
    subjects = cert.get_subject().get_components()
    for subject in subjects:
        try:
            key = subject_switcher.get(subject[0].decode().lower(), "subject_" + subject[0].decode().lower())
            if key in inserted_list:
                try:
                    value = subject[1].decode().lower()
                except:
                    value = subject[1].lower()
                cert_json[key] = value
        except Exception as e:
            print(e)
            continue

    # issuer
    issuerinfos = cert.get_issuer().get_components()
    for issuerinfo in issuerinfos:
        try:
            key = issuer_switcher.get(issuerinfo[0].decode().lower(), "issuer_" + issuerinfo[0].decode().lower())
            if key in inserted_list:
                value = issuerinfo[1].decode().lower()
                cert_json[key] = value

        except Exception as e:
            print(e)
            key = issuer_switcher.get(issuerinfo[0].decode(), "issuer_" + issuerinfo[0].decode())
            if key in inserted_list:
                value = issuerinfo[1].lower()
                cert_json[key] = value
            continue

    notbefore_datetime = parser.parse(cert.get_notBefore())
    cert_json["not_before"] = notbefore_datetime.strftime('%Y-%m-%d %H:%M:%S')

    notafter_datetime = parser.parse(cert.get_notAfter())
    cert_json["not_after"] = notafter_datetime.strftime('%Y-%m-%d %H:%M:%S')

    cert_json['life_time'] = (notafter_datetime - notbefore_datetime).days
    cert_json["serial_number"] = hex(cert.get_serial_number())[2:]
    cert_json["signature_algorithm"] = cert.get_signature_algorithm().decode()

    # public key
    pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
    hasher = hashlib.sha1()
    hasher.update(pubkey)
    cert_json["public_key_sha1"] = hasher.hexdigest()
    hasher = hashlib.sha256()
    hasher.update(pubkey)
    cert_json["public_key_sha256"] = hasher.hexdigest()

    # der hash
    der_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    hasher = hashlib.sha1()
    hasher.update(der_cert)
    cert_json["der_sha1"] = hasher.hexdigest()

    # extensions
    e_count = cert.get_extension_count()
    if e_count > 0:
        for i in range(0, e_count):
            try:
                extension = cert.get_extension(i)
                ext_name = extension.get_short_name().decode().lower()
                ext_name = extension_switcher.get(ext_name, ext_name)
                ext_str = extension.__str__().strip("\n").replace("\n", ",")
                # ext_bytes = extension.get_data() # The ASN.1 encoded data of this X509 extension
                if ext_name in inserted_list:
                    cert_json[ext_name] = ext_str
            except:
                continue

    new_cert_json = parse_attribute_detail(cert_json)
    return new_cert_json

def parse_certinfo_from_text(cert_text):
    """
    parse the information of certificate text file
    :param cert_text: the text certificate
    :return: certificate attributes dict
    """
    cert_json = {}

    lines = cert_text.split("\n")
    for i in range(len(lines)):
        try:
            line = lines[i].strip()
            if line.startswith("Version: "):
                cert_json["version"] = line.split(" ")[1]
            elif line.startswith("Subject: "):  # subject
                subjects = line[9:].split(',')
                for sub in subjects:
                    try:
                        sub = sub.strip()
                        key = sub.split('=')[0]
                        value = sub.split('=')[1].lower()
                        key = subject_switcher.get(key, "subject_" + key)
                        if key in inserted_list:
                            cert_json[key] = value
                    except Exception as e:
                        continue
                        print("subject", sub, e)
            elif line.startswith("Issuer: "):  # issuer
                issuerinfos = line[9:].split(',')
                for issuerinfo in issuerinfos:
                    try:
                        issuer = issuerinfo.strip()
                        key = issuer.split('=')[0]
                        value = issuer.split('=')[1].lower()
                        key = issuer_switcher.get(key, "issuer_" + key)
                        if key in inserted_list:
                            cert_json[key] = value
                        cert_json[key] = value
                    except Exception as e:
                        continue
                        print("issuer", issuer, e)
            elif line.startswith("Not Before"):
                datetime_notbefore = parser.parse(line.split(': ')[1])  # datetime type
                cert_json["not_before"] = datetime_notbefore.strftime('%Y-%m-%d %H:%M:%S')
            elif line.startswith("Not After"):
                datetime_notafter = parser.parse(line.split(': ')[1])  # datetime type
                cert_json["not_after"] = datetime_notafter.strftime('%Y-%m-%d %H:%M:%S')
            elif line.startswith("Serial Number: "):
                sn = re.findall(r'.*\((.*)\).*', line)
                cert_json["serial_number"] = sn[0][2:]
            elif line.startswith("Signature Algorithm: "):
                cert_json["signature_algorithm"] = line[21:]
            elif line.startswith("X509v3 extensions:"):  ## extensions
                continue
            elif line.startswith("X509v3 "):
                ext_name = line[7:].split(":")[0].replace(" ", '_').lower()
                ext_name = extension_switcher.get(ext_name, ext_name)
                ext_str = lines[i + 1].strip()
                if ext_name in inserted_list:
                    cert_json[ext_name] = ext_str
        except Exception as e:
            print(e)

    if cert_json.get("not_before") and cert_json.get("not_after"):
        cert_json['life_time'] = (datetime_notafter - datetime_notbefore).days
    else:
        cert_json['life_time'] = None

    new_cert_json = parse_attribute_detail(cert_json)
    return new_cert_json

def parse_certinfo_from_wireshark_obj(cert):
    """
    parse the origianl information from the wireshark certificate object
    :param cert: cert json from wireshark
    :return: cert attributes dict
    """
    cert = cert['x509af.signedCertificate_element']
    cert_json = {}

    # before
    cert_json["der_md5"] = None  # DerMD5
    cert_json["der_sha1"] = None  # DerSHA1
    cert_json["public_key_sha1"] = None
    cert_json["public_key_sha256"] = None
    if cert.get('x509af.version'):
        cert_json["version"] = cert['x509af.version']
    else:
        cert_json["version"] = None

    # signature algorithm
    try:
        oid = cert['x509af.signature_element']['x509af.algorithm.id']
        cert_json['signature_algorithm'] = oid_switcher.get(oid, oid)
    except:
        cert_json['signature_algorithm'] = None

    # subject
    try:
        subjects = cert['x509af.subject_tree']['x509af.rdnSequence_tree']['x509if.RDNSequence_item_tree']
    except:
        subjects = []
    if isinstance(subjects, dict):
        subjects = [subjects]
    for l in subjects:
        try:
            key = l['x509if.RelativeDistinguishedName_item_element']['x509if.id']
            key = oid_switcher.get(key, key)
            if key == "country_name":
                value = l['x509if.RelativeDistinguishedName_item_element']['x509sat.CountryName']
            elif key == "email_address":
                value = l['x509if.RelativeDistinguishedName_item_element']['x509sat.IA5String']
            elif key == "serial_number":
                value = l['x509if.RelativeDistinguishedName_item_element']['x509sat.PrintableString']
            else:
                tree = l['x509if.RelativeDistinguishedName_item_element']['x509sat.DirectoryString_tree']
                if tree.get('x509sat.uTF8String'):
                    value = tree['x509sat.uTF8String']
                elif tree.get('x509sat.printableString'):
                    value = tree['x509sat.printableString']
            cert_json[key] = value
        except Exception as e:
            print(f"subject error: {e.args}")

    # issuer
    try:
        issuers = cert['x509af.issuer_tree']['x509if.rdnSequence_tree']['x509if.RDNSequence_item_tree']
    except:
        issuers = []
    if isinstance(issuers, dict):
        issuers = [issuers]
    for l in issuers:
        try:
            key = l['x509if.RelativeDistinguishedName_item_element']['x509if.id']
            key = oid_switcher.get(key, key)
            if key == "country_name":
                value = l['x509if.RelativeDistinguishedName_item_element']['x509sat.CountryName']
            elif key == "email_address":
                value = l['x509if.RelativeDistinguishedName_item_element']['x509sat.IA5String']
            elif key == "serial_number":
                value = l['x509if.RelativeDistinguishedName_item_element']['x509sat.PrintableString']
            else:
                tree = l['x509if.RelativeDistinguishedName_item_element']['x509sat.DirectoryString_tree']
                if tree.get('x509sat.uTF8String'):
                    value = tree['x509sat.uTF8String']
                elif tree.get('x509sat.printableString'):
                    value = tree['x509sat.printableString']

            cert_json['issuer_' + key] = value
        except Exception as e:
            print(f"issuer error: {e.args}")

    # extension
    try:
        extensions = cert['x509af.extensions_tree']['x509af.Extension_element']
    except:
        extensions = []
    if isinstance(extensions, dict):
        extensions = [extensions]
    for l in extensions:
        try:
            oid = l['x509af.extension.id']
            key = oid_switcher.get(oid, oid)
            if key == "subject_alt_name":
                sans = l['x509ce.GeneralNames_tree']['x509ce.GeneralName_tree']
                if isinstance(sans, dict):
                    sans = [sans]
                for san in sans:
                    if san.get('x509ce.dNSName'):
                        if cert_json.get('domains'):
                            cert_json['domains'].append(san['x509ce.dNSName'])
                        else:
                            cert_json['domains'] = [san['x509ce.dNSName']]
            elif key == 'basic_constraint':
                if l.get('x509af.critical'):
                    cert_json['isCA'] = 1
                else:
                    cert_json['isCA'] = 0

        except Exception as e:
            print(f"extension error: {e.args}")

    try:
        # validity
        nb = cert['x509af.validity_element']['x509af.notBefore_tree']['x509af.utcTime'].replace(' (UTC)', '')
        datetime_notbefore = parser.parse(nb, yearfirst=True)  # datetime type
        cert_json["not_before"] = datetime_notbefore.strftime('%Y-%m-%d %H:%M:%S')

        na = cert['x509af.validity_element']['x509af.notAfter_tree']['x509af.utcTime'].replace(' (UTC)', '')
        datetime_notafter = parser.parse(na, yearfirst=True)  # datetime type
        cert_json["not_after"] = datetime_notafter.strftime('%Y-%m-%d %H:%M:%S')
        cert_json['life_time'] = (datetime_notafter - datetime_notbefore).days
    except Exception as e:
        print(f"certinfo error: {e.args}")

    return cert_json




def parse_ct_entry(leaf_path, extra_path):
    """
    Parse the Merkle Tree of a CT entry
    :param leaf_path: path to .leaf file
    :param extra_path: path to .extra file
    :return: the chain of certificate info_dict
    """
    try:
        f=open(leaf_path,"rb")
        f_e=open(extra_path,"rb")
    except:
        print("File Error: can not been open")
        f.close()
        f_e.close()
        return

    leaf_cert = MerkleTreeHeader.parse(f.read())
    leaf_timestamp = leaf_cert.Timestamp

    cert_chain=[]
    if leaf_cert.LogEntryType == "X509LogEntryType":
        ### We have a normal x509 entry
        cert_data_string = Certificate.parse(leaf_cert.Entry).CertData
        cert_chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data_string)]

        ### Parse the `extra_data` structure for the rest of the chain
        extra_data = CertificateChain.parse(f_e.read())
        for cert in extra_data.Chain:
            cert_chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
    else:
        ### We have a precert entry
        extra_data = PreCertEntry.parse(f_e.read())
        cert_chain = [crypto.load_certificate(crypto.FILETYPE_ASN1, extra_data.LeafCert.CertData)]
        for cert in extra_data.Chain:
            cert_chain.append(crypto.load_certificate(crypto.FILETYPE_ASN1, cert.CertData))
    f_e.close()
    f.close()

    ###start to get information from certificate chains
    n = 0
    output_chain = []
    for certobj in cert_chain:
        n = n+1
        cert_json={}
        ###get cert infos
        try:
            cert_json = parse_certinfo(certobj)
        except Exception as e:
            print("Unexpected error:{}".format(e.args[0]))
            continue
        output_chain.append(cert_json)
    return output_chain
