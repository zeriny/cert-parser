import os
from OpenSSL import crypto
import xlrd
import hashlib
from dateutil import parser
import tldextract



class CertHelper():
    def __init__(self):
        self.inserted_list = ['serial_number', 'subject_key_identifier', 'public_key_sha1', 'public_key_sha256', 'der_sha1',
            '_id', 'not_before', 'not_after','signature_algorithm', 'version', 'country', 'organization', 'locality_name', 
            'common_name', 'organizational_unit_name', 'state_or_province_name', 'email_address', 'business_category', 'issuer_id',
            'issuer_serial_number', 'issuer_country', 'issuer_organization', 'issuer_locality_name', 'issuer_common_name',
            'issuer_organizational_unit_name', 'issuer_state_or_province_name', 'issuer_email_address', 'issuer_business_category', 
            'subject_alt_name', 'dns_san', 'email_san', 'ip_san', 'is_ct_precert', 'basic_constraints', 'authority_key_identifier', 
            'key_usage', 'crl_distribution_points', 'extended_key_usage', 'authority_info_access', 'ct_precert_poison', 
            'ct_precert_scts', 'is_ca', 'slds', 'ips', 'emails', 'domains'
            ]

        ## 名称转换
        self.subject_switcher = {
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

        self.issuer_switcher = {
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

        self.extension_switcher = {
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

        self.oid_switcher = {
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

        self.san_switcher = {
            'DNS': 'dns_san',
            'IP Address': 'ip_san',
            'email': "email_san"
        }

        self.certPolicy_switcher = {
            'Policy': 'policy_oid',
            'CPS': 'cert_policies_pointer',
            'User Notice': 'user_notice_text'
        }

        self.crlDistribution_switcher = {
            'Full Name': 'full_name',
            'URI': 'crl_distribution_uri',
            'Relative Name': 'relative_name',
            'DirName': 'dir_name'
        }

        self.crlDirName_switcher = {
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


    

    # parse the information of a TLS certificate
    def parse_certinfo(self, cert):
        cert_json = {}

        ### get basic information from a certificate
        cert_json["version"] = cert.get_version()

        ## subject
        subjects = cert.get_subject().get_components()
        for subject in subjects:
            try:
                key = self.subject_switcher.get(subject[0].decode().lower(), "subject_" + subject[0].decode().lower())
                if key in self.inserted_list:
                    try:
                        value = subject[1].decode().lower()
                    except:
                        value = subject[1].lower()
                    cert_json[key] = value
            except Exception as e:
                print(e)
                continue

        ## issuer
        issuerinfos = cert.get_issuer().get_components()
        for issuerinfo in issuerinfos:
            try:
                key = self.issuer_switcher.get(issuerinfo[0].decode().lower(), "issuer_" + issuerinfo[0].decode().lower())
                if key in self.inserted_list:
                    value = issuerinfo[1].decode().lower()
                    cert_json[key] = value

            except Exception as e:
                print(e)
                key = self.issuer_switcher.get(issuerinfo[0].decode(), "issuer_" + issuerinfo[0].decode())
                if key in self.inserted_list:
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

        ## public key
        pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, cert.get_pubkey())
        hasher = hashlib.sha1()
        hasher.update(pubkey)
        cert_json["public_key_sha1"] = hasher.hexdigest()
        hasher = hashlib.sha256()
        hasher.update(pubkey)
        cert_json["public_key_sha256"] = hasher.hexdigest()

        ## der hash
        der_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        hasher = hashlib.sha1()
        hasher.update(der_cert)
        cert_json["der_sha1"] = hasher.hexdigest()

        ## extensions
        e_count = cert.get_extension_count()
        if e_count > 0:
            for i in range(0, e_count):
                try:
                    extension = cert.get_extension(i)
                    ext_name = extension.get_short_name().decode().lower()
                    ext_name = self.extension_switcher.get(ext_name, ext_name)
                    ext_str = extension.__str__().strip("\n").replace("\n", ",")  
                    # ext_bytes = extension.get_data() # The ASN.1 encoded data of this X509 extension
                    if ext_name in self.inserted_list:
                        cert_json[ext_name] = ext_str
                except:
                    continue

        new_cert_json = self.parse_attribute_detail(cert_json)

        return new_cert_json

    ### parse each attribute in detail
    def parse_attribute_detail(self, cert_json):
        all_domain_list = []
        all_sld_list = []
        all_ip_list = []
        all_email_list = []

        #### Subject Alternative Name
        if cert_json.get("subject_alt_name"):
            SANlist = cert_json["subject_alt_name"].split(", ")
            knownSANnames = ["DirName", "othername", "URI"]
            othersans = {}
            for san in SANlist:
                try:
                    key = san.strip().split(":")[0]
                    value = san.strip().split(":")[1]
                    key = self.san_switcher.get(key, key)
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
                        if key not in knownSANnames:
                            with open("./newkeys/SAN.txt", 'a+') as fd:
                                fd.write("{}\n".format(key))

                except Exception as e:
                    print("Parse SAN detail error: {}".format(e.args[0]))
            if othersans:
                cert_json["subject_alt_name"] = othersans

        ### Subject Common Name
        if cert_json.get("common_name"):
            cn = cert_json["common_name"]
            ret = tldextract.extract(cn)
            if ret.fqdn:
                all_domain_list.append(ret.fqdn)
                all_sld_list.append(ret.registered_domain)
            elif ret.ipv4:
                all_ip_list.append(cn)

        ### Subject emailAddress
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

        ### Other Extensions
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

        #### 下面的先忽略掉
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
                        key = self.certPolicy_switcher.get(key, key)
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
                    key = self.crlDistribution_switcher.get(key, key)
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



if __name__ == "__main__":
    cert_file = "test.der"
    with open(cert_file, 'rb') as fd:
        cert = fd.read()
    cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

    ch = CertHelper()
    cert_info = ch.parse_certinfo(cert_obj)
    print (cert_info)

