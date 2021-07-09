import whois
from flask import current_app
import requests
import re
import json
from datetime import datetime
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from shodan import Shodan
import traceback
from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute

app= current_app

#let's import for the same place for everything
from lib import IP_REGEX, DOMAIN_REGEX,EMAIL_REGEX,SHA_REGEX,SHA512_REGEX,MD5_REGEX,ATTACK_REGEX, URL_REGEX, CVE_REGEX
#IP_REGEX = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
#DOMAIN_REGEX = r'(?:(?:[\da-zA-Z])(?:[_\w-]{,62})\.){,127}(?:(?:[\da-zA-Z])[_\w-]{,61})?(?:[\da-zA-Z]\.(?:(?:xn\-\-[a-zA-Z\d]+)|(?:[a-zA-Z\d]{2,})))'
#EMAIL_REGEX = r'\S+@\S+\.\S+'
#SHA_REGEX=r'[A-Fa-f0-9]{64}'
#MD5_REGEX=r'[A-Fa-f0-9]{32}'
#SHA512_REGEX=r'[A-Fa-f0-9]{128}'
#ATTACK_REGEX=r'T\d{4}'
#URL_REGEX = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
#CVE_REGEX = r'CVE\-\d{4}\-\w+'

def enrich_indicator(data):
    indicator=data.get('indicator')
    otx_api_key=data.get('av_api_key')
    shodan_api_key=data.get('shodan_api_key')
    riskiq_username=data.get('riskiq_username')
    riskiq_key=data.get('riskiq_api_key')
    greynoise_api_key=data.get('gn_api_key')
    emailrep_api_key=data.get('emailrep_api_key')
    vt_api_key=data.get('vt_api_key')
    misp_api_key=data.get('misp_api_key')
    misp_url=data.get('misp_url')
    hibp_api_key=data.get('hibp_api_key')
    hunter_api_key=data.get('hunter_api_key')
    
    # if you no api key on user record, get from .env
    if not otx_api_key:
        otx_api_key=app.config['OTX_API_KEY']
    if not shodan_api_key:
        shodan_api_key=app.config['SHODAN_API_KEY']
    if not riskiq_username or not riskiq_key:
        riskiq_username=app.config['RISKIQ_USERNAME']
        riskiq_key=app.config['RISKIQ_KEY']
    if not greynoise_api_key:
        greynoise_api_key=app.config['GREYNOISE_API_KEY']
    if not emailrep_api_key:
        emailrep_api_key=app.config['EMAILREP_API_KEY']
    if not vt_api_key:
        vt_api_key=app.config['VT_API_KEY']
    if not misp_api_key:
        misp_api_key=app.config['MISP_API_KEY']
    if not misp_url:
        misp_url=app.config['MISP_URL']
    if not hibp_api_key:
        hibp_api_key=app.config['HIBP_API_KEY']
    if not hunter_api_key:
        hunter_api_key=app.config['HUNTER_API_KEY']
    
    # Determine type of indicator
    ip = re.findall(IP_REGEX,indicator)
    domain = re.findall(DOMAIN_REGEX,indicator)
    attack = re.findall(ATTACK_REGEX,indicator)
    sha256 = re.findall(SHA_REGEX,indicator)
    email_address = re.findall(EMAIL_REGEX,indicator)
    md5 = re.findall(MD5_REGEX,indicator)
    sha512 = re.findall(SHA512_REGEX,indicator)
    url = re.findall(URL_REGEX, indicator)
    cve = re.findall(CVE_REGEX, indicator)

    # Depending on the type of indicator, run the different enrichment modules and update the DB with the enriched data
    update_data = {}
    
    if ip:
        update_data.update(get_ipinfo_data(indicator))
        update_data.update(get_otx_data(indicator, 'ip', otx_api_key))
        update_data.update(get_shodan_data(indicator, shodan_api_key))
        update_data.update(get_riskiq_data(indicator, riskiq_username, riskiq_key))
        update_data.update(get_greynoise_data(indicator, greynoise_api_key))
        update_data.update(get_misp_data(indicator, 'ip-src',misp_api_key, misp_url))
    
    elif email_address:
        update_data.update(get_emailrep_data(indicator, emailrep_api_key))
        update_data.update(get_misp_data(indicator, 'email-src',misp_api_key, misp_url))
        update_data.update(get_hibp_data(indicator,hibp_api_key))
        update_data.update(get_hunter_data(indicator,hunter_api_key))

    elif url:
        update_data.update(get_misp_data(indicator, 'url', misp_api_key, misp_url))
        update_data.update(get_urlscan_data(indicator))

    elif domain:
        update_data.update(get_otx_data(indicator, 'domain', otx_api_key))
        update_data.update(get_riskiq_data(indicator, riskiq_username, riskiq_key))
        update_data.update(get_urlscan_data(indicator))
        update_data.update(get_whois_data(indicator))
        update_data.update(get_misp_data(indicator, 'domain', misp_api_key, misp_url))

    elif sha256 or md5 or sha512:
        update_data.update(get_vt_file_data(indicator,vt_api_key))

        if md5:
            update_data.update(get_otx_data(indicator, 'md5', otx_api_key))
            update_data.update(get_misp_data(indicator, 'md5', misp_api_key, misp_url))
        if sha256:
            update_data.update(get_otx_data(indicator, 'sha256', otx_api_key))
            update_data.update(get_misp_data(indicator, 'sha256', misp_api_key, misp_url))

    elif attack:
        update_data.update(get_attack_data(indicator))

    elif cve:
        update_data.update(get_cve_data(indicator))
        update_data.update(get_misp_data(indicator, 'vulnerability', misp_api_key, misp_url))

    if len(update_data) > 0:
        update_data.update({'last_seen':datetime.now(), 'last_updated':datetime.now()})

    return update_data

def get_cve_data(indicator):
    data = {'vuln_cvss':'','vuln_references':'','vuln_summary':'','vuln_published':'','vuln_modified':''}
    
    try:
            vuln_req = requests.get('http://cve.circl.lu/api/cve/'+indicator)
            if vuln_req.json():
                vuln_json = vuln_req.json()
                ref_list = []
                data['vuln_cvss'] = vuln_json.get('cvss')
                for item in vuln_json.get('references', []):
                    ref_list.append(item)
                data['vuln_references'] = ",".join(ref_list)
                data['vuln_summary'] = vuln_json.get('summary')
                data['vuln_published'] = vuln_json.get('Published')
                data['vuln_modified'] = vuln_json.get('Modified')
            else:
                data['vuln_cvss'] = 'None'
                data['vuln_references'] = 'None'
                data['vuln_summary'] = 'None'
                data['vuln_published'] = 'None'
                data['vuln_modified'] = 'None'
    except Exception as err:
        print('cve-search error {}'.format(traceback.format_exception(type(err), err, err.__traceback__)))
    
    return data

def get_vt_file_data(indicator, vt_api_key):
    data = {'vt_scan_date':'','vt_positives':''}

    if vt_api_key:
        try:
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': vt_api_key, 'resource': indicator}
            response = requests.get(url, params=params)
            response = response.json()
            data['vt_scan_date'] = response.get('scan_date')
            data['vt_positives'] = str(response.get('positives')) + '/' + str(response.get('total'))
        except Exception as err:
            print('Virustotal error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))

    return data

def get_hunter_data(indicator, hunter_api_key):
    data = {'hunter_result':'','hunter_score':'','hunter_disposable':'','hunter_webmail':'','hunter_mx_records':'','hunter_smtp_server':'','hunter_smtp_check':'','hunter_blocked':''}

    if hunter_api_key:
        try:
            url = 'https://api.hunter.io/v2/email-verifier'
            params = {'api_key':hunter_api_key,'email':indicator}
            hunter_request = requests.get(url, params=params)
            hunter_data = hunter_request.json()
            hunter_data = hunter_data.get('data')
            data['hunter_result'] = hunter_data.get('result')
            data['hunter_score'] = hunter_data.get('score')
            data['hunter_disposable'] = hunter_data.get('disposable')
            data['hunter_webmail'] = hunter_data.get('webmail')
            data['hunter_mx_records'] = hunter_data.get('mx_records')
            data['hunter_smtp_server'] = hunter_data.get('smtp_server')
            data['hunter_smtp_check'] = hunter_data.get('smtp_check')
            data['hunter_blocked'] = hunter_data.get('block')
    
        except Exception as err:
            print('Hunter error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))

    return data

def get_attack_data(indicator):
    data = {'attack_permissionsrequired':'','attack_name':'','attack_description':'','attack_platforms':'','attack_detection':''}

    r = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json')
    attack_library = r.json()
    for thing in attack_library.get('objects'):
        if thing.get('type') == 'attack-pattern':
            for source in thing.get('external_references'):
                if source.get('source_name') == 'mitre-attack':
                    external_id = source.get('external_id')
                    if external_id == indicator:
                        if thing.get('x_mitre_permissions_required'):
                            permissions_required = (', '.join(thing.get('x_mitre_permissions_required')))
                        else:
                            permissions_required = 'n/a'
                        name = thing.get('name')
                        description = thing.get('description')
                        detection = thing.get('x_mitre_detection')
                        if thing.get('x_mitre_platforms'):
                            platforms = (', '.join(thing.get('x_mitre_platforms')))   
                        else:
                            platforms = 'n/a'

    data['attack_permissionsrequired'] = permissions_required
    data['attack_name'] = name
    data['attack_description'] = description
    data['attack_detection'] = detection
    data['attack_platforms'] = platforms

    return data

def get_vt_url_data(indicator, vt_api_key):
    data = {'vt_scan_date':'','vt_positives':''}

    if vt_api_key:
        try:
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': vt_api_key, 'resource': indicator}
            response = requests.get(url, params=params)
            response = response.json()
            data['vt_scan_date'] = response.get('scan_date')
            data['vt_positives'] = str(response.get('positives')) + '/' + str(response.get('total'))
        except Exception as err:
            print('Virustotal error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))

    return data

def get_whois_data(indicator):
    data = {'whois_creationdate':'n/a','whois_registrar':'n/a','whois_expirationdate':'n/a','whois_nameservers':'n/a','whois_lastupdated':'n/a'}
    
    try:
        domain_details = whois.query(indicator)
        result = domain_details.__dict__
        try:
            data['whois_creationdate'] = result.get('creation_date',{}).strftime("%m/%d/%Y")
        except:
            data['whois_creationdate'] = "Unknown"
        try:
            data['whois_expiration_date'] = result.get('expiration_date',{}).strftime("%m/%d/%Y")
        except:
            data['whois_expiration_date'] = "Unknown"
        try:
            data['whois_last_updated'] = result.get('last_updated',{}).strftime("%m/%d/%Y")
        except:
            data['whois_last_updated'] = "Unknown"
        data['name_servers'] = str(result.get('name_servers',{}))
    except Exception as err:
        print('Whois error on indicator {} : {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))
     
    return data

def get_urlscan_data(indicator):
    data = {'urlscan_score':'n/a','urlscan_categories':'n/a','urlscan_tags':'n/a','urlscan_malicious':'n/a'}
    
    try:
        domain = re.findall(r'https?://([A-Za-z_0-9.-]+).*',indicator)
        domain = domain[0]

        urlscan_result = requests.get("https://urlscan.io/api/v1/search/?q=domain:"+domain)
        urlscan_result = urlscan_result.json()
        # was getting index out of range error
        if len( urlscan_result['results']) > 0:
            latest_scan = urlscan_result['results'][0]['result']
            latest_results = requests.get(latest_scan)
            latest_results = latest_results.json()
        
            data['urlscan_score'] = str(latest_results.get('verdicts', {}).get('overall', {}).get('score'))
            data['urlscan_categories'] = str(latest_results.get('verdicts', {}).get('overall', {}).get('categories'))
            data['urlscan_tags'] = str(latest_results.get('verdicts', {}).get('overall', {}).get('tags'))
            data['urlscan_malicious'] = str(latest_results.get('verdicts', {}).get('overall', {}).get('malicious'))
    except Exception as err:
        print('Urlscan error {}'.format(traceback.format_exception(type(err), err, err.__traceback__)))
    return data


def get_emailrep_data(indicator,emailrep_api_key):
    data = {'emailrep_reputation':'','emailrep_suspicious':'','emailrep_references':'',
            'emailrep_blacklisted':'','emailrep_maliciousactivity':'','emailrep_credsleaked':'','emailrep_databreach':'',
            'emailrep_first_seen':'','emailrep_last_seen':'','emailrep_domain_rep':'','emailrep_profiles':''}

    if emailrep_api_key:
            try:
                headers = {'key':emailrep_api_key}
                email_request = requests.get('https://emailrep.io/'+indicator, headers=headers)
                emailrep = email_request.json()
                data['emailrep_reputation'] = emailrep.get('reputation')
                data['emailrep_suspicious'] = emailrep.get('suspicious')
                data['emailrep_references'] = emailrep.get('references')
                data['emailrep_blacklisted'] = emailrep.get('details', {}).get('blacklisted')
                data['emailrep_maliciousactivity'] = emailrep.get('details', {}).get('malicious_activity')
                data['emailrep_credsleaked'] = emailrep.get('details',{}).get('credentials_leaked')
                data['emailrep_databreach'] = emailrep.get('details',{}).get('data_breach')
                data['emailrep_first_seen'] = emailrep.get('details',{}).get('first_seen')
                data['emailrep_last_seen'] = emailrep.get('details',{}).get('last_seen')
                data['emailrep_domain_rep'] = emailrep.get('details',{}).get('domain_reputation')
                data['emailrep_profiles'] = str(emailrep.get('details',{}).get('profiles'))
            except Exception as err:
                print('Emailrep error {}'.format(traceback.format_exception(type(err), err, err.__traceback__)))
    return data

def get_hibp_data(indicator, hibp_api_key):
    data = {'hibp_breaches':''}

    if hibp_api_key:
        headers = {'hibp-api-key':hibp_api_key}
        hibp_data = requests.get('https://haveibeenpwned.com/api/v3/breachedaccount/'+indicator,headers=headers)
        
        hibp_json = hibp_data.json()
        breaches = []
        for breach in hibp_json:
            breaches.append(breach.get('Name'))
        data['hibp_breaches'] = ", ".join(breaches)

    return data


def get_riskiq_data(indicator, riskiq_username, riskiq_key):
    data = {'risk_classifications':'','risk_sinkhole':'','risk_evercompromised':'',
            'risk_primarydomain':'','risk_tags':'','risk_dynamicdns':'','risk_sources':''}
    
    if indicator and riskiq_username and riskiq_key:
        try:
            params = {"query": indicator}
            username = riskiq_username 
            key = riskiq_key
            auth = (username, key)
    
            risk_info = requests.get('https://api.riskiq.net/pt/v2/enrichment', params=params, auth=auth)
            risk_data = risk_info.json()
            data['risk_classifications']=risk_data.get('classification')
            data['risk_sinkhole'] = risk_data.get('sinkhole')
            data['risk_evercompromised'] = risk_data.get('everCompromised')
            data['risk_primarydomain'] = risk_data.get('primaryDomain')
            try:
                data['risk_subdomains'] = ",".join(risk_data.get('subdomains'))
            except:
                pass
            risk_list_tags = []
            risk_tags = risk_data.get('tags',[])
            for tag in risk_tags:
                risk_list_tags.append(tag)
            data['risk_dynamicdns']=risk_data.get('dynamicDns')
    
            risk_osint = requests.get('https://api.riskiq.net/pt/v2/enrichment/osint', params=params,auth=auth)
            risk_osint = risk_osint.json()
            risk_sources = risk_osint.get('results',[])
            risk_sources_list = []
            for source in risk_sources:
                if source not in risk_sources_list:
                    risk_sources_list.append(source['sourceUrl'])
                if source.get('tags'):
                    for tag in source['tags']:
                        if tag not in risk_list_tags:
                            risk_list_tags.append(tag)
            risk_tags = ", ".join(risk_list_tags)
            data['risk_tags'] = risk_tags
            data['risk_sources'] = ",".join(risk_sources_list)
        except Exception as err:
            print('RiskIQ error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))
    return data

def get_otx_data(indicator, ind_type, otx_api_key):
    data={'av_general':'n/a','av_reputation':'n/a','av_malware_data':'n/a','av_url_data':'n/a','av_passive_data':'n/a','av_pulse_count':'0','av_tlp':'n/a'}
    if otx_api_key:
        try:
            otx = OTXv2(otx_api_key)
            indicator_details=None
            if ind_type=='md5':
                indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5, indicator)
            elif ind_type=='sha256':
                indicator_details = otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_SHA256, indicator)
            elif ind_type=='domain':    
                indicator_details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, indicator)
            elif ind_type=='ip':    
                indicator_details = otx.get_indicator_details_full(IndicatorTypes.IPv4, indicator)
            if indicator_details:
                data['av_general'] = str(indicator_details.get('general', {}))
                data['av_reputation'] =  str(indicator_details.get('reputation', {}).get('reputation'))
                data['av_malware_data'] = str(indicator_details.get('malware', {}).get('data'))
                data['av_url_data']= str(indicator_details.get('url_list', {}).get('url_list'))
                data['av_passive_data'] = str(indicator_details.get('passive_dns'))
                data['av_pulse_count'] = str(indicator_details.get('general', {}).get('pulse_info', {}).get('count'))
                if indicator_details.get('analysis', {}).get('analysis'):
                    data['av_tlp'] = str(indicator_details.get('analysis', {}).get('analysis', {}).get('metadata',{}).get('tlp'))

        except Exception as err:
            print ('OTX error for indicator {}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))
        
    return data
    
def get_shodan_data(indicator, shodan_api_key):
    data={}
    if shodan_api_key:
        try:
            shodan_api = Shodan(shodan_api_key)
            shodan_query = shodan_api.host(indicator)
            shodan_ports = []
            shodan_tags = shodan_query.get('tags')
            shodan_list_tags = []
            if shodan_tags:
                for tag in shodan_tags:
                    shodan_list_tags.append(tag)
            else:
                shodan_tags='None'
            data['shodan_tags'] = ", ".join(shodan_list_tags)
            data['shodan_region'] = shodan_query.get('region_code','None')
            data['shodan_postal'] = shodan_query.get('postal_code','None')
            data['shodan_country'] = shodan_query.get('country_code','None')
            data['shodan_city'] = shodan_query.get('city','None')
            
            for item in shodan_query.get('data', []):
                shodan_ports.append(str(item['port']))
            data['shodan_ports'] = ", ".join(shodan_ports)
            data['shodan_hostnames'] = str(shodan_query.get('hostnames','None'))
            data['shodan_org'] = shodan_query.get('org','None')
            
        except Exception as err:
            print('Shodan error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))
    return data

def get_ipinfo_data(indicator):
    
    try:
        ipinfo_data = requests.get('https://ipinfo.io/'+indicator)
        ipinfo = ipinfo_data.json()
        
        return {'ipinfo_city': ipinfo.get('city'),
                'ipinfo_hostname':ipinfo.get('hostname'),
                'ipinfo_region':ipinfo.get('region'),
                'ipinfo_country':ipinfo.get('country'),
                'ipinfo_org':ipinfo.get('org'),
                'ipinfo_postal':ipinfo.get('postal')}
    except Exception as err:
        print('IpInfo error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))
        return {}

def get_greynoise_data(indicator,greynoise_api_key):
    data={'gn_seen':'','gn_classification':'','gn_first_seen':'',
          'gn_last_seen':'','gn_actor':'','gn_tags':''}
    
    if greynoise_api_key:
        try:
            gn_api_key=greynoise_api_key
            headers = {'Accept': 'application/json','key': gn_api_key}
        
            gn = requests.get('https://api.greynoise.io/v2/noise/context/'+indicator, params={}, headers = headers)
            gn_json = gn.json()
            data['gn_seen'] = gn_json.get('seen')
            data['gn_classification']= gn_json.get('classification')
            data['gn_first_seen'] = gn_json.get('first_seen')
            data['gn_last_seen'] = gn_json.get('last_seen')
            data['gn_actor'] = gn_json.get('actor')
            #print(gn_json)
            gn_tags = gn_json.get('tags',[])
            gn_tag_list = []
            for tag in gn_tags:
                gn_tag_list.append(tag)
            data['gn_tags'] = ", ".join(gn_tag_list)
    
        except Exception as err:
            print('Greynoise error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))
    return data

def get_misp_data(indicator,indicator_type,misp_api_key,misp_url):
    data={'misp_eventid':'n/a','misp_firstseen':'n/a','misp_lastseen':'n/a',
          'misp_eventinfo':'n/a','misp_dateadded':'n/a','misp_comment':'n/a'}
    
    if misp_api_key:
        try:
            misp_key=misp_api_key
            misp = ExpandedPyMISP(misp_url, misp_key, True)
            body = {"returnFormat":"json","type":indicator_type,"value":indicator} # add type to be passed by the enrichment function to just search for that type
            misp_query = misp.direct_call('attributes/restSearch', body)
            data['misp_eventid'] = misp_query['Attribute'][0]['event_id']
            data['misp_firstseen'] = misp_query['Attribute'][0]['first_seen']
            data['misp_lastseen'] = misp_query['Attribute'][0]['last_seen']
            data['misp_eventinfo'] = misp_query['Attribute'][0]['Event']['info']
            try:
                ts=int(misp_query['Attribute'][0]['timestamp'])
                data['misp_dateadded'] =  datetime.fromtimestamp(ts).isoformat()
            except:
                data['misp_dateadded'] = misp_query['Attribute'][0]['timestamp']
            data['misp_comment'] = misp_query['Attribute'][0]['Event']['comment']

        except Exception as err:
            print('MISP error for indicator{}: {}'.format(indicator, traceback.format_exception(type(err), err, err.__traceback__)))
    return data

def export_to_misp(user_details, report,indicators):
    misp_url = user_details.get('misp_url')
    misp_key = user_details.get('misp_api_key')
    misp_verifycert = True
    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    event = MISPEvent()
    event.info = report.title
    event = misp.add_event(event, pythonify=True)
    print(event)
    created = json.loads(event.to_json())
    event_id = created.get('id')
    report_id = report.id
    
    for indicator in indicators:
        indicator_value = indicator[1]
        if indicator[2] == 'IP':
            indicator_type = "ip-dst"
        elif indicator[2] == 'Domain':
            indicator_type = 'domain'
        elif indicator[2] == 'Email':
            indicator_type = 'email-src'
        elif indicator[2] == 'CVE':
            indicator_value = indicator[1].replace('_', '-')
            indicator_type = 'vulnerability'
        elif indicator[2] == 'MD5 Hash':
            indicator_type = 'md5'
        elif indicator[2] == 'SHA256 Hash':
            indicator_type = 'sha256'
        elif indicator[2] == 'URL':
            indicator_type = 'url'
        try:
            misp.add_attribute(event_id,{'type':indicator_type,'value':indicator_value},pythonify=True)
        except:
            pass