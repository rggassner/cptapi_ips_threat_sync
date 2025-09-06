#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys,json,re
from datetime import datetime
from my_config import *
from cptapi import Cptapi

def load_protections():
    source_domain=Cptapi(user,password,url,SOURCE_DOM,api_wait_time=api_wait_time,read_only=True,page_size=page_size)
    source_protections=source_domain.show_threat_protections()
    threat_protection=[]
    for protection in source_protections:
        s_protection = source_domain.show_threat_protection(uid=protection['uid'],show_profiles=True)
        for profile in s_protection['profiles']:
            if profile['name'] == SOURCE_PROFILE:
                threat_protection.append({'action':profile['final']['action'],'name':protection['name'],'uid':protection['uid'],'capture-packets':profile['final']['capture-packets']})
                print('Loading protection {} {} '.format(len(threat_protection), protection['name']))
        if len(threat_protection) > PROTECTIONS_LIMIT:
            break
    source_domain.logout()
    return threat_protection

def update_ips(domains):
    for domain in domains:
        working_domain=Cptapi(user,password,url,domain['name'],api_wait_time=api_wait_time,read_only=False,page_size=page_size)
        print('Updating IPS in domain {}'.format(domain['name']))
        ips_update=working_domain.run_ips_update()
        print('Result {}'.format(ips_update))
        working_domain.logout()

try:
    print ('Loading protections.')
    previous_protections=json.load(open(PROTECTION_FILE))
    print ('Loaded.')
except FileNotFoundError as e:
    print('Protection file not found. Running full sync.')
    previous_protections=[{'name':'bogus','action':'bogus','uid':'bogus','capture-packets':'bogus'}]

try:
    with open("disabled.json") as f:
        disabled_overrides = json.load(f)
    print(f"Loaded {len(disabled_overrides)} disabled overrides.")
except FileNotFoundError:
    disabled_overrides = []
    print("No disabled overrides found.")


print('Conecting MDS.')
mds=Cptapi(user,password,url,'MDS',api_wait_time=api_wait_time,read_only=True,page_size=page_size)
print('Conected.')
print('Retrieving domains.')
domains=mds.show_domains()
domains_names=[x['name'] for x in domains]
print('Domains {}.'.format(domains_names))
print('Disconecting MDS.')
mds.logout()
print('Disconected.')
print('Updating ips.')
update_ips(domains)
print('Ips updated.')
print('Loading protections.')
protections=load_protections()
print('Protections loaded.')

for domain in domains:
    print('Working on domain {}'.format(domain['name']))
    working_domain=Cptapi(user,password,url,domain['name'],api_wait_time=api_wait_time,read_only=False,page_size=page_size)
    change_count=0
    for protection in protections:
        # --- apply override if protection name matches
        if protection['name'] in disabled_overrides:
            print(f"Overriding {protection['name']} to Inactive (disabled).")
            protection['action'] = "Inactive"
            protection['capture-packets'] = False
        # if this protection exists and actual action equals previous one. Comprehension, lambda and filter show off 8-D
        if protection['uid'] in [i['uid'] for i in previous_protections] and \
        ( protection['action'] == list(filter(lambda x: (x['uid']==protection['uid']),previous_protections))[0]['action'] and \
        protection['capture-packets'] == list(filter(lambda x: (x['uid']==protection['uid']),previous_protections))[0]['capture-packets'] ):
            #print('Already exists and action is the same.')
            pass
        else:
            res=working_domain.set_threat_protection(uid=protection['uid'],profile=DESTINATION_PROFILE,action=protection['action'],capture_packets=protection['capture-packets'])
            if 'name' in res:
                print('Changing {} {} {}.'.format(domain['name'],res['name'],protection['action']))
                change_count=change_count+1
            elif 'code' in res and res['code'] == 'generic_err_object_not_found' and 'message' in res and res['message'] == 'Requested object [N/A] not found':
                print('Known Object not found {}'.format(res))
            elif 'code' in res and res['code'] == 'generic_err_object_not_found':
                print('Object not found {}'.format(res))
                exit()
            elif 'code' in res and res['code'] == 'generic_server_error':
                print('Generic error {}'.format(res))
                exit()
            elif 'code' in res and res['code'] == 'generic_err_invalid_parameter' and 'message' in res and re.match(r'.*no action for engine settings.*',res['message']):
                print('Known invalid parameter error.')
            else:
                print('---------- Error {} {}.'.format(domain['name'],res))
                exit()
        if change_count > MAX_PUBLISH:
            working_domain.publish()
            print('Publishing needed: {} changes.'.format(change_count))
            change_count = 0
    if change_count > 0:
        working_domain.publish()
        print('Publishing needed: {} changes.'.format(change_count))
    working_domain.logout()
json.dump(protections,open(PROTECTION_FILE,'w'))

