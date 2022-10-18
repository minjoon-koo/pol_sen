import boto3
import os, subprocess, sys  #argv를 통해 파라미터 전달 : api 또는 internal 통신을 통해 구현한 것이 아닌 script 형태로 구현
from datetime import datetime
import json, yaml
import common  #cloud secret 등을 통해 추출 한 token key load를 위한 커스텀라이브로 현재 구성에서는 생략가능

#Default Set
os.chdir(os.path.dirname(os.path.realpath(__file__)))
conf = common.common()
default_template = './template/default.yml'
create_policy = './log/policy_'+datetime.today().strftime("%Y%m%d-%H%M%S")+'.yml'

ListAcc = 'F' 
ReadAcc = 'F'
WriteAcc = 'F'
RoleDelete = 'F'
stsAcc = 'F'
#사용자 입력 값으로 유효성 검사 필요
ARN = [] #arn에서 ec2,s3 가 포함되어있다면 리소스 제약 해제
RoleName = ''
'''
parameter 샘플
{
    'ARN' : ['list'],
    'RoleName' : 'string', 
    'ListAcc' : 'T/F',
    'ReadAcc' : 'T/F',
    'WriteAcc' : 'T/F',
    'RoleDelete' : 'T/F',
    'stsAcc' : 'T/F'
}
'''
try:
    parameter = json.loads(sys.argv[1])
    ARN = parameter['ARN']
    RoleName = parameter['RoleName']
    try: ListAcc = parameter['ListAcc']
    except: pass    
    try: ReadAcc = parameter['ReadAcc']
    except: pass
    try: WriteAcc = parameter['WriteAcc']
    except: pass
    try: RoleDelete = parameter['RoleDelete']
    except: pass
    try: stsAcc = parameter['stsAcc']
    except: pass
except:
    pass


def RoleCreate(ARN, RoleName, ListAcc, ReadAcc, WriteAcc, RoleDelete):
    ERROR_MSG = '입력값 및 arn에 적합한 권한을 삽입하였는지 확인하여 주십시오.'
    try:
        with open(default_template) as f:
            policy_add = yaml.load(f, Loader=yaml.FullLoader)

        policy_add['name']=RoleName
        if ListAcc == 'T' : policy_add['list']= ARN
        if ReadAcc == 'T' : policy_add['read']= ARN
        if WriteAcc== 'T' : policy_add['write']= ARN
        '''sts 기능 구현 미흡 유효값이 정확히 무엇인지 파악 미흡
        if stsAcc  == 'T' : 
            if len(ARN) != 1 : 
                ERROR_MSG = ('value error : sts 권한을 설정하시는 경우 1개의 arn만 입력하여 주십시오.')
                sys.exit(ERROR_MSG)
            else: 
                policy_add['sts']['assume-role']= ARN
                policy_add['sts']['assume-role-with-saml']= ARN
                policy_add['sts']['assume-role-with-web-identity']= ARN
        '''        
        #arn ec2,s3 권한인지 확인하여 제한 해제
        ActionList = ActionCheck(ARN)
        if len(ActionList) : 
            policy_add['wildcard-only']['service-read']=ActionList
            policy_add['wildcard-only']['service-write']=ActionList
            policy_add['wildcard-only']['service-list']=ActionList


        with open(create_policy, 'w') as f:
            yaml.dump(policy_add, f)
        
        #ARN이 유효하지 않은 경우 error code return
        byte_res = subprocess.check_output(['policy_sentry','write-policy','--input-file',create_policy]) #log directory에 생성 기록남김
        string_res = byte_res.decode("utf-8")
        json_res = json.loads(string_res)
        return json_res
    except:
        sys.exit(ERROR_MSG)

def ActionCheck(ARN):
    ActionList = []
    ActionEc2 = False
    ActionS3 = False
    for i in ARN:
        if i.split(':')[2].find('ec2') != -1 : ActionEc2 = True
        if i.split(':')[2].find('s3') != -1 : ActionS3 = True
        
    if ActionEc2 : ActionList.append('ec2')
    if ActionS3 : ActionList.append('s3')

    return ActionList

def PolicyCreate(RoleName,json_res):
    ERROR_MSG = '입력값 및 arn에 적합한 권한을 삽입하였는지 확인하여 주십시오.'
    try:
        iam = boto3.client('iam')
        response = iam.create_policy(
            PolicyName=RoleName,
            PolicyDocument=json.dumps(json_res)
        )
        return response
    except:
        sys.exit(ERROR_MSG)

def PolicyUpdate(PolicyArn,json_res):
    ERROR_MSG = '입력값 및 arn에 적합한 권한을 삽입하였는지 확인하여 주십시오.'
    try:
        iam = boto3.client('iam')
        response = iam.create_policy_version(
            PolicyArn=PolicyArn,
            PolicyDocument=json.dumps(json_res),
            SetAsDefault=True
        )
        return response
    except:
        sys.exit(ERROR_MSG)

def PolicyDelete(PolicyArn):
    ERROR_MSG = '삭제할 수 없습니다. 삭제할 정책 명을 확인하여 주십시오.'
    try:
        iam = boto3.client('iam')
        response = iam.delete_policy(
            PolicyArn = PolicyArn
        )
        return response
    except:
        sys.exit(ERROR_MSG)

def Check_policies(RoleName,json_res,RoleDelete):
    RoleDict = {}
    iam = boto3.client("iam")
    paginator = iam.get_paginator('list_policies')
    for response in paginator.paginate(Scope="Local"):
        for policy in response["Policies"]:
            RoleDict[policy['PolicyName']] = policy['Arn']
    
    if RoleName in RoleDict and RoleDelete == 'F':
        resultJson = PolicyUpdate(RoleDict[RoleName],json_res)
        sys.exit(resultJson)
        #print(resultJson)
    elif RoleDelete == 'T':
        resultJson = PolicyDelete(RoleDict[RoleName])
        sys.exit(resultJson)
    else : 
        resultJson = PolicyCreate(RoleName,json_res)
        sys.exit(resultJson)
        #print(resultJson)


def main(): #main 구성 1.policy_sentry를 이용한 정책 생성 / 2. boto3(aws lib)을 이용하여 정책 반영
    if RoleDelete == 'F':
        NewPolicy = RoleCreate(ARN, RoleName, ListAcc, ReadAcc, WriteAcc, RoleDelete)
        Check_policies(RoleName,NewPolicy,RoleDelete)
    else:
        Check_policies(RoleName,'',RoleDelete)

if __name__ == '__main__':
    main()

