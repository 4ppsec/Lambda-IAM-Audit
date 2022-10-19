import json
import boto3
import os
import sys
import time


try:
  import argparse
except:
  os.system("pip install argparse")
  try:
    import argparse
  except Exception as e:
    sys.exit(e)

try:
  from prettytable import PrettyTable, ALL
except:
  try:
    os.system("python3 -m pip install -U git+https://github.com/jazzband/prettytable")
    from prettytable import PrettyTable
  except Exception as e:
    sys.exit(e)


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--profile", help="AWS profile", default="default")
    parser.add_argument("-r", "--region", help="AWS region", default="us-east-1")
    return parser.parse_args()


def get_policies(aws_client, role):
  policies = []
  try:    
    role_policies = aws_client.list_role_policies(RoleName=role)

    # extract role policy
    for policy_name in role_policies["PolicyNames"]:
        policy_data = aws_client.get_role_policy(RoleName=role, PolicyName=policy_name)
        if "PolicyDocument" in policy_data:
          policy_statement = policy_data["PolicyDocument"].get("Statement")
          policies.append(policy_statement)

    # extract attached policies
    attached_policies = aws_client.list_attached_role_policies(RoleName=role)
    for attached_policy in attached_policies["AttachedPolicies"]:
      policy_arn = attached_policy.get("PolicyArn")
      if policy_arn:
        policy_data = aws_client.get_policy(PolicyArn=policy_arn).get("Policy")
        if policy_data:
          default_version_id = policy_data.get("DefaultVersionId")
          if default_version_id:
            policy_version = aws_client.get_policy_version(
                PolicyArn=policy_arn, 
                VersionId=default_version_id
            )
            policy_version = policy_version.get("PolicyVersion", {}).get("Document", {}).get("Statement")
            policies.append(policy_version)
  except Exception as e:
    print(e)

  return policies


def build_table(vulns):
  x = PrettyTable(hrules=ALL)
  x.field_names = ["Role Arn", "Associated Functions", "Risky Actions"]
  for vuln in vulns:
    x.add_row([vuln, '\n'.join(vulns[vuln]["functions"]), '\n'.join(vulns[vuln]["actions"])])
  print(x)


def progress(percent=0, width=40):
    left = width * percent // 100
    right = width - left
    tags = "#" * left
    spaces = " " * right
    percents = f"{percent:.0f}%"
    print("\r[", tags, spaces, "]", percents, sep="", end="", flush=True)


def main():
  try:
    vuln_roles = {}
    args = get_args()
    
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    sts = session.client('sts')
    iam  = session.client('iam')
    lmbda = session.client('lambda')
    
    caller = sts.get_caller_identity()
    user = "root" if caller['UserId']==caller['Account'] else caller['UserId']
    print(f"[!] Running on account: {caller['Account']}, in region {args.region} with UserId: {user}")

    function_list = lmbda.list_functions().get("Functions", [])
    func_num = len(function_list)
    print(f"[v] Found {str(func_num)} functions. Collecting IAM information...")
    
    i = 0
    for func in function_list:
      i+=1
      progress(int(i/func_num*100))
      func_arn = func.get("FunctionName")
      func_role = func.get("Role")
      if func_role:
        role_name = func_role.split('/')[-1]
        role_policies = get_policies(iam, role_name)
        for func_policies in role_policies:
          func_policies = [func_policies] if isinstance(func_policies, dict) else func_policies
          for policy in func_policies:
            if policy["Effect"] == "Allow":
              actions = policy["Action"]
              actions = [actions] if isinstance(actions, str) else actions
              for action in actions:
                if action.split(":")[1] == "*":
                  if role_name not in vuln_roles:
                    vuln_roles[role_name] = {
                      "functions":[], 
                      "actions":[]
                    }
                  if action not in vuln_roles[role_name]["actions"]:
                    vuln_roles[role_name]["actions"].append(action)
                  if func_arn not in vuln_roles[role_name]["functions"]:
                    vuln_roles[role_name]["functions"].append(func_arn)
    # print(json.dumps(vuln_roles, indent=2))
    print("\n")
    build_table(vuln_roles)

  except Exception as e:
    print(e)


if __name__ == "__main__":
    print('''

 ██████╗ ██╗  ██╗██████╗ ██████╗ ███████╗███████╗ ██████╗
██╔═══██╗██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝
██║██╗██║███████║██████╔╝██████╔╝███████╗█████╗  ██║     
██║██║██║╚════██║██╔═══╝ ██╔═══╝ ╚════██║██╔══╝  ██║     
╚█║████╔╝     ██║██║     ██║     ███████║███████╗╚██████╗
 ╚╝╚═══╝      ╚═╝╚═╝     ╚═╝     ╚══════╝╚══════╝ ╚═════╝
                                                         
    AWS IAM Policy Auditing, by Tal Melamed @4ppsec
    ''')
    main()
    


