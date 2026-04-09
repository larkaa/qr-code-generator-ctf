#!/usr/bin/env python3
"""
MinIO/S3 Enumeration Tool for Pentest
Usage: python3 minio_enum.py --list-buckets
       python3 minio_enum.py --list-all
       python3 minio_enum.py --list-objects-in-bucket BUCKET_NAME
       python3 minio_enum.py --test-rights [BUCKET_NAME]
"""

import boto3
import argparse
import sys
import urllib3
from botocore.client import Config
from botocore.exceptions import ClientError

urllib3.disable_warnings()

# ============================================================
# HARDCODED CONFIG — edit these
# ============================================================
ENDPOINT   = ""
ACCESS_KEY = ""
SECRET_KEY = ""
# ============================================================

def get_client():
    return boto3.client(
        's3',
        endpoint_url=ENDPOINT,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        config=Config(
            signature_version='s3v4',
            connect_timeout=5,
            read_timeout=120,
            retries={'max_attempts': 1}
        ),
        verify=False
    )

def get_iam_client():
    return boto3.client(
        'iam',
        endpoint_url=ENDPOINT,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        verify=False
    )

# ============================================================
# CORE FUNCTIONS
# ============================================================

def list_buckets(s3):
    """Return list of bucket dicts with Name key"""
    try:
        response = s3.list_buckets()
        return response.get('Buckets', [])
    except ClientError as e:
        print(f"[ERROR] list_buckets: {e.response['Error']['Code']}")
        return []
    except Exception as e:
        print(f"[ERROR] list_buckets: {type(e).__name__}: {e}")
        return []

def list_objects_in_bucket(s3, bucket_name, prefix='', max_keys=1000):
    """List all objects in a bucket using pagination"""
    objects = []
    try:
        paginator = s3.get_paginator('list_objects_v2')
        pages = paginator.paginate(
            Bucket=bucket_name,
            Prefix=prefix,
            PaginationConfig={'MaxItems': max_keys}
        )
        for page in pages:
            for obj in page.get('Contents', []):
                objects.append(obj)
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print(f"  [DENIED] Cannot list objects in {bucket_name}")
        else:
            print(f"  [ERROR] {code}")
    except Exception as e:
        print(f"  [ERROR] {type(e).__name__}: {e}")
    return objects

def check_bucket_permissions(s3, bucket_name):
    """Test all read and write permissions on a bucket"""
    perms = {}

    tests = {
        # Read ops
        'list_objects':     lambda: s3.list_objects_v2(
                                Bucket=bucket_name, MaxKeys=1),
        'get_location':     lambda: s3.get_bucket_location(
                                Bucket=bucket_name),
        'get_acl':          lambda: s3.get_bucket_acl(
                                Bucket=bucket_name),
        'get_policy':       lambda: s3.get_bucket_policy(
                                Bucket=bucket_name),
        'get_versioning':   lambda: s3.get_bucket_versioning(
                                Bucket=bucket_name),
        'get_encryption':   lambda: s3.get_bucket_encryption(
                                Bucket=bucket_name),
        'get_tagging':      lambda: s3.get_bucket_tagging(
                                Bucket=bucket_name),
        'get_cors':         lambda: s3.get_bucket_cors(
                                Bucket=bucket_name),
        'get_logging':      lambda: s3.get_bucket_logging(
                                Bucket=bucket_name),

        # Write ops
        'put_object':       lambda: s3.put_object(
                                Bucket=bucket_name,
                                Key='__pentest_probe__',
                                Body=b'pentest_probe'),
        'delete_object':    lambda: s3.delete_object(
                                Bucket=bucket_name,
                                Key='__pentest_probe__'),
        'put_acl':          lambda: s3.put_bucket_acl(
                                Bucket=bucket_name,
                                ACL='private'),
    }

    extras = {}  # store extra data from successful calls

    for perm_name, test_fn in tests.items():
        try:
            result = test_fn()
            perms[perm_name] = 'ALLOW'

            # Capture useful data
            if perm_name == 'get_policy':
                extras['policy'] = result.get('Policy', '')
            elif perm_name == 'get_acl':
                extras['acl'] = result.get('Grants', [])
            elif perm_name == 'get_location':
                extras['region'] = result.get('LocationConstraint', 'us-east-1')
            elif perm_name == 'list_objects':
                extras['object_count'] = result.get('KeyCount', 0)

        except ClientError as e:
            code = e.response['Error']['Code']
            no_resource = [
                'NoSuchBucketPolicy',
                'NoSuchLifecycleConfiguration',
                'ServerSideEncryptionConfigurationNotFoundError',
                'NoSuchCORSConfiguration',
                'NoSuchTagSet',
            ]
            if code in ['AccessDenied', 'AllAccessDisabled']:
                perms[perm_name] = 'DENY'
            elif code in no_resource:
                perms[perm_name] = 'NONE'
            else:
                perms[perm_name] = f'ERR:{code}'
        except Exception as e:
            perms[perm_name] = f'ERR:{type(e).__name__}'

    return perms, extras

def check_iam_rights(iam):
    """Check IAM level permissions"""
    results = {}
    checks = {
        'list_users':    lambda: iam.list_users(),
        'list_policies': lambda: iam.list_policies(),
        'list_groups':   lambda: iam.list_groups(),
        'get_account':   lambda: iam.get_account_summary(),
    }
    for name, fn in checks.items():
        try:
            result = fn()
            results[name] = ('ALLOW', result)
        except ClientError as e:
            results[name] = ('DENY', e.response['Error']['Code'])
        except Exception as e:
            results[name] = ('ERR', str(e))
    return results

# ============================================================
# COMMAND HANDLERS
# ============================================================

def cmd_list_buckets(s3):
    print("\n[*] Listing buckets...")
    buckets = list_buckets(s3)
    if not buckets:
        print("  No buckets found or access denied")
        return
    print(f"  Found {len(buckets)} bucket(s):")
    for b in buckets:
        print(f"  + {b['Name']:50} created={b.get('CreationDate','?')}")
    return buckets

def cmd_list_all(s3):
    print("\n[*] Listing all buckets and their objects...")
    buckets = list_buckets(s3)
    if not buckets:
        print("  No buckets accessible")
        return

    total_objects = 0
    total_size = 0

    for bucket in buckets:
        bname = bucket['Name']
        print(f"\n  BUCKET: {bname}")
        print(f"  {'':->50}")

        objects = list_objects_in_bucket(s3, bname)
        if not objects:
            print("    (empty or no access)")
            continue

        for obj in objects:
            size_kb = obj['Size'] / 1024
            modified = obj.get('LastModified', '?')
            print(f"    {obj['Key']:60} "
                  f"{size_kb:8.1f} KB  {modified}")
            total_objects += 1
            total_size += obj['Size']

    print(f"\n  TOTAL: {total_objects} objects, "
          f"{total_size/1024/1024:.2f} MB")

def cmd_list_objects(s3, bucket_name):
    print(f"\n[*] Listing objects in bucket: {bucket_name}")
    objects = list_objects_in_bucket(s3, bucket_name)
    if not objects:
        print("  No objects found or access denied")
        return

    print(f"  Found {len(objects)} object(s):")
    for obj in objects:
        size_kb = obj['Size'] / 1024
        modified = obj.get('LastModified', '?')
        print(f"  + {obj['Key']:60} "
              f"{size_kb:8.1f} KB  {modified}")

def cmd_test_rights(s3, iam, bucket_name=None):
    print("\n[*] Testing permissions...")

    # Determine target buckets
    if bucket_name:
        buckets = [{'Name': bucket_name}]
    else:
        print("  No bucket specified — listing all first...")
        buckets = list_buckets(s3)
        if not buckets:
            print("  Cannot list buckets")
            return

    # Summary accumulators
    write_buckets  = []
    policy_buckets = []
    denied_buckets = []

    for bucket in buckets:
        bname = bucket['Name']
        print(f"\n  BUCKET: {bname}")
        print(f"  {'':->50}")

        # Quick accessibility check
        try:
            s3.head_bucket(Bucket=bname)
        except ClientError as e:
            code = e.response['Error']['Code']
            print(f"    SKIP ({code})")
            denied_buckets.append(bname)
            continue

        perms, extras = check_bucket_permissions(s3, bname)

        # Print permissions table
        read_ops  = ['list_objects','get_location','get_acl',
                     'get_policy','get_versioning','get_encryption',
                     'get_tagging','get_cors','get_logging']
        write_ops = ['put_object','delete_object','put_acl']

        print("    READ OPERATIONS:")
        for op in read_ops:
            status = perms.get(op, '?')
            symbol = '✓' if status == 'ALLOW' else \
                     '~' if status == 'NONE'  else '✗'
            print(f"      {symbol} {op:30} {status}")

        print("    WRITE OPERATIONS:")
        for op in write_ops:
            status = perms.get(op, '?')
            symbol = '✓' if status == 'ALLOW' else '✗'
            print(f"      {symbol} {op:30} {status}")

        # Print extra data
        if 'policy' in extras:
            print(f"    POLICY: {extras['policy'][:300]}")
        if 'acl' in extras:
            print(f"    ACL GRANTS:")
            for grant in extras['acl']:
                print(f"      {grant}")
        if 'region' in extras:
            print(f"    REGION: {extras['region']}")

        # Track interesting findings
        if perms.get('put_object') == 'ALLOW':
            write_buckets.append(bname)
        if perms.get('get_policy') == 'ALLOW':
            policy_buckets.append(bname)

    # IAM check
    print("\n  IAM PERMISSIONS:")
    iam_results = check_iam_rights(iam)
    for name, (status, data) in iam_results.items():
        symbol = '✓' if status == 'ALLOW' else '✗'
        print(f"    {symbol} {name:30} {status}")
        if status == 'ALLOW' and name == 'list_users':
            for u in data.get('Users', []):
                print(f"        User: {u['UserName']}")

    # Final summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"  Buckets tested:      {len(buckets)}")
    print(f"  Denied buckets:      {len(denied_buckets)}")
    if write_buckets:
        print(f"  !!! WRITE ACCESS:    {write_buckets}")
    if policy_buckets:
        print(f"  !!! POLICY ACCESS:   {policy_buckets}")
    if not write_buckets and not policy_buckets:
        print("  Result: read-only access")

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='MinIO/S3 Pentest Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 minio_enum.py --list-buckets
  python3 minio_enum.py --list-all
  python3 minio_enum.py --list-objects-in-bucket my-bucket
  python3 minio_enum.py --test-rights
  python3 minio_enum.py --test-rights my-bucket
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list-buckets',
                       action='store_true',
                       help='List all accessible buckets')
    group.add_argument('--list-all',
                       action='store_true',
                       help='List all buckets and their objects')
    group.add_argument('--list-objects-in-bucket',
                       metavar='BUCKET',
                       help='List objects in a specific bucket')
    group.add_argument('--test-rights',
                       nargs='?',
                       const='__ALL__',
                       metavar='BUCKET',
                       help='Test permissions (optional: specific bucket)')

    args = parser.parse_args()

    print(f"[*] Endpoint:   {ENDPOINT}")
    print(f"[*] Access Key: {ACCESS_KEY}")

    s3  = get_client()
    iam = get_iam_client()

    if args.list_buckets:
        cmd_list_buckets(s3)

    elif args.list_all:
        cmd_list_all(s3)

    elif args.list_objects_in_bucket:
        cmd_list_objects(s3, args.list_objects_in_bucket)

    elif args.test_rights is not None:
        bucket = None if args.test_rights == '__ALL__' else args.test_rights
        cmd_test_rights(s3, iam, bucket)

if __name__ == '__main__':
    main()
