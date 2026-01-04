#!/usr/bin/env python
import argparse
import configparser
import os
import sys

from enumerate_iam.main import enumerate_iam


def read_aws_credentials(profile_name):
    """Read AWS credentials from ~/.aws/credentials file"""
    credentials_path = os.path.expanduser('~/.aws/credentials')

    if not os.path.exists(credentials_path):
        print(f"Error: AWS credentials file not found at {credentials_path}")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(credentials_path)

    if profile_name not in config:
        print(f"Error: Profile '{profile_name}' not found in {credentials_path}")
        print(f"Available profiles: {', '.join(config.sections())}")
        sys.exit(1)

    profile = config[profile_name]

    access_key = profile.get('aws_access_key_id')
    secret_key = profile.get('aws_secret_access_key')
    session_token = profile.get('aws_session_token')

    if not access_key or not secret_key:
        print(f"Error: Profile '{profile_name}' is missing required credentials")
        sys.exit(1)

    return access_key, secret_key, session_token


def main():
    parser = argparse.ArgumentParser(description='Enumerate IAM permissions')

    parser.add_argument('--access-key', help='AWS access key')
    parser.add_argument('--secret-key', help='AWS secret key')
    parser.add_argument('--session-token', help='STS session token')
    parser.add_argument('--profile', help='AWS profile name from ~/.aws/credentials')
    parser.add_argument('--region', help='AWS region to send API requests to', default='us-east-1')

    args = parser.parse_args()

    # Determine credential source
    if args.profile:
        if args.access_key or args.secret_key:
            print("Error: Cannot use --profile together with --access-key or --secret-key")
            sys.exit(1)

        access_key, secret_key, session_token = read_aws_credentials(args.profile)
        # Override session token if provided via command line
        if args.session_token:
            session_token = args.session_token
    else:
        if not args.access_key or not args.secret_key:
            print("Error: Either --profile or both --access-key and --secret-key must be provided")
            sys.exit(1)

        access_key = args.access_key
        secret_key = args.secret_key
        session_token = args.session_token

    enumerate_iam(access_key,
                  secret_key,
                  session_token,
                  args.region)


if __name__ == '__main__':
    main()
