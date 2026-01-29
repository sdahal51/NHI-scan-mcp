"""AWS IAM scanner for discovering users and roles."""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from .models import IAMUser, IAMRole, IdentityType


class AWSIAMScanner:
    """Scanner for AWS IAM resources."""

    def __init__(
        self,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None,
        aws_session_token: Optional[str] = None,
        region_name: str = "us-east-1",
    ):
        """Initialize AWS IAM scanner.

        Args:
            aws_access_key_id: AWS access key ID (if None, uses default credential chain)
            aws_secret_access_key: AWS secret access key
            aws_session_token: AWS session token (for temporary credentials)
            region_name: AWS region name
        """
        session_kwargs = {"region_name": region_name}

        if aws_access_key_id and aws_secret_access_key:
            session_kwargs.update({
                "aws_access_key_id": aws_access_key_id,
                "aws_secret_access_key": aws_secret_access_key,
            })
            if aws_session_token:
                session_kwargs["aws_session_token"] = aws_session_token

        self.session = boto3.Session(**session_kwargs)
        self.iam_client = self.session.client("iam")
        self.sts_client = self.session.client("sts")

    def get_caller_identity(self) -> Dict[str, Any]:
        """Get the identity of the caller.

        Returns:
            Dictionary with caller identity information
        """
        try:
            return self.sts_client.get_caller_identity()
        except (ClientError, NoCredentialsError) as e:
            raise Exception(f"Failed to get caller identity: {str(e)}")

    def list_users(self) -> List[IAMUser]:
        """List all IAM users in the account.

        Returns:
            List of IAMUser objects
        """
        users = []
        try:
            paginator = self.iam_client.get_paginator("list_users")
            for page in paginator.paginate():
                for user_data in page["Users"]:
                    user = self._enrich_user_data(user_data)
                    users.append(user)
        except ClientError as e:
            raise Exception(f"Failed to list IAM users: {str(e)}")

        return users

    def _enrich_user_data(self, user_data: Dict[str, Any]) -> IAMUser:
        """Enrich user data with additional information.

        Args:
            user_data: Basic user data from list_users

        Returns:
            Enriched IAMUser object
        """
        username = user_data["UserName"]

        tags = {}
        try:
            tag_response = self.iam_client.list_user_tags(UserName=username)
            tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}
        except ClientError:
            pass

        access_keys = []
        try:
            key_response = self.iam_client.list_access_keys(UserName=username)
            access_keys = [
                {
                    "AccessKeyId": key["AccessKeyId"],
                    "Status": key["Status"],
                    "CreateDate": key["CreateDate"],
                }
                for key in key_response.get("AccessKeyMetadata", [])
            ]
        except ClientError:
            pass

        mfa_devices = []
        try:
            mfa_response = self.iam_client.list_mfa_devices(UserName=username)
            mfa_devices = [
                device["SerialNumber"]
                for device in mfa_response.get("MFADevices", [])
            ]
        except ClientError:
            pass

        return IAMUser(
            arn=user_data["Arn"],
            name=username,
            user_id=user_data["UserId"],
            path=user_data["Path"],
            created_date=user_data["CreateDate"],
            password_last_used=user_data.get("PasswordLastUsed"),
            tags=tags,
            access_keys=access_keys,
            mfa_devices=mfa_devices,
        )

    def list_roles(self) -> List[IAMRole]:
        """List all IAM roles in the account.

        Returns:
            List of IAMRole objects
        """
        roles = []
        try:
            paginator = self.iam_client.get_paginator("list_roles")
            for page in paginator.paginate():
                for role_data in page["Roles"]:
                    role = self._enrich_role_data(role_data)
                    roles.append(role)
        except ClientError as e:
            raise Exception(f"Failed to list IAM roles: {str(e)}")

        return roles

    def _enrich_role_data(self, role_data: Dict[str, Any]) -> IAMRole:
        """Enrich role data with additional information.

        Args:
            role_data: Basic role data from list_roles

        Returns:
            Enriched IAMRole object
        """
        rolename = role_data["RoleName"]

        tags = {}
        try:
            tag_response = self.iam_client.list_role_tags(RoleName=rolename)
            tags = {tag["Key"]: tag["Value"] for tag in tag_response.get("Tags", [])}
        except ClientError:
            pass

        last_used = None
        try:
            role_detail = self.iam_client.get_role(RoleName=rolename)
            last_used_data = role_detail.get("Role", {}).get("RoleLastUsed", {})
            if "LastUsedDate" in last_used_data:
                last_used = last_used_data["LastUsedDate"]
        except ClientError:
            pass

        return IAMRole(
            arn=role_data["Arn"],
            name=rolename,
            role_id=role_data["RoleId"],
            path=role_data["Path"],
            created_date=role_data["CreateDate"],
            assume_role_policy=role_data["AssumeRolePolicyDocument"],
            max_session_duration=role_data.get("MaxSessionDuration", 3600),
            tags=tags,
            last_used=last_used,
        )

    def get_user_policies(self, username: str) -> Tuple[List[str], List[str], List[str]]:
        """Get policies attached to a user.

        Args:
            username: IAM username

        Returns:
            Tuple of (attached_policy_arns, inline_policy_names, group_names)
        """
        attached_policies = []
        inline_policies = []
        groups = []

        try:
            attached_response = self.iam_client.list_attached_user_policies(
                UserName=username
            )
            attached_policies = [
                policy["PolicyArn"]
                for policy in attached_response.get("AttachedPolicies", [])
            ]

            inline_response = self.iam_client.list_user_policies(UserName=username)
            inline_policies = inline_response.get("PolicyNames", [])

            groups_response = self.iam_client.list_groups_for_user(UserName=username)
            groups = [group["GroupName"] for group in groups_response.get("Groups", [])]

        except ClientError as e:
            raise Exception(f"Failed to get policies for user {username}: {str(e)}")

        return attached_policies, inline_policies, groups

    def get_role_policies(self, rolename: str) -> Tuple[List[str], List[str]]:
        """Get policies attached to a role.

        Args:
            rolename: IAM role name

        Returns:
            Tuple of (attached_policy_arns, inline_policy_names)
        """
        attached_policies = []
        inline_policies = []

        try:
            attached_response = self.iam_client.list_attached_role_policies(
                RoleName=rolename
            )
            attached_policies = [
                policy["PolicyArn"]
                for policy in attached_response.get("AttachedPolicies", [])
            ]

            inline_response = self.iam_client.list_role_policies(RoleName=rolename)
            inline_policies = inline_response.get("PolicyNames", [])

        except ClientError as e:
            raise Exception(f"Failed to get policies for role {rolename}: {str(e)}")

        return attached_policies, inline_policies

    def get_policy_document(self, policy_arn: str) -> Optional[Dict[str, Any]]:
        """Get policy document for a managed policy.

        Args:
            policy_arn: Policy ARN

        Returns:
            Policy document or None if not accessible
        """
        try:
            policy = self.iam_client.get_policy(PolicyArn=policy_arn)
            version_id = policy["Policy"]["DefaultVersionId"]
            version = self.iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            return version["PolicyVersion"]["Document"]
        except ClientError:
            return None

    def get_inline_policy_document(
        self, name: str, policy_name: str, is_role: bool = False
    ) -> Optional[Dict[str, Any]]:
        """Get inline policy document.

        Args:
            name: User or role name
            policy_name: Inline policy name
            is_role: Whether this is a role (vs user)

        Returns:
            Policy document or None if not accessible
        """
        try:
            if is_role:
                response = self.iam_client.get_role_policy(
                    RoleName=name, PolicyName=policy_name
                )
            else:
                response = self.iam_client.get_user_policy(
                    UserName=name, PolicyName=policy_name
                )
            return response.get("PolicyDocument")
        except ClientError:
            return None
