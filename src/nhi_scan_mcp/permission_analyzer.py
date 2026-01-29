"""Permission analysis for IAM identities."""

from typing import Dict, List, Set, Any
from .models import PermissionAnalysis, PermissionLevel, IAMUser, IAMRole
from .aws_scanner import AWSIAMScanner


class PermissionAnalyzer:
    """Analyzes IAM permissions and determines access levels."""

    # Admin-level managed policies
    ADMIN_POLICIES = [
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/IAMFullAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    ]

    # Dangerous permissions that indicate high privilege
    DANGEROUS_PERMISSIONS = [
        "iam:*",
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:PutUserPolicy",
        "iam:AttachUserPolicy",
        "iam:UpdateAssumeRolePolicy",
        "sts:AssumeRole",
        "lambda:*",
        "ec2:*",
        "s3:*",
        "*:*",
        "secretsmanager:GetSecretValue",
        "kms:Decrypt",
        "dynamodb:*",
    ]

    def __init__(self, scanner: AWSIAMScanner):
        """Initialize permission analyzer.

        Args:
            scanner: AWS IAM scanner instance
        """
        self.scanner = scanner

    def analyze_user_permissions(self, user: IAMUser) -> PermissionAnalysis:
        """Analyze permissions for an IAM user.

        Args:
            user: IAM user to analyze

        Returns:
            Permission analysis result
        """
        attached_policies, inline_policies, groups = self.scanner.get_user_policies(
            user.name
        )

        admin_access = any(
            policy in self.ADMIN_POLICIES for policy in attached_policies
        )

        all_permissions = set()
        resource_access = {}

        for policy_arn in attached_policies:
            policy_doc = self.scanner.get_policy_document(policy_arn)
            if policy_doc:
                perms, resources = self._extract_permissions(policy_doc)
                all_permissions.update(perms)
                self._merge_resource_access(resource_access, resources)

        for policy_name in inline_policies:
            policy_doc = self.scanner.get_inline_policy_document(
                user.name, policy_name, is_role=False
            )
            if policy_doc:
                perms, resources = self._extract_permissions(policy_doc)
                all_permissions.update(perms)
                self._merge_resource_access(resource_access, resources)

        dangerous_perms = [
            perm for perm in all_permissions if self._is_dangerous_permission(perm)
        ]

        permission_level = self._determine_permission_level(
            attached_policies, all_permissions, admin_access
        )

        return PermissionAnalysis(
            identity_arn=user.arn,
            permission_level=permission_level,
            attached_policies=attached_policies,
            inline_policies=inline_policies,
            group_memberships=groups,
            admin_access=admin_access,
            dangerous_permissions=dangerous_perms,
            resource_access=resource_access,
        )

    def analyze_role_permissions(self, role: IAMRole) -> PermissionAnalysis:
        """Analyze permissions for an IAM role.

        Args:
            role: IAM role to analyze

        Returns:
            Permission analysis result
        """
        attached_policies, inline_policies = self.scanner.get_role_policies(role.name)

        admin_access = any(
            policy in self.ADMIN_POLICIES for policy in attached_policies
        )

        all_permissions = set()
        resource_access = {}

        for policy_arn in attached_policies:
            policy_doc = self.scanner.get_policy_document(policy_arn)
            if policy_doc:
                perms, resources = self._extract_permissions(policy_doc)
                all_permissions.update(perms)
                self._merge_resource_access(resource_access, resources)

        for policy_name in inline_policies:
            policy_doc = self.scanner.get_inline_policy_document(
                role.name, policy_name, is_role=True
            )
            if policy_doc:
                perms, resources = self._extract_permissions(policy_doc)
                all_permissions.update(perms)
                self._merge_resource_access(resource_access, resources)

        dangerous_perms = [
            perm for perm in all_permissions if self._is_dangerous_permission(perm)
        ]

        permission_level = self._determine_permission_level(
            attached_policies, all_permissions, admin_access
        )

        return PermissionAnalysis(
            identity_arn=role.arn,
            permission_level=permission_level,
            attached_policies=attached_policies,
            inline_policies=inline_policies,
            group_memberships=[],
            admin_access=admin_access,
            dangerous_permissions=dangerous_perms,
            resource_access=resource_access,
        )

    def _extract_permissions(
        self, policy_document: Dict[str, Any]
    ) -> tuple[Set[str], Dict[str, List[str]]]:
        """Extract permissions and resources from a policy document.

        Args:
            policy_document: IAM policy document

        Returns:
            Tuple of (permissions set, resource access dict)
        """
        permissions = set()
        resource_access = {}

        if "Statement" not in policy_document:
            return permissions, resource_access

        for statement in policy_document["Statement"]:
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            permissions.update(actions)

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            for action in actions:
                service = action.split(":")[0] if ":" in action else "unknown"
                if service not in resource_access:
                    resource_access[service] = []
                resource_access[service].extend(resources)

        return permissions, resource_access

    def _merge_resource_access(
        self, target: Dict[str, List[str]], source: Dict[str, List[str]]
    ) -> None:
        """Merge resource access dictionaries.

        Args:
            target: Target dictionary to merge into
            source: Source dictionary to merge from
        """
        for service, resources in source.items():
            if service not in target:
                target[service] = []
            target[service].extend(resources)
            target[service] = list(set(target[service]))

    def _is_dangerous_permission(self, permission: str) -> bool:
        """Check if a permission is considered dangerous.

        Args:
            permission: Permission string (e.g., "iam:CreateUser")

        Returns:
            True if dangerous
        """
        permission_lower = permission.lower()

        for dangerous in self.DANGEROUS_PERMISSIONS:
            dangerous_lower = dangerous.lower()

            if permission_lower == dangerous_lower:
                return True

            if dangerous_lower.endswith("*"):
                prefix = dangerous_lower[:-1]
                if permission_lower.startswith(prefix):
                    return True

        return False

    def _determine_permission_level(
        self,
        attached_policies: List[str],
        all_permissions: Set[str],
        admin_access: bool,
    ) -> PermissionLevel:
        """Determine the overall permission level.

        Args:
            attached_policies: List of attached policy ARNs
            all_permissions: Set of all permissions
            admin_access: Whether has admin access

        Returns:
            Permission level
        """
        if admin_access:
            return PermissionLevel.ADMIN

        if "arn:aws:iam::aws:policy/PowerUserAccess" in attached_policies:
            return PermissionLevel.POWER_USER

        if "*:*" in all_permissions or "iam:*" in all_permissions:
            return PermissionLevel.ADMIN

        dangerous_count = sum(
            1 for perm in all_permissions if self._is_dangerous_permission(perm)
        )

        if dangerous_count > 5:
            return PermissionLevel.POWER_USER
        elif dangerous_count > 0:
            return PermissionLevel.READ_WRITE

        write_actions = [
            perm
            for perm in all_permissions
            if any(
                keyword in perm.lower()
                for keyword in [
                    "create",
                    "update",
                    "delete",
                    "put",
                    "write",
                    "modify",
                ]
            )
        ]

        if write_actions:
            return PermissionLevel.READ_WRITE

        read_actions = [
            perm
            for perm in all_permissions
            if any(
                keyword in perm.lower()
                for keyword in ["get", "list", "describe", "read"]
            )
        ]

        if read_actions:
            return PermissionLevel.READ_ONLY

        if all_permissions:
            return PermissionLevel.LIMITED

        return PermissionLevel.NONE

    def analyze_caller_permissions(self) -> PermissionAnalysis:
        """Analyze permissions for the current caller.

        Returns:
            Permission analysis for the caller
        """
        try:
            caller_identity = self.scanner.get_caller_identity()
            arn = caller_identity["Arn"]

            if ":user/" in arn:
                username = arn.split("/")[-1]
                users = self.scanner.list_users()
                user = next((u for u in users if u.name == username), None)
                if user:
                    return self.analyze_user_permissions(user)
            elif ":role/" in arn or ":assumed-role/" in arn:
                if ":assumed-role/" in arn:
                    role_name = arn.split("/")[-2]
                else:
                    role_name = arn.split("/")[-1]

                roles = self.scanner.list_roles()
                role = next((r for r in roles if r.name == role_name), None)
                if role:
                    return self.analyze_role_permissions(role)

            return PermissionAnalysis(
                identity_arn=arn,
                permission_level=PermissionLevel.UNKNOWN,
                attached_policies=[],
                inline_policies=[],
                group_memberships=[],
                admin_access=False,
                dangerous_permissions=[],
                resource_access={},
            )

        except Exception:
            return PermissionAnalysis(
                identity_arn="unknown",
                permission_level=PermissionLevel.NONE,
                attached_policies=[],
                inline_policies=[],
                group_memberships=[],
                admin_access=False,
                dangerous_permissions=[],
                resource_access={},
            )
