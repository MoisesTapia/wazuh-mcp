from __future__ import annotations

from typing import Any, Optional

from fastmcp import FastMCP

from ..client import WazuhClient


def register(mcp: FastMCP, client: WazuhClient) -> None:

    # ── Users ────────────────────────────────────────────────────────────────

    @mcp.tool()
    async def list_users(
        user_ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists RBAC users with their assigned roles.

        Args:
            user_ids: Comma-separated user IDs.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Users with id, username, assigned roles.
        """
        params = {k: v for k, v in {
            "user_ids": user_ids, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/security/users", params=params or None)

    @mcp.tool()
    async def get_current_user() -> dict:
        """
        Returns information about the currently authenticated user.

        Returns:
            data.affected_items: Current user data (id, username, roles).
        """
        return await client.get("/security/users/me")

    @mcp.tool()
    async def get_current_user_policies() -> dict:
        """
        Returns the processed (effective) policies of the current user.

        Returns:
            data.affected_items: Effective policies with allowed actions and resources.
        """
        return await client.get("/security/users/me/policies")

    @mcp.tool()
    async def create_user(
        username: str,
        password: str,
        allow_run_as: Optional[bool] = None,
    ) -> dict:
        """
        Creates a new RBAC user in Wazuh.

        CAUTION: Password must be at least 8 characters with uppercase, number and symbol.

        Args:
            username: Unique username.
            password: Password (min. 8 chars, 1 uppercase, 1 number, 1 symbol).
            allow_run_as: If True, allows the user to use the run_as functionality.

        Returns:
            data.affected_items: Created user data with assigned ID.
        """
        body: dict[str, Any] = {"username": username, "password": password}
        if allow_run_as is not None:
            body["allow_run_as"] = allow_run_as
        return await client.post("/security/users", json=body)

    @mcp.tool()
    async def update_user(
        user_id: int,
        password: Optional[str] = None,
        allow_run_as: Optional[bool] = None,
    ) -> dict:
        """
        Updates the password or permissions of an existing user.

        CAUTION: Changing another user's password invalidates their active session.

        Args:
            user_id: Numeric ID of the user to modify.
            password: New password (min. 8 chars, 1 uppercase, 1 number, 1 symbol).
            allow_run_as: Enables or disables the run_as capability.

        Returns:
            data.affected_items: Updated user data.
        """
        body: dict[str, Any] = {}
        if password is not None:
            body["password"] = password
        if allow_run_as is not None:
            body["allow_run_as"] = allow_run_as
        return await client.put(f"/security/users/{user_id}", json=body)

    @mcp.tool()
    async def delete_users(user_ids: str) -> dict:
        """
        Permanently deletes users.

        DESTRUCTIVE: Deleted users lose access immediately. Cannot be undone.

        Args:
            user_ids: Comma-separated user IDs.

        Returns:
            data.affected_items: List of deleted users.
        """
        return await client.delete("/security/users", params={"user_ids": user_ids})

    @mcp.tool()
    async def set_user_run_as(user_id: int, allow_run_as: bool) -> dict:
        """
        Enables or disables the run_as capability for a user.

        Args:
            user_id: Numeric user ID.
            allow_run_as: True to enable, False to disable.

        Returns:
            data.affected_items: Confirmation of the change.
        """
        return await client.put(
            f"/security/users/{user_id}/run_as",
            params={"allow_run_as": allow_run_as},
        )

    # ── Roles ────────────────────────────────────────────────────────────────

    @mcp.tool()
    async def list_roles(
        role_ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists available roles with their policies and rules.

        Args:
            role_ids: Comma-separated role IDs.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Roles with id, name, associated policies and rules.
        """
        params = {k: v for k, v in {
            "role_ids": role_ids, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/security/roles", params=params or None)

    @mcp.tool()
    async def create_role(name: str) -> dict:
        """
        Creates a new RBAC role.

        Args:
            name: Unique role name.

        Returns:
            data.affected_items: Created role data with its ID.
        """
        return await client.post("/security/roles", json={"name": name})

    @mcp.tool()
    async def update_role(role_id: int, name: str) -> dict:
        """
        Updates the name of an existing role.

        Args:
            role_id: Numeric role ID.
            name: New role name.

        Returns:
            data.affected_items: Updated role data.
        """
        return await client.put(f"/security/roles/{role_id}", json={"name": name})

    @mcp.tool()
    async def delete_roles(role_ids: str) -> dict:
        """
        Permanently deletes roles.

        DESTRUCTIVE: Users with these roles will lose those permissions immediately.

        Args:
            role_ids: Comma-separated role IDs.

        Returns:
            data.affected_items: List of deleted roles.
        """
        return await client.delete("/security/roles", params={"role_ids": role_ids})

    # ── Policies ──────────────────────────────────────────────────────────────

    @mcp.tool()
    async def list_policies(
        policy_ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists RBAC policies with their actions, resources and effects.

        Args:
            policy_ids: Comma-separated policy IDs.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Policies with id, name, actions, resources, effect.
        """
        params = {k: v for k, v in {
            "policy_ids": policy_ids, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/security/policies", params=params or None)

    @mcp.tool()
    async def create_policy(name: str, policy: dict) -> dict:
        """
        Creates a new RBAC policy.

        Args:
            name: Unique policy name.
            policy: Definition with keys: actions (list[str]), resources (list[str]),
                    effect ('allow' | 'deny').

        Returns:
            data.affected_items: Created policy data with its ID.
        """
        return await client.post("/security/policies", json={"name": name, "policy": policy})

    @mcp.tool()
    async def update_policy(
        policy_id: int,
        name: Optional[str] = None,
        policy: Optional[dict] = None,
    ) -> dict:
        """
        Updates an existing RBAC policy.

        Args:
            policy_id: Numeric policy ID.
            name: New policy name.
            policy: New definition with actions, resources and effect.

        Returns:
            data.affected_items: Updated policy data.
        """
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if policy is not None:
            body["policy"] = policy
        return await client.put(f"/security/policies/{policy_id}", json=body)

    @mcp.tool()
    async def delete_policies(policy_ids: str) -> dict:
        """
        Permanently deletes policies.

        DESTRUCTIVE: Roles using these policies will lose those permissions.

        Args:
            policy_ids: Comma-separated policy IDs.

        Returns:
            data.affected_items: List of deleted policies.
        """
        return await client.delete("/security/policies", params={"policy_ids": policy_ids})

    # ── Security Rules ────────────────────────────────────────────────────────

    @mcp.tool()
    async def list_security_rules(
        rule_ids: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> dict:
        """
        Lists available RBAC security rules.

        Args:
            rule_ids: Comma-separated rule IDs.
            limit: Maximum number of results.
            offset: Offset for pagination.

        Returns:
            data.affected_items: Rules with id, name and definition.
        """
        params = {k: v for k, v in {
            "rule_ids": rule_ids, "limit": limit, "offset": offset,
        }.items() if v is not None}
        return await client.get("/security/rules", params=params or None)

    @mcp.tool()
    async def create_security_rule(name: str, rule: dict) -> dict:
        """
        Creates a new RBAC security rule.

        Args:
            name: Unique rule name.
            rule: Rule definition (matching conditions).

        Returns:
            data.affected_items: Created rule data with its ID.
        """
        return await client.post("/security/rules", json={"name": name, "rule": rule})

    @mcp.tool()
    async def update_security_rule(
        rule_id: int,
        name: Optional[str] = None,
        rule: Optional[dict] = None,
    ) -> dict:
        """
        Updates an existing RBAC security rule.

        Args:
            rule_id: Numeric rule ID.
            name: New rule name.
            rule: New rule definition.

        Returns:
            data.affected_items: Updated rule data.
        """
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if rule is not None:
            body["rule"] = rule
        return await client.put(f"/security/rules/{rule_id}", json=body)

    @mcp.tool()
    async def delete_security_rules(rule_ids: str) -> dict:
        """
        Permanently deletes security rules.

        DESTRUCTIVE: Roles linked to these rules will lose the association.

        Args:
            rule_ids: Comma-separated rule IDs.

        Returns:
            data.affected_items: List of deleted rules.
        """
        return await client.delete("/security/rules", params={"rule_ids": rule_ids})

    # ── Assignments ───────────────────────────────────────────────────────────

    @mcp.tool()
    async def add_roles_to_user(
        user_id: int,
        role_ids: str,
        position: Optional[int] = None,
    ) -> dict:
        """
        Assigns roles to an RBAC user.

        Args:
            user_id: Numeric user ID.
            role_ids: Comma-separated role IDs.
            position: Position at which to insert the roles (optional).

        Returns:
            data.affected_items: User data with the assigned roles.
        """
        params: dict[str, Any] = {"role_ids": role_ids}
        if position is not None:
            params["position"] = position
        return await client.post(f"/security/users/{user_id}/roles", params=params)

    @mcp.tool()
    async def remove_roles_from_user(user_id: int, role_ids: str) -> dict:
        """
        Removes roles from an RBAC user.

        CAUTION: The user will lose the permissions of those roles immediately.

        Args:
            user_id: Numeric user ID.
            role_ids: Comma-separated role IDs to remove.

        Returns:
            data.affected_items: Updated user data.
        """
        return await client.delete(
            f"/security/users/{user_id}/roles",
            params={"role_ids": role_ids},
        )

    @mcp.tool()
    async def add_policies_to_role(
        role_id: int,
        policy_ids: str,
        position: Optional[int] = None,
    ) -> dict:
        """
        Assigns policies to an RBAC role.

        Args:
            role_id: Numeric role ID.
            policy_ids: Comma-separated policy IDs.
            position: Position at which to insert the policies (optional).

        Returns:
            data.affected_items: Role data with the assigned policies.
        """
        params: dict[str, Any] = {"policy_ids": policy_ids}
        if position is not None:
            params["position"] = position
        return await client.post(f"/security/roles/{role_id}/policies", params=params)

    @mcp.tool()
    async def remove_policies_from_role(role_id: int, policy_ids: str) -> dict:
        """
        Removes policies from an RBAC role.

        Args:
            role_id: Numeric role ID.
            policy_ids: Comma-separated policy IDs to remove.

        Returns:
            data.affected_items: Updated role data.
        """
        return await client.delete(
            f"/security/roles/{role_id}/policies",
            params={"policy_ids": policy_ids},
        )

    @mcp.tool()
    async def add_rules_to_role(role_id: int, rule_ids: str) -> dict:
        """
        Assigns security rules to an RBAC role.

        Args:
            role_id: Numeric role ID.
            rule_ids: Comma-separated rule IDs.

        Returns:
            data.affected_items: Role data with the assigned rules.
        """
        return await client.post(
            f"/security/roles/{role_id}/rules",
            params={"rule_ids": rule_ids},
        )

    @mcp.tool()
    async def remove_rules_from_role(role_id: int, rule_ids: str) -> dict:
        """
        Removes security rules from an RBAC role.

        Args:
            role_id: Numeric role ID.
            rule_ids: Comma-separated rule IDs to remove.

        Returns:
            data.affected_items: Updated role data.
        """
        return await client.delete(
            f"/security/roles/{role_id}/rules",
            params={"rule_ids": rule_ids},
        )

    # ── Config and metadata ───────────────────────────────────────────────────

    @mcp.tool()
    async def get_security_config() -> dict:
        """
        Returns security configuration: token expiration and RBAC mode.

        Returns:
            data.affected_items: auth_token_exp_timeout (seconds) and rbac_mode ('white'|'black').
        """
        return await client.get("/security/config")

    @mcp.tool()
    async def update_security_config(
        auth_token_exp_timeout: Optional[int] = None,
        rbac_mode: Optional[str] = None,
    ) -> dict:
        """
        Updates the system security configuration.

        CAUTION: Changing auth_token_exp_timeout revokes ALL active JWT tokens.

        Args:
            auth_token_exp_timeout: Token expiration time in seconds.
            rbac_mode: RBAC mode. Values: 'white' (explicitly allow) or 'black' (explicitly deny).

        Returns:
            data.affected_items: Confirmation with the updated configuration.
        """
        body: dict[str, Any] = {}
        if auth_token_exp_timeout is not None:
            body["auth_token_exp_timeout"] = auth_token_exp_timeout
        if rbac_mode is not None:
            body["rbac_mode"] = rbac_mode
        return await client.put("/security/config", json=body)

    @mcp.tool()
    async def restore_security_config() -> dict:
        """
        Restores security configuration to default values.

        CAUTION: Revokes all active JWT tokens. All users must re-authenticate.

        Returns:
            data.affected_items: Confirmation of the reset.
        """
        return await client.delete("/security/config")

    @mcp.tool()
    async def revoke_all_tokens() -> dict:
        """
        Immediately invalidates ALL JWT tokens in the system.

        CAUTION: All users must re-authenticate after this operation.

        Returns:
            data.affected_items: Confirmation of the mass revocation.
        """
        return await client.put("/security/user/revoke")

    @mcp.tool()
    async def list_rbac_actions(endpoint: Optional[str] = None) -> dict:
        """
        Lists the catalog of available RBAC actions in the API.

        Args:
            endpoint: Filter actions for a specific endpoint (e.g. '/agents').

        Returns:
            data.affected_items: RBAC actions with their associated resources.
        """
        params = {"endpoint": endpoint} if endpoint is not None else None
        return await client.get("/security/actions", params=params)

    @mcp.tool()
    async def list_rbac_resources() -> dict:
        """
        Lists the catalog of available RBAC resources.

        Returns:
            data.affected_items: RBAC resources with their descriptions and examples.
        """
        return await client.get("/security/resources")
