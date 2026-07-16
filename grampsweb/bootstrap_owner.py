"""Idempotent bootstrap for the GrampsWeb tree and owner user.

Runs inside the grampsweb container (docker exec) with Flask app context,
using the internal gramps_webapi functions directly. This avoids the
create_owner/login REST API dance entirely, which deadlocks in multi-tree
mode (GRAMPSWEB_TREE="*"): a user with no tree cannot obtain a login token,
but obtaining a tree requires a login token.

Safe to run on every deploy: finds the tree/user by name if they already
exist and resyncs the user's password/role/tree instead of failing.

Tree registration (WebDbManager's create_if_missing) has been observed to
silently no-op on a container's very first exec, before Gramps' own
per-user config directory has finished initializing. Every creation is
therefore verified by re-reading the tree/user registry afterwards, with
retries - a step that reports success without verifying left a previous
deploy with an admin user pointing at a tree that didn't exist anywhere.
"""

import os
import time
import uuid

from gramps_webapi.api.util import list_trees
from gramps_webapi.app import create_app
from gramps_webapi.auth import add_user, get_all_user_details, modify_user, user_db
from gramps_webapi.auth.const import ROLE_OWNER
from gramps_webapi.dbmanager import WebDbManager

TREE_NAME = os.environ["BOOTSTRAP_TREE_NAME"]
USERNAME = os.environ["BOOTSTRAP_USERNAME"]
FULLNAME = os.environ["BOOTSTRAP_FULLNAME"]
PASSWORD = os.environ["BOOTSTRAP_PASSWORD"]
EMAIL = os.environ["BOOTSTRAP_EMAIL"]

MAX_ATTEMPTS = 5
RETRY_DELAY_SECONDS = 3


def find_tree(name):
    for tree_name, path in list_trees():
        if tree_name == name:
            return os.path.basename(path)
    return None


app = create_app()
with app.app_context():
    user_db.create_all()

    tree_id = find_tree(TREE_NAME)
    if tree_id:
        print(f"Tree '{TREE_NAME}' already exists: {tree_id}")
    else:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            candidate_id = str(uuid.uuid4())
            mgr = WebDbManager(
                dirname=candidate_id,
                name=TREE_NAME,
                create_if_missing=True,
                create_backend=app.config["NEW_DB_BACKEND"],
                ignore_lock=app.config["IGNORE_DB_LOCK"],
            )
            marker = os.path.join(mgr.path, "database.txt")
            if os.path.isfile(marker) and find_tree(TREE_NAME) == candidate_id:
                tree_id = candidate_id
                print(f"Created tree '{TREE_NAME}': {tree_id} (backend={mgr._dbid})")
                break
            print(
                f"Attempt {attempt}/{MAX_ATTEMPTS}: tree creation unverified, "
                f"retrying in {RETRY_DELAY_SECONDS}s..."
            )
            time.sleep(RETRY_DELAY_SECONDS)
        else:
            raise RuntimeError(
                f"Failed to create and verify tree '{TREE_NAME}' after {MAX_ATTEMPTS} attempts"
            )

    existing_users = {u["name"] for u in get_all_user_details(tree=None)}
    if USERNAME in existing_users:
        modify_user(
            name=USERNAME,
            password=PASSWORD,
            fullname=FULLNAME,
            email=EMAIL,
            role=ROLE_OWNER,
            tree=tree_id,
        )
        action = "Updated existing"
    else:
        add_user(
            name=USERNAME,
            password=PASSWORD,
            fullname=FULLNAME,
            email=EMAIL,
            role=ROLE_OWNER,
            tree=tree_id,
        )
        action = "Created"

    refreshed = {u["name"]: u["tree"] for u in get_all_user_details(tree=None)}
    if refreshed.get(USERNAME) != tree_id:
        raise RuntimeError(
            f"User '{USERNAME}' has tree '{refreshed.get(USERNAME)}' after "
            f"{action.lower()} user, expected '{tree_id}'"
        )
    print(f"{action} user '{USERNAME}' (tree={tree_id}, role=OWNER) - verified")

print(f"TREE_ID={tree_id}")
