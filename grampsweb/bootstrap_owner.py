"""Idempotent bootstrap for the GrampsWeb tree and owner user.

Runs inside the grampsweb container (docker exec) with Flask app context,
using the internal gramps_webapi functions directly. This avoids the
create_owner/login REST API dance entirely, which deadlocks in multi-tree
mode (GRAMPSWEB_TREE="*"): a user with no tree cannot obtain a login token,
but obtaining a tree requires a login token.

Safe to run on every deploy: finds the tree/user by name if they already
exist and resyncs the user's password/role/tree instead of failing.
"""

import os
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

app = create_app()
with app.app_context():
    user_db.create_all()

    existing_trees = {name: path for name, path in list_trees()}
    if TREE_NAME in existing_trees:
        tree_id = os.path.basename(existing_trees[TREE_NAME])
        print(f"Tree '{TREE_NAME}' already exists: {tree_id}")
    else:
        tree_id = str(uuid.uuid4())
        WebDbManager(
            dirname=tree_id,
            name=TREE_NAME,
            create_if_missing=True,
            create_backend=app.config["NEW_DB_BACKEND"],
            ignore_lock=app.config["IGNORE_DB_LOCK"],
        )
        print(f"Created tree '{TREE_NAME}': {tree_id}")

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
        print(f"Updated existing user '{USERNAME}' (tree={tree_id}, role=OWNER)")
    else:
        add_user(
            name=USERNAME,
            password=PASSWORD,
            fullname=FULLNAME,
            email=EMAIL,
            role=ROLE_OWNER,
            tree=tree_id,
        )
        print(f"Created user '{USERNAME}' (tree={tree_id}, role=OWNER)")

print(f"TREE_ID={tree_id}")
